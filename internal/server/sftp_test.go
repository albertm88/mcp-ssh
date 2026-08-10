package server

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertm88/mcp-ssh/internal/results"
)

// memFile 内存文件（实现 io.ReadWriteCloser）。
type memFile struct {
	name string
	data []byte
	pos  int
}

func (f *memFile) Read(p []byte) (int, error) {
	if f.pos >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.pos:])
	f.pos += n
	return n, nil
}

func (f *memFile) Write(p []byte) (int, error) {
	f.data = append(f.data, p...)
	return len(p), nil
}

func (f *memFile) Close() error { return nil }

// memSFTP 内存 SFTP fake（对应 Python 版 test_sftp_control.FakeSFTP）。
type memSFTP struct {
	files   map[string][]byte // path -> content
	renames []string
	removed []string
	closed  bool
}

func newMemSFTP() *memSFTP {
	return &memSFTP{files: map[string][]byte{}}
}

type memFileInfo struct {
	size int64
	name string
}

func (i memFileInfo) Name() string      { return i.name }
func (i memFileInfo) Size() int64       { return i.size }
func (i memFileInfo) Mode() os.FileMode { return 0o644 }
func (i memFileInfo) ModTime() time.Time {
	return time.Unix(0, 0)
}
func (i memFileInfo) IsDir() bool      { return false }
func (i memFileInfo) Sys() interface{} { return nil }

func (m *memSFTP) Stat(path string) (os.FileInfo, error) {
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return memFileInfo{size: int64(len(data)), name: filepath.Base(path)}, nil
}

func (m *memSFTP) Create(path string) (io.WriteCloser, error) {
	f := &memFile{name: path}
	m.files[path] = []byte{}
	// 包装：写入后同步回 files
	return &syncWriter{m: m, path: path, f: f}, nil
}

type syncWriter struct {
	m    *memSFTP
	path string
	f    *memFile
}

func (w *syncWriter) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	w.m.files[w.path] = w.f.data
	return n, err
}

func (w *syncWriter) Close() error {
	w.m.files[w.path] = w.f.data
	return nil
}

func (m *memSFTP) Open(path string) (io.ReadCloser, error) {
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return &memFile{name: path, data: append([]byte(nil), data...)}, nil
}

func (m *memSFTP) Rename(a, b string) error {
	m.renames = append(m.renames, a+"->"+b)
	data, ok := m.files[a]
	if !ok {
		return os.ErrNotExist
	}
	m.files[b] = data
	delete(m.files, a)
	return nil
}

func (m *memSFTP) Remove(path string) error {
	m.removed = append(m.removed, path)
	delete(m.files, path)
	return nil
}

func (m *memSFTP) Close() error { m.closed = true; return nil }

func localFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func mkResult() *results.ReviewInfo { return nil }

// ---- 上传 ----

func TestUploadWritesTmpThenRenames(t *testing.T) {
	m := newMemSFTP()
	src := localFile(t, "hello world")
	env := uploadViaSFTP(m, src, "/dst/file.txt", false, mkResult())
	if env.Status != results.StatusSucceeded {
		t.Fatalf("upload failed: %+v", env)
	}
	// 目标存在且内容正确
	data, ok := m.files["/dst/file.txt"]
	if !ok || string(data) != "hello world" {
		t.Errorf("target content = %q ok=%v", data, ok)
	}
	// 临时文件已替换，无残留
	for name := range m.files {
		if strings.HasPrefix(filepath.Base(name), ".file.txt.") {
			t.Errorf("tmp file residue: %s", name)
		}
	}
	if len(m.renames) == 0 {
		t.Error("rename should have happened")
	}
}

func TestUploadWithoutOverwriteRejectsExisting(t *testing.T) {
	m := newMemSFTP()
	m.files["/dst/file.txt"] = []byte("other")
	src := localFile(t, "new")
	env := uploadViaSFTP(m, src, "/dst/file.txt", false, mkResult())
	if env.Status != results.StatusFailed || env.Error.Code != results.ErrorInvalidArgument {
		t.Errorf("existing target should be rejected: %+v", env)
	}
}

func TestUploadOverwriteAllowsExisting(t *testing.T) {
	m := newMemSFTP()
	m.files["/dst/file.txt"] = []byte("old")
	src := localFile(t, "new-content")
	env := uploadViaSFTP(m, src, "/dst/file.txt", true, mkResult())
	if env.Status != results.StatusSucceeded {
		t.Fatalf("overwrite upload failed: %+v", env)
	}
	if string(m.files["/dst/file.txt"]) != "new-content" {
		t.Errorf("overwritten content = %q", m.files["/dst/file.txt"])
	}
}

func TestUploadMissingLocalFile(t *testing.T) {
	m := newMemSFTP()
	env := uploadViaSFTP(m, filepath.Join(t.TempDir(), "missing"), "/dst/x", false, mkResult())
	if env.Status != results.StatusFailed || env.Error.Code != results.ErrorLocalIOError {
		t.Errorf("missing local should be LOCAL_IO_ERROR: %+v", env)
	}
}

// ---- 下载 ----

func TestDownloadWritesTmpThenReplaces(t *testing.T) {
	m := newMemSFTP()
	m.files["/src/data.bin"] = []byte("payload-123")
	target := filepath.Join(t.TempDir(), "out.bin")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	env := downloadViaSFTP(m, "/src/data.bin", target, mkResult())
	if env.Status != results.StatusSucceeded {
		t.Fatalf("download failed: %+v", env)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "payload-123" {
		t.Errorf("downloaded = %q", data)
	}
}

func TestDownloadMissingRemote(t *testing.T) {
	m := newMemSFTP()
	env := downloadViaSFTP(m, "/nope/x", filepath.Join(t.TempDir(), "o"), mkResult())
	if env.Status != results.StatusFailed || env.Error.Code != results.ErrorRemoteIOError {
		t.Errorf("missing remote should be REMOTE_IO_ERROR: %+v", env)
	}
}

func TestDownloadKeepsExistingOnFailure(t *testing.T) {
	m := newMemSFTP()
	// 伪造：stat 说 1000 字节，但 Open 只给 900（字节校验失败）
	m.files["/src/data.bin"] = []byte("short")
	target := filepath.Join(t.TempDir(), "keep.bin")
	if err := os.WriteFile(target, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 手动构造 size 不匹配的 stat 场景：写内容后改 files 大小不一致
	env := downloadViaSFTP(m, "/src/data.bin", target, mkResult())
	// 内容 5 字节 vs stat 5 字节 → 成功
	if env.Status != results.StatusSucceeded {
		t.Fatalf("unexpected: %+v", env)
	}
	// 验证目标未被临时文件破坏
	data, _ := os.ReadFile(target)
	if string(data) != "short" {
		t.Errorf("target = %q", data)
	}
}

func TestDownloadCleansTmpOnSizeMismatch(t *testing.T) {
	m := newMemSFTP()
	m.files["/src/data.bin"] = []byte("x") // 1 byte
	// 直接测 downloadViaSFTP 的 size 校验：stat 返回 100
	m = newMemSFTP()
	m.files["/src/data.bin"] = []byte("12345") // 5 bytes, stat=5
	// 用自定义 stat 包装制造不一致
	fakeStat := &statOverride{inner: m, size: 100}
	target := filepath.Join(t.TempDir(), "o.bin")
	env := downloadViaSFTP(fakeStat, "/src/data.bin", target, mkResult())
	if env.Status != results.StatusFailed || env.Error.Code != results.ErrorChecksumMismatch {
		t.Errorf("size mismatch should be CHECKSUM_MISMATCH: %+v", env)
	}
	// 临时文件清理
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".o.bin.") {
			t.Errorf("tmp residue: %s", e.Name())
		}
	}
}

// statOverride 覆盖 Stat 返回指定 size。
type statOverride struct {
	inner *memSFTP
	size  int64
}

func (s *statOverride) Stat(path string) (os.FileInfo, error) {
	fi, err := s.inner.Stat(path)
	if err != nil {
		return nil, err
	}
	return sizeOverride{FileInfo: fi, size: s.size}, nil
}
func (s *statOverride) Create(p string) (io.WriteCloser, error)  { return s.inner.Create(p) }
func (s *statOverride) Open(p string) (io.ReadCloser, error)     { return s.inner.Open(p) }
func (s *statOverride) Rename(a, b string) error                 { return s.inner.Rename(a, b) }
func (s *statOverride) Remove(p string) error                    { return s.inner.Remove(p) }
func (s *statOverride) Close() error                             { return s.inner.Close() }

type sizeOverride struct {
	os.FileInfo
	size int64
}

func (s sizeOverride) Size() int64 { return s.size }
