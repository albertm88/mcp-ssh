package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertm88/mcp-ssh/internal/sshclient"
)

// TestE2EUploadDownload 真实 WSL2 端到端：仅在设置 SSH_E2E_HOST 时运行。
func TestE2EUploadDownload(t *testing.T) {
	host := os.Getenv("SSH_E2E_HOST")
	if host == "" {
		t.Skip("SSH_E2E_HOST 未设置，跳过真实 E2E")
	}
	client, err := sshclient.Connect(host, 10*time.Second)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer client.Close()

	// 上传
	src := filepath.Join(t.TempDir(), "payload.bin")
	content := strings.Repeat("hello-fast-", 100)
	if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	remote := "/tmp/fast-e2e-payload.bin"
	env := uploadFile(client, src, remote, true, nil) // overwrite 幂等（残留清理由审核拒绝时不阻塞）
	if env.Status != "succeeded" {
		t.Fatalf("上传失败: %+v", env)
	}
	t.Log("E2E_UPLOAD_OK")

	// 下载
	target := filepath.Join(t.TempDir(), "downloaded.bin")
	env = downloadFile(client, remote, target, nil)
	if env.Status != "succeeded" {
		t.Fatalf("下载失败: %+v", env)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Fatalf("下载内容不一致: len=%d want=%d", len(data), len(content))
	}
	t.Log("E2E_DOWNLOAD_ROUNDTRIP_OK")

	// 清理远端（whitelist 模式拒绝 rm 属预期；用 off 模式确保清理）
	execEnv := execWithReview(host, "rm -f /tmp/fast-e2e-payload.bin", 10, true, "", nil)
	if execEnv.Status == "succeeded" {
		t.Log("E2E_CLEANUP_OK")
	} else {
		t.Logf("清理被审核拒绝（预期，白名单模式）: %s", execEnv.Status)
	}
}
