package server

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"github.com/albertm88/mcp-ssh/internal/results"
	"github.com/albertm88/mcp-ssh/internal/sshclient"
)

// uploadFile 原子上传：临时名 → 写入 → SHA-256 校验 → 重命名。
func uploadFile(client *sshclient.Client, localPath, remotePath string, overwrite bool, reviewInfo *results.ReviewInfo) *results.Envelope {
	conn, err := client.SSHConn()
	if err != nil {
		return results.MakeFailure(results.ErrorConnectionLost, err.Error(), "ssh_upload", "", "", nil, reviewInfo)
	}
	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		return results.MakeFailure(results.ErrorRemoteIOError, err.Error(), "ssh_upload", "", "", nil, reviewInfo)
	}
	defer sftpClient.Close()

	// 存在性检查
	if !overwrite {
		if _, err := sftpClient.Stat(remotePath); err == nil {
			return results.MakeFailure(results.ErrorInvalidArgument,
				fmt.Sprintf("远端目标已存在：%s（overwrite=False）", remotePath), "ssh_upload", "", "", nil, reviewInfo)
		}
	}

	tmp := tmpName(remotePath)
	src, err := os.Open(localPath)
	if err != nil {
		return results.MakeFailure(results.ErrorLocalIOError, err.Error(), "ssh_upload", "", "", nil, reviewInfo)
	}
	defer src.Close()

	dst, err := sftpClient.Create(tmp)
	if err != nil {
		return results.MakeFailure(results.ErrorRemoteIOError, err.Error(), "ssh_upload", "", "", nil, reviewInfo)
	}
	written, copyErr := io.Copy(dst, src)
	dst.Close()
	if copyErr != nil {
		cleanupRemove(sftpClient, tmp)
		return results.MakeFailure(results.ErrorRemoteIOError, copyErr.Error(), "ssh_upload", "", "", nil, reviewInfo)
	}

	// 字节数校验
	localStat, err := srcStat(localPath)
	if err == nil && written != localStat {
		cleanupRemove(sftpClient, tmp)
		return results.MakeFailure(results.ErrorChecksumMismatch,
			fmt.Sprintf("字节数不一致：local=%d remote=%d", localStat, written), "ssh_upload", "", "", nil, reviewInfo)
	}

	// SHA-256 校验
	localDigest, err := sshclient.Sha256File(localPath)
	if err != nil {
		cleanupRemove(sftpClient, tmp)
		return results.MakeFailure(results.ErrorLocalIOError, err.Error(), "ssh_upload", "", "", nil, reviewInfo)
	}
	remoteFile, err := sftpClient.Open(tmp)
	if err != nil {
		cleanupRemove(sftpClient, tmp)
		return results.MakeFailure(results.ErrorRemoteIOError, err.Error(), "ssh_upload", "", "", nil, reviewInfo)
	}
	remoteData, readErr := io.ReadAll(remoteFile)
	remoteFile.Close()
	if readErr != nil {
		cleanupRemove(sftpClient, tmp)
		return results.MakeFailure(results.ErrorRemoteIOError, readErr.Error(), "ssh_upload", "", "", nil, reviewInfo)
	}
	remoteDigest := sshclient.Sha256Bytes(remoteData)
	if localDigest != remoteDigest {
		cleanupRemove(sftpClient, tmp)
		return results.MakeFailure(results.ErrorChecksumMismatch, "SHA-256 校验不一致", "ssh_upload", "", "", nil, reviewInfo)
	}

	// 原子重命名
	if err := sftpClient.Rename(tmp, remotePath); err != nil {
		cleanupRemove(sftpClient, tmp)
		return results.MakeFailure(results.ErrorRemoteIOError, err.Error(), "ssh_upload", "", "", nil, reviewInfo)
	}

	env := results.MakeSuccess("ssh_upload", "",
		map[string]interface{}{
			"local_path": localPath, "remote_path": remotePath,
			"bytes": written, "sha256": localDigest, "atomic": true,
		},
		fmt.Sprintf("上传成功：%s -> %s（sha256=%s）", localPath, remotePath, localDigest[:16]),
		reviewInfo)
	return env
}

// downloadFile 原子下载：临时名 → 字节校验 → 原子替换。
func downloadFile(client *sshclient.Client, remotePath, localPath string, reviewInfo *results.ReviewInfo) *results.Envelope {
	conn, err := client.SSHConn()
	if err != nil {
		return results.MakeFailure(results.ErrorConnectionLost, err.Error(), "ssh_download", "", "", nil, reviewInfo)
	}
	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		return results.MakeFailure(results.ErrorRemoteIOError, err.Error(), "ssh_download", "", "", nil, reviewInfo)
	}
	defer sftpClient.Close()

	remoteStat, err := sftpClient.Stat(remotePath)
	if err != nil {
		return results.MakeFailure(results.ErrorRemoteIOError, "远端文件不存在："+remotePath, "ssh_download", "", "", nil, reviewInfo)
	}

	// 本地临时名
	tmp := localTmpName(localPath)
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		return results.MakeFailure(results.ErrorRemoteIOError, err.Error(), "ssh_download", "", "", nil, reviewInfo)
	}
	defer remoteFile.Close()

	dst, err := os.Create(tmp)
	if err != nil {
		return results.MakeFailure(results.ErrorLocalIOError, err.Error(), "ssh_download", "", "", nil, reviewInfo)
	}
	written, copyErr := io.Copy(dst, remoteFile)
	dst.Close()
	if copyErr != nil {
		os.Remove(tmp)
		return results.MakeFailure(results.ErrorLocalIOError, copyErr.Error(), "ssh_download", "", "", nil, reviewInfo)
	}

	// 字节数校验
	if written != remoteStat.Size() {
		os.Remove(tmp)
		return results.MakeFailure(results.ErrorChecksumMismatch,
			fmt.Sprintf("字节数不一致：remote=%d local=%d", remoteStat.Size(), written), "ssh_download", "", "", nil, reviewInfo)
	}

	// 原子替换
	if err := os.Rename(tmp, localPath); err != nil {
		os.Remove(tmp)
		return results.MakeFailure(results.ErrorLocalIOError, err.Error(), "ssh_download", "", "", nil, reviewInfo)
	}

	digest, err := sshclient.Sha256File(localPath)
	if err != nil {
		digest = ""
	}
	env := results.MakeSuccess("ssh_download", "",
		map[string]interface{}{
			"remote_path": remotePath, "local_path": localPath,
			"bytes": written, "sha256": digest,
		},
		fmt.Sprintf("下载成功：%s -> %s（sha256=%s）", remotePath, localPath, digest[:16]),
		reviewInfo)
	return env
}

// fsList 列出目录（解析 ls 输出，name 从时间列后提取 + 剥离 CRLF）。
func fsList(host, remotePath string, showHidden bool, timeout int, reviewInfo *results.ReviewInfo) *results.Envelope {
	lsCmd := fmt.Sprintf("ls -la --time-style=long-iso %s", shellQuote(remotePath))
	if !showHidden {
		lsCmd = fmt.Sprintf("ls -l --time-style=long-iso %s", shellQuote(remotePath))
	}
	env := execWithReview(host, lsCmd, float64(timeout), true, "", nil)
	if env.Status != results.StatusSucceeded {
		return results.MakeFailure(results.ErrorRemoteExitNonzero, "列出目录失败："+remotePath, "ssh_filesystem", host, "", nil, reviewInfo)
	}
	out, _ := env.Data["stdout"].(string)
	entries := parseLsOutput(out)
	env2 := results.MakeSuccess("ssh_filesystem", host,
		map[string]interface{}{"action": "list", "path": remotePath, "entries": entries},
		fmt.Sprintf("目录：%s（%d 项）", remotePath, len(entries)),
		reviewInfo)
	return env2
}

// parseLsOutput 解析 ls -l --time-style=long-iso 输出。
func parseLsOutput(out string) []map[string]interface{} {
	entries := []map[string]interface{}{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 7 {
			continue
		}
		perm := parts[0]
		name := parts[len(parts)-1]
		if name == "." || name == ".." {
			continue
		}
		entries = append(entries, map[string]interface{}{
			"name": name, "type": string(perm[0]),
			"permissions": perm, "size": parts[4],
			"mtime": parts[5] + " " + parts[6],
		})
	}
	return entries
}

// fsStat 获取远端文件状态。
func fsStat(host, remotePath string, timeout int, reviewInfo *results.ReviewInfo) *results.Envelope {
	env := execWithReview(host, fmt.Sprintf("stat %s", shellQuote(remotePath)), float64(timeout), true, "", nil)
	if env.Status != results.StatusSucceeded {
		return results.MakeFailure(results.ErrorRemoteExitNonzero, "stat 失败："+remotePath, "ssh_filesystem", host, "", nil, reviewInfo)
	}
	out, _ := env.Data["stdout"].(string)
	return results.MakeSuccess("ssh_filesystem", host,
		map[string]interface{}{"action": "stat", "path": remotePath, "stat": out},
		"stat "+remotePath, reviewInfo)
}

// fsMkdir 创建目录。
func fsMkdir(host, remotePath string, parents bool, timeout int, reviewInfo *results.ReviewInfo) *results.Envelope {
	flag := ""
	if parents {
		flag = "-p "
	}
	cmd := fmt.Sprintf("mkdir %s%s", flag, shellQuote(remotePath))
	env := execWithReview(host, cmd, float64(timeout), true, "", nil)
	if env.Status != results.StatusSucceeded {
		return results.MakeFailure(results.ErrorRemoteExitNonzero, "目录创建失败："+remotePath, "ssh_filesystem", host, "", nil, reviewInfo)
	}
	return results.MakeSuccess("ssh_filesystem", host,
		map[string]interface{}{"action": "mkdir", "path": remotePath, "parents": parents},
		"目录创建成功："+remotePath, reviewInfo)
}

// fsRemove 删除文件或目录。
func fsRemove(host, remotePath string, recursive bool, timeout int, reviewInfo *results.ReviewInfo) *results.Envelope {
	flag := "-f "
	if recursive {
		flag = "-rf "
	}
	cmd := fmt.Sprintf("rm %s%s", flag, shellQuote(remotePath))
	env := execWithReview(host, cmd, float64(timeout), true, "", nil)
	if env.Status != results.StatusSucceeded {
		return results.MakeFailure(results.ErrorRemoteExitNonzero, "删除失败："+remotePath, "ssh_filesystem", host, "", nil, reviewInfo)
	}
	return results.MakeSuccess("ssh_filesystem", host,
		map[string]interface{}{"action": "remove", "path": remotePath, "recursive": recursive},
		"删除成功："+remotePath, reviewInfo)
}

// tmpName 生成远端临时文件名。
func tmpName(target string) string {
	dir := filepath.ToSlash(filepath.Dir(target))
	name := filepath.Base(target)
	tmp := fmt.Sprintf(".%s.%d.tmp", name, time.Now().UnixNano())
	if dir == "." || dir == "" {
		return tmp
	}
	return dir + "/" + tmp
}

// localTmpName 生成本地临时文件名。
func localTmpName(target string) string {
	dir := filepath.Dir(target)
	name := filepath.Base(target)
	return filepath.Join(dir, fmt.Sprintf(".%s.%d.tmp", name, time.Now().UnixNano()))
}

func srcStat(path string) (int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// cleanupRemove 尽力清理临时远端文件（失败不阻断主流程）。
func cleanupRemove(s *sftp.Client, remote string) {
	_ = s.Remove(remote)
}

var _ = strconv.Itoa
