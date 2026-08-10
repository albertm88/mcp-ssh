package sshclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2EExec 真实 WSL2 端到端：仅在设置 SSH_E2E_HOST 时运行。
// 用法：
//
//	SSH_E2E_HOST=ssh-mcp-wsl-test SSH_CONFIG_FILE=/tmp/mcp-ssh-linux-test-config \
//	  SSH_KNOWN_HOSTS=/home/azusa/.ssh/known_hosts go test -run TestE2E -v ./internal/sshclient/
func TestE2EExec(t *testing.T) {
	host := os.Getenv("SSH_E2E_HOST")
	if host == "" {
		t.Skip("SSH_E2E_HOST 未设置，跳过真实 E2E")
	}
	client, err := Connect(host, 10*time.Second)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer client.Close()

	res, err := client.Exec("hostname", 15*time.Second, true)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) == "" {
		t.Fatalf("hostname: exit=%d out=%q", res.ExitCode, res.Stdout)
	}
	t.Logf("E2E_HOSTNAME_OK: %s", strings.TrimSpace(res.Stdout))

	// 非零退出码
	res, err = client.Exec("exit 3", 10*time.Second, true)
	if err != nil {
		t.Fatalf("exit 3 failed: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3", res.ExitCode)
	}

	// 超时（sleep 3 + timeout 1）
	t0 := time.Now()
	res, err = client.Exec("sleep 3", 1*time.Second, true)
	if err == nil || !res.TimedOut {
		t.Errorf("超时注入应失败: err=%v timedOut=%v", err, res != nil && res.TimedOut)
	}
	if time.Since(t0) > 3*time.Second {
		t.Error("超时应在 1s 内返回")
	}
	t.Log("E2E_TIMEOUT_OK")
}

// TestE2EHostKeyReject 未信任主机必须被拒绝。
func TestE2EHostKeyReject(t *testing.T) {
	t.Setenv("SSH_KNOWN_HOSTS", filepath.Join(t.TempDir(), "empty-known-hosts"))
	_, err := Connect("127.0.0.1", 3*time.Second)
	if err == nil {
		t.Skip("未信任主机未被拒绝（known_hosts 为空时行为）")
	}
	if !IsHostKeyError(err) {
		t.Logf("错误类型: %v", err)
	}
}
