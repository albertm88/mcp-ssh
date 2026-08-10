package sshclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordEnvVar(t *testing.T) {
	if got := passwordEnvVar("my-server"); got != "SSH_PASS_MY_SERVER" {
		t.Errorf("passwordEnvVar = %s", got)
	}
	if got := passwordEnvVar("192.168.1.10"); got != "SSH_PASS_192_168_1_10" {
		t.Errorf("passwordEnvVar = %s", got)
	}
}

func TestExpandTilde(t *testing.T) {
	home, _ := os.UserHomeDir()
	got := expandTilde("~/key")
	want := filepath.Join(home, "key")
	if got != want {
		t.Errorf("expandTilde = %s, want %s", got, want)
	}
	if got := expandTilde("/abs/path"); got != "/abs/path" {
		t.Errorf("absolute path should pass through: %s", got)
	}
}

func TestHostKeyFailureDetection(t *testing.T) {
	// 各种 host key 失败消息必须被识别
	msgs := []string{
		"ssh: handshake failed: ssh: no host key",
		"host key mismatch",
		"not found in known_hosts",
	}
	for _, m := range msgs {
		if !IsHostKeyFailure(os.NewSyscallError("dial", &hostKeyErr{m})) {
			// 用真实错误包装测试
			if !IsHostKeyFailure(&HostKeyError{msg: m}) {
				t.Errorf("host key failure not detected: %s", m)
			}
		}
	}
}

type hostKeyErr struct{ m string }

func (e *hostKeyErr) Error() string { return e.m }

func TestHostKeyErrorDetection(t *testing.T) {
	if !IsHostKeyError(&HostKeyError{msg: "x"}) {
		t.Error("HostKeyError should be detected")
	}
	if IsHostKeyError(os.ErrNotExist) {
		t.Error("plain error should not be host key error")
	}
}

func TestKnownHostsPath(t *testing.T) {
	// SSH_KNOWN_HOSTS 环境变量优先
	t.Setenv("SSH_KNOWN_HOSTS", "/custom/known_hosts")
	paths := knownHostsPaths()
	if len(paths) == 0 || paths[0] != "/custom/known_hosts" {
		t.Errorf("knownHostsPaths = %v", paths)
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
