package sshclient

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// 生成测试密钥对（内存），返回 (公钥, authorized_keys 文本)。
func testKeyPair(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub, string(ssh.MarshalAuthorizedKey(pub))
}

func writeKnownHosts(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_KNOWN_HOSTS", path)
	return path
}

func TestLoadKnownHosts(t *testing.T) {
	_, priv := testKeyPair(t)
	writeKnownHosts(t, "myhost "+priv+"\n")
	keys, err := LoadKnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["myhost"]; !ok {
		t.Error("myhost key not loaded")
	}
}

func TestLoadKnownHostsBracketPort(t *testing.T) {
	_, priv := testKeyPair(t)
	writeKnownHosts(t, "[1.2.3.4]:2222 "+priv+"\n")
	keys, err := LoadKnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["[1.2.3.4]:2222"]; !ok {
		t.Error("bracket-port key not loaded")
	}
}

func TestLoadKnownHostsEmpty(t *testing.T) {
	t.Setenv("USERPROFILE", t.TempDir())
	writeKnownHosts(t, "")
	_, err := LoadKnownHosts()
	if err == nil {
		t.Error("empty known_hosts should error (no trusted source)")
	}
}

func TestLoadKnownHostsNoFile(t *testing.T) {
	// 隔离：USERPROFILE 指向空目录（无系统 known_hosts）+ SSH_KNOWN_HOSTS 指向缺失文件
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("SSH_KNOWN_HOSTS", filepath.Join(t.TempDir(), "missing"))
	_, err := LoadKnownHosts()
	if err == nil {
		t.Error("missing known_hosts should error")
	}
}

func TestHostKeyCallbackAccept(t *testing.T) {
	pub, priv := testKeyPair(t)
	writeKnownHosts(t, "target "+priv+"\n")
	cb, err := hostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("target", nil, pub); err != nil {
		t.Errorf("known host should be accepted: %v", err)
	}
}

func TestHostKeyCallbackUnknownRejected(t *testing.T) {
	pub, priv := testKeyPair(t)
	writeKnownHosts(t, "other "+priv+"\n")
	cb, err := hostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("target", nil, pub); err == nil {
		t.Error("unknown host must be rejected")
	}
}

func TestHostKeyCallbackMismatch(t *testing.T) {
	pub1, priv := testKeyPair(t)
	_, _ = pub1, priv
	_, priv2 := testKeyPair(t)
	writeKnownHosts(t, "target "+priv2+"\n")
	cb, err := hostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	// 用不同密钥连接同一主机 → 指纹不匹配
	otherPub, _ := testKeyPair(t)
	if err := cb("target", nil, otherPub); err == nil {
		t.Error("mismatched key must be rejected")
	}
}

func TestHostKeyCallbackPortForm(t *testing.T) {
	pub, priv := testKeyPair(t)
	writeKnownHosts(t, "[127.0.0.1]:2222 "+priv+"\n")
	cb, err := hostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	// 回调收到 hostname 形式 127.0.0.1:2222
	if err := cb("127.0.0.1:2222", nil, pub); err != nil {
		t.Errorf("port-form host should be accepted: %v", err)
	}
}

func TestAuthMethodsPasswordEnv(t *testing.T) {
	writeConfig(t, "Host p\n  HostName 1.1.1.1\n")
	t.Setenv("SSH_PASS_P", "secret123")
	auths, err := authMethods("p")
	if err != nil {
		t.Fatal(err)
	}
	if len(auths) == 0 {
		t.Error("password auth method should be present")
	}
}

func TestAuthMethodsNoCreds(t *testing.T) {
	writeConfig(t, "Host n\n  HostName 1.1.1.1\n")
	t.Setenv("SSH_PASS_N", "")
	t.Setenv("SSH_PASS", "")
	_, err := authMethods("n")
	if err == nil {
		t.Error("no credentials should error")
	}
}
