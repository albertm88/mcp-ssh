package sshclient

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) {
	t.Helper()
	t.Setenv("USERPROFILE", t.TempDir())
	dir := sshDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSSHConfigForAlias(t *testing.T) {
	writeConfig(t, `
Host gitlab
  HostName gitlab.example.com
  User dev
  Port 2222
  IdentityFile ~/.ssh/gitlab_key

Host myserver
  HostName 10.0.0.5
  User ubuntu
`)
	cfg := sshConfigFor("myserver")
	if cfg == nil {
		t.Fatal("sshConfigFor returned nil")
	}
	if cfg.HostName != "10.0.0.5" || cfg.User != "ubuntu" {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.Port != 0 { // 未指定保持默认
		t.Errorf("port = %d, want 0 (default 22)", cfg.Port)
	}
}

func TestSSHConfigForPortAndIdentity(t *testing.T) {
	writeConfig(t, `
Host special
  HostName 1.2.3.4
  Port 2222
  IdentityFile ~/keys/special
`)
	cfg := sshConfigFor("special")
	if cfg == nil {
		t.Fatal("nil")
	}
	if cfg.Port != 2222 {
		t.Errorf("port = %d", cfg.Port)
	}
	if cfg.IdentityFile != filepath.Join(home(), "keys", "special") {
		t.Errorf("identity = %q", cfg.IdentityFile)
	}
}

func TestSSHConfigForMissingAlias(t *testing.T) {
	writeConfig(t, `
Host a
  HostName 1.1.1.1
`)
	if cfg := sshConfigFor("b"); cfg != nil {
		t.Errorf("missing alias should return nil, got %+v", cfg)
	}
}

func TestSSHConfigForTrailingHostBlock(t *testing.T) {
	// 回归：目标块后面还有别的 Host 块时不能覆盖 entry
	writeConfig(t, `
Host target
  HostName 9.9.9.9
  User root

Host other
  HostName 8.8.8.8
`)
	cfg := sshConfigFor("target")
	if cfg == nil || cfg.HostName != "9.9.9.9" {
		t.Errorf("trailing host block clobbered entry: %+v", cfg)
	}
}

func TestCandidateKeyPathsIncludesIdentity(t *testing.T) {
	writeConfig(t, `
Host khost
  HostName 1.1.1.1
  IdentityFile ~/.ssh/custom_key
`)
	paths := candidateKeyPaths("khost")
	if len(paths) == 0 || paths[0] != filepath.Join(home(), ".ssh", "custom_key") {
		t.Errorf("paths = %v", paths)
	}
}

func TestCandidateKeyPathsDefaults(t *testing.T) {
	writeConfig(t, "Host x\n  HostName 1.1.1.1\n")
	paths := candidateKeyPaths("x")
	want := []string{
		filepath.Join(sshDir(), "id_ed25519"),
		filepath.Join(sshDir(), "id_ecdsa"),
		filepath.Join(sshDir(), "id_rsa"),
		filepath.Join(sshDir(), "id_dsa"),
	}
	for i, w := range want {
		if paths[i] != w {
			t.Errorf("paths[%d] = %s, want %s", i, paths[i], w)
		}
	}
}

func TestResolveHostConfigOverride(t *testing.T) {
	writeConfig(t, `
Host alias
  HostName 10.1.1.1
  User alice
  Port 2222
`)
	u, h, p := ResolveHost("alias")
	if u != "alice" || h != "10.1.1.1" || p != 2222 {
		t.Errorf("resolved = %q@%s:%d", u, h, p)
	}
}

func TestResolveHostUserAtPort(t *testing.T) {
	writeConfig(t, "")
	u, h, p := ResolveHost("bob@1.2.3.4:2222")
	if u != "bob" || h != "1.2.3.4" || p != 2222 {
		t.Errorf("resolved = %q@%s:%d", u, h, p)
	}
}

func home() string {
	// USERPROFILE 已被 t.Setenv 指向临时目录
	if v := os.Getenv("USERPROFILE"); v != "" && os.PathSeparator == '\\' {
		return v
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}
