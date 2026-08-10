// Package sshclient 封装 SSH 连接、认证、命令执行与 SFTP 传输。
// 与 Python 版行为兼容：host key 严格策略、密钥优先密码兜底、超时控制。
package sshclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// HostKeyError 表示 host key 校验失败。
type HostKeyError struct{ msg string }

func (e *HostKeyError) Error() string { return e.msg }

// IsHostKeyError 判断错误是否为 host key 问题。
func IsHostKeyError(err error) bool {
	var hk *HostKeyError
	return errors.As(err, &hk)
}

// IsHostKeyFailure 判断 SSH 错误是否属于 host key 失败（兼容 Python 版语义）。
func IsHostKeyFailure(err error) bool {
	if err == nil {
		return false
	}
	var hk *HostKeyError
	if errors.As(err, &hk) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "not found in known_hosts") ||
		strings.Contains(msg, "host key mismatch") ||
		strings.Contains(msg, "no host key") ||
		strings.Contains(msg, "certificate is not authorized")
}

// HostKeyMismatchMessage 构造脱敏的 host key 错误消息。
func HostKeyMismatchMessage(host string, port int, err error) string {
	return fmt.Sprintf("主机密钥校验失败：%s:%d — %s。请运行 ssh-keyscan -H %s >> ~/.ssh/known_hosts", host, port, err, host)
}

// sshDir 返回 .ssh 目录（跨平台：Windows 用 USERPROFILE）。
func sshDir() string {
	if base := os.Getenv("USERPROFILE"); base != "" && isWindows() {
		return filepath.Join(base, ".ssh")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ssh"
	}
	return filepath.Join(home, ".ssh")
}

func isWindows() bool {
	return os.PathSeparator == '\\'
}

func systemKnownHostsPath() string {
	return filepath.Join(sshDir(), "known_hosts")
}

// HasTrustedKnownHosts 检查是否存在可信 known_hosts 来源。
func HasTrustedKnownHosts() bool {
	if v := os.Getenv("SSH_KNOWN_HOSTS"); v != "" {
		_, err := os.Stat(v)
		return err == nil
	}
	_, err := os.Stat(systemKnownHostsPath())
	return err == nil
}

// knownHostsPaths 返回所有 known_hosts 候选路径。
func knownHostsPaths() []string {
	paths := []string{}
	if v := os.Getenv("SSH_KNOWN_HOSTS"); v != "" {
		paths = append(paths, v)
	}
	paths = append(paths, systemKnownHostsPath())
	return paths
}

// LoadKnownHosts 加载可信主机密钥集合。
func LoadKnownHosts() (map[string]ssh.PublicKey, error) {
	keys := map[string]ssh.PublicKey{}
	for _, p := range knownHostsPaths() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			_, hosts, pubKey, _, rest, err := ssh.ParseKnownHosts([]byte(line + "\n"))
			if err != nil {
				continue
			}
			_ = rest
			for _, h := range hosts {
				keys[h] = pubKey
			}
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("没有可用的 known_hosts 可信来源：请配置 SSH_KNOWN_HOSTS 或系统 ~/.ssh/known_hosts 后重试，禁止自动信任未知主机密钥。")
	}
	return keys, nil
}

// hostKeyCallback 构造严格 RejectPolicy 回调。
func hostKeyCallback() (ssh.HostKeyCallback, error) {
	keys, err := LoadKnownHosts()
	if err != nil {
		return nil, err
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		host := hostname
		if h, _, err := net.SplitHostPort(hostname); err == nil {
			host = h
		}
		fingerprint := ssh.FingerprintSHA256(key)
		// known_hosts 中可能的键形式：[host]:port、host、hostname
		candidates := []string{host, hostname}
		if h, p, err := net.SplitHostPort(hostname); err == nil {
			candidates = append(candidates, "["+h+"]:"+p)
		}
		for _, candidate := range candidates {
			if known, ok := keys[candidate]; ok {
				if known.Type() == key.Type() && bytes.Equal(known.Marshal(), key.Marshal()) {
					return nil
				}
				return fmt.Errorf("主机密钥不匹配（%s），已拒绝连接。指纹：%s", candidate, fingerprint)
			}
		}
		return fmt.Errorf("未知主机密钥（%s），已拒绝连接。指纹：%s。请先 ssh-keyscan -H %s >> ~/.ssh/known_hosts", host, fingerprint, host)
	}, nil
}

// passwordEnvVar 构造 SSH_PASS_<HOST> 环境变量名。
func passwordEnvVar(host string) string {
	key := "SSH_PASS_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(host))
	return key
}

// ResolveHost 解析 host 参数为 (user, host, port)。
// 支持 user@host:port 形式；优先从 ~/.ssh/config 读取别名配置。
func ResolveHost(hostSpec string) (string, string, int) {
	userName := os.Getenv("USER")
	if u, err := user.Current(); err == nil {
		userName = u.Username
		// Windows 下 user.Current() 返回 DOMAIN\User，SSH 只要后者
		if idx := strings.LastIndex(userName, "\\"); idx >= 0 {
			userName = userName[idx+1:]
		}
	}
	host := hostSpec
	port := 22

	// user@host[:port]
	if at := strings.LastIndex(hostSpec, "@"); at >= 0 {
		userName = hostSpec[:at]
		host = hostSpec[at+1:]
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		fmt.Sscanf(p, "%d", &port)
	}

	// ~/.ssh/config 别名覆盖
	if cfg := sshConfigFor(host); cfg != nil {
		if cfg.User != "" {
			userName = cfg.User
		}
		if cfg.HostName != "" {
			host = cfg.HostName
		}
		if cfg.Port != 0 {
			port = cfg.Port
		}
	}
	return userName, host, port
}

// configEntry 是 ~/.ssh/config 的简化条目。
type configEntry struct {
	User     string
	HostName string
	Port     int
	IdentityFile string
}

// sshConfigFor 解析 ~/.ssh/config 中指定别名/主机的配置。
func sshConfigFor(alias string) *configEntry {
	path := filepath.Join(sshDir(), "config")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var entry *configEntry
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")
		if key == "host" {
			// 已匹配目标块后遇到下一个 Host → 返回
			if entry != nil {
				return entry
			}
			if strings.EqualFold(value, alias) {
				entry = &configEntry{}
			}
			continue
		}
		if entry == nil {
			continue
		}
		switch key {
		case "user":
			entry.User = value
		case "hostname":
			entry.HostName = value
		case "port":
			fmt.Sscanf(value, "%d", &entry.Port)
		case "identityfile":
			entry.IdentityFile = expandTilde(value)
		}
	}
	return entry
}

func expandTilde(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// authMethods 构建认证方法：密钥优先，密码兜底。
func authMethods(host string) ([]ssh.AuthMethod, error) {
	methods := []ssh.AuthMethod{}
	// 密钥
	for _, keyPath := range candidateKeyPaths(host) {
		if data, err := os.ReadFile(keyPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(data); err == nil {
				methods = append(methods, ssh.PublicKeys(signer))
				break
			}
		}
	}
	// 密码（SSH_PASS_<HOST> 或 SSH_PASS）
	pass := os.Getenv(passwordEnvVar(host))
	if pass == "" {
		pass = os.Getenv("SSH_PASS")
	}
	if pass != "" {
		methods = append(methods, ssh.Password(pass))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("无可用密钥/密码")
	}
	return methods, nil
}

// candidateKeyPaths 返回候选密钥路径（含 config IdentityFile）。
func candidateKeyPaths(host string) []string {
	paths := []string{}
	dir := sshDir()
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"} {
		paths = append(paths, filepath.Join(dir, name))
	}
	if cfg := sshConfigFor(host); cfg != nil && cfg.IdentityFile != "" {
		paths = append([]string{cfg.IdentityFile}, paths...)
	}
	// 环境变量 SSH_IDENTITY_FILE 覆盖
	if v := os.Getenv("SSH_IDENTITY_FILE"); v != "" {
		paths = append([]string{v}, paths...)
	}
	return paths
}

// Client 是一次 SSH 连接。
type Client struct {
	conn    *ssh.Client
	Address string
}

// Connect 建立连接（host key 严格校验 + 超时）。
func Connect(hostSpec string, timeout time.Duration) (*Client, error) {
	user, host, port := ResolveHost(hostSpec)
	addr := fmt.Sprintf("%s:%d", host, port)

	callback, err := hostKeyCallback()
	if err != nil {
		return nil, &HostKeyError{msg: err.Error()}
	}
	// 用原始别名查找密钥（config 的 IdentityFile 挂在别名下）
	auths, err := authMethods(hostSpec)
	if err != nil {
		return nil, fmt.Errorf("无法连接 %s（%s@%s:%d）：%w", hostSpec, user, host, port, err)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: callback,
		Timeout:         timeout,
	}

	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		if IsHostKeyFailure(err) {
			return nil, &HostKeyError{msg: HostKeyMismatchMessage(host, port, err)}
		}
		if strings.Contains(err.Error(), "unable to authenticate") || strings.Contains(err.Error(), "permission denied") {
			return nil, fmt.Errorf("认证失败：%s@%s:%d — %v", user, host, port, err)
		}
		if strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "身份文件不存在") {
			return nil, fmt.Errorf("SSH 身份文件不存在：%v", err)
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("主机不可达：%s:%d 连接超时（%v）", host, port, timeout)
		}
		return nil, fmt.Errorf("无法连接 %s（%s@%s:%d）：%v", hostSpec, user, host, port, err)
	}
	return &Client{conn: conn, Address: addr}, nil
}

// Close 关闭连接。
func (c *Client) Close() { c.conn.Close() }

// SSHConn 返回底层 SSH 连接（供 pkg/sftp 使用）。
func (c *Client) SSHConn() (*ssh.Client, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("连接已关闭")
	}
	return c.conn, nil
}

// ExecResult 是命令执行结果。
type ExecResult struct {
	ExitCode  int
	Stdout    string
	Stderr    string
	TimedOut  bool
	Truncated bool
}

// Exec 执行命令，返回 stdout/stderr/退出码。
func (c *Client) Exec(command string, timeout time.Duration, getPTY bool) (*ExecResult, error) {
	session, err := c.conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	// 输出配额（与 Python 版 _MAX_OUTPUT_BYTES 一致：1 MiB）
	const maxOutput = 1 << 20

	var stdout, stderr strings.Builder
	stdoutLimited := &limitedWriter{b: &stdout, max: maxOutput, truncated: &stdoutTrunc}
	stderrLimited := &limitedWriter{b: &stderr, max: maxOutput, truncated: &stderrTrunc}
	session.Stdout = stdoutLimited
	session.Stderr = stderrLimited

	if getPTY {
		modes := ssh.TerminalModes{ssh.ECHO: 0}
		if err := session.RequestPty("xterm", 80, 24, modes); err != nil {
			return nil, err
		}
	}

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	var runErr error
	select {
	case runErr = <-done:
	case <-time.After(timeout):
		session.Close()
		return &ExecResult{TimedOut: true}, fmt.Errorf("远程命令执行超过 timeout deadline")
	}

	exitCode := 0
	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitStatus()
		} else {
			return nil, runErr
		}
	}
	return &ExecResult{
		ExitCode:  exitCode,
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		TimedOut:  false,
		Truncated: stdoutTrunc || stderrTrunc,
	}, nil
}

var stdoutTrunc, stderrTrunc bool

type limitedWriter struct {
	b         *strings.Builder
	max       int
	truncated *bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.max - w.b.Len()
	if remaining <= 0 {
		*w.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		w.b.Write(p[:remaining])
		*w.truncated = true
		return len(p), nil
	}
	return w.b.Write(p)
}

// SFTPClient 封装 SFTP 会话。
type SFTPClient struct {
	conn *ssh.Client
}

// NewSFTP 创建 SFTP 客户端。
func (c *Client) NewSFTP() (*SFTPClient, error) {
	return &SFTPClient{conn: c.conn}, nil
}

// Sha256File 计算本地文件的 SHA-256。
func Sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// Sha256Bytes 计算字节流的 SHA-256。
func Sha256Bytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
