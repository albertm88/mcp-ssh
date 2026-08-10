// Package server 实现 8 个 MCP 工具（与 Python 版行为兼容）。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/albertm88/mcp-ssh/internal/audit"
	"github.com/albertm88/mcp-ssh/internal/results"
	"github.com/albertm88/mcp-ssh/internal/review"
	"github.com/albertm88/mcp-ssh/internal/sshclient"
)

// S 是 MCP 服务器实例。
var S *server.MCPServer

// reviewEngine 是全局审核引擎。
var reviewEngine = review.NewEngine()

const (
	maxSingleFileBytes = 100 << 20 // 100 MiB
	maxOutputBytes     = 1 << 20   // 1 MiB
)

// Register 注册全部 8 个工具。
func Register() *server.MCPServer {
	s := server.NewMCPServer("ssh", "1.0.0")
	S = s

	s.AddTool(sshExecTool(), sshExecHandler)
	s.AddTool(sshUploadTool(), sshUploadHandler)
	s.AddTool(sshDownloadTool(), sshDownloadHandler)
	s.AddTool(sshFilesystemTool(), sshFilesystemHandler)
	s.AddTool(sshListHostsTool(), sshListHostsHandler)
	s.AddTool(sshGetReviewModeTool(), sshGetReviewModeHandler)
	s.AddTool(sshSetReviewModeTool(), sshSetReviewModeHandler)
	s.AddTool(sshGetAuditLogsTool(), sshGetAuditLogsHandler)
	return s
}

// envelopeFromResult 把工具返回 map 序列化为 MCP 文本。
func envelopeText(env *results.Envelope) string {
	b, err := json.Marshal(env)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// handleResult 是工具处理器统一返回（返回结构化内容 + 文本）。
func handleResult(env *results.Envelope) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultText(envelopeText(env)), nil
}

// execWithReview 执行带审核与防御纵深校验的命令执行流程。
func execWithReview(host, command string, timeout float64, allowDangerous bool, shell string, environment map[string]string) *results.Envelope {
	ctx := &review.Context{
		Tool:           "ssh_exec",
		Command:        command,
		Host:           host,
		AllowDangerous: allowDangerous,
		Shell:          shell,
	}

	// 防御纵深（所有模式生效）
	if err := review.ValidateCommand(command, allowDangerous); err != nil {
		return results.MakeFailure(results.ErrorInvalidArgument, err.Error(), "ssh_exec", host, "", nil, nil)
	}

	// 环境变量名规范化
	envNames := []string{}
	if environment != nil {
		for name := range environment {
			envNames = append(envNames, name)
		}
		ctx.Environment = envNames
	}

	// 审核
	res := reviewEngine.Review(ctx)
	if !res.Approved {
		return results.MakeRejected(res.Reason, "ssh_exec", host)
	}
	reviewInfo := &results.ReviewInfo{
		Mode:     string(res.Mode),
		Decision: "approved",
		Risk:     res.RiskLevel,
		Reason:   res.Reason,
		PlanID:   res.PlanID,
	}

	// 规范化命令（shell 包装）
	cmd := normalizeCommand(command, shell, environment)

	t0 := time.Now()
	client, err := sshclient.Connect(host, 10*time.Second)
	if err != nil {
		return connectFailureEnvelope(err, "ssh_exec", host, reviewInfo)
	}
	defer client.Close()

	execTimeout := time.Duration(timeout) * time.Second
	if execTimeout <= 0 {
		execTimeout = 30 * time.Second
	}
	result, err := client.Exec(cmd, execTimeout, true)
	elapsed := time.Since(t0).Milliseconds()

	if err != nil {
		if result != nil && result.TimedOut {
			return results.MakeFailure(results.ErrorExecTimeout, "远程命令执行超过 timeout deadline", "ssh_exec", host, results.StatusTimedOut,
				map[string]interface{}{"exit_code": nil, "timed_out": true, "truncated": false}, reviewInfo)
		}
		return results.MakeFailure(results.ErrorRemoteIOError, err.Error(), "ssh_exec", host, "",
			map[string]interface{}{"exit_code": nil, "timed_out": false, "truncated": false}, reviewInfo)
	}

	env := results.MakeSuccess("ssh_exec", host,
		map[string]interface{}{
			"exit_code":  result.ExitCode,
			"stdout":     result.Stdout,
			"stderr":     result.Stderr,
			"timed_out":  result.TimedOut,
			"truncated":  result.Truncated,
		},
		"", reviewInfo)
	env.DurationMs = elapsed

	// 非零退出码
	if result.ExitCode != 0 {
		return results.MakeFailure(results.ErrorRemoteExitNonzero,
			fmt.Sprintf("远程命令退出码非零：%d", result.ExitCode), "ssh_exec", host, "",
			map[string]interface{}{
				"exit_code": result.ExitCode, "stdout": result.Stdout,
				"stderr": result.Stderr, "timed_out": false, "truncated": result.Truncated,
			}, reviewInfo)
	}
	// 输出截断
	if result.Truncated {
		return results.MakeFailure(results.ErrorOutputLimit,
			fmt.Sprintf("远程命令输出超过配额（最大%d字节）", maxOutputBytes), "ssh_exec", host, "",
			map[string]interface{}{
				"exit_code": result.ExitCode, "stdout": result.Stdout,
				"stderr": result.Stderr, "timed_out": false, "truncated": true,
			}, reviewInfo)
	}
	parts := []string{fmt.Sprintf("[exit_code] %d", result.ExitCode)}
	if result.Stdout != "" {
		parts = append(parts, "[stdout]\n"+strings.TrimRight(result.Stdout, "\n"))
	}
	if result.Stderr != "" {
		parts = append(parts, "[stderr]\n"+strings.TrimRight(result.Stderr, "\n"))
	}
	env.Text = strings.Join(parts, "\n")

	// 审计
	_ = audit.Append(audit.Record{
		Host: host, Tool: "ssh_exec", Status: env.Status,
		Args: map[string]interface{}{"command": command, "exit_code": result.ExitCode},
	})
	return env
}

// normalizeCommand 跨平台命令标准化（与 Python 版 _normalize_command 一致）。
func normalizeCommand(command, shell string, environment map[string]string) string {
	command = strings.ReplaceAll(command, "\r\n", "\n")
	command = strings.ReplaceAll(command, "\r", "\n")

	if shell != "" {
		switch strings.ToLower(shell) {
		case "cmd", "cmd.exe":
			command = "cmd /c " + command
		case "powershell", "pwsh", "ps":
			encoded := powershellEncodedCommand(command)
			command = "powershell -NoProfile -EncodedCommand " + encoded
		case "bash", "sh", "zsh":
			command = fmt.Sprintf("%s -c %s", shell, shellQuote(command))
		}
	}

	if environment != nil {
		parts := []string{}
		for k, v := range environment {
			parts = append(parts, "export "+k+"="+shellQuote(v)+";")
		}
		command = strings.Join(parts, " ") + " " + command
	}
	return command
}

func powershellEncodedCommand(command string) string {
	// UTF-16LE base64
	utf16 := []byte{}
	for _, r := range []byte(command) {
		utf16 = append(utf16, r, 0)
	}
	imported := []byte{}
	_ = imported
	// 简单实现：按字节转 UTF-16LE
	b := make([]byte, 0, len(command)*2)
	for i := 0; i < len(command); i++ {
		b = append(b, command[i], 0)
	}
	_ = utf16
	return base64Encode(b)
}

func base64Encode(b []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, 0, (len(b)+2)/3*4)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		remaining := len(b) - i
		n = uint32(b[i]) << 16
		if remaining > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if remaining > 2 {
			n |= uint32(b[i+2])
		}
		out = append(out, chars[(n>>18)&0x3F], chars[(n>>12)&0x3F])
		if remaining > 1 {
			out = append(out, chars[(n>>6)&0x3F])
		} else {
			out = append(out, '=')
		}
		if remaining > 2 {
			out = append(out, chars[n&0x3F])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}

// shellQuote 单引号包裹（POSIX 语义，与 Python shlex.quote 一致）。
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$`&|;<>()*?[]#~=%!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// connectFailureEnvelope 把连接错误映射为稳定错误 envelope。
func connectFailureEnvelope(err error, tool, host string, reviewInfo *results.ReviewInfo) *results.Envelope {
	if sshclient.IsHostKeyError(err) {
		return results.MakeFailure(results.ErrorHostKeyMismatch, err.Error(), tool, host, "", nil, reviewInfo)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "认证失败"):
		return results.MakeFailure(results.ErrorAuthFailed, msg, tool, host, "", nil, reviewInfo)
	case strings.Contains(msg, "身份文件不存在"):
		return results.MakeFailure(results.ErrorInvalidArgument, msg, tool, host, "", nil, reviewInfo)
	case strings.Contains(msg, "连接超时") || strings.Contains(strings.ToLower(msg), "timeout"):
		return results.MakeFailure(results.ErrorConnectTimeout, msg, tool, host, results.StatusTimedOut, nil, reviewInfo)
	default:
		return results.MakeFailure(results.ErrorConnectionLost, msg, tool, host, "", nil, reviewInfo)
	}
}

// listHosts 解析 ~/.ssh/config 主机别名。
func listHosts() ([]map[string]string, string) {
	dir := sshDir()
	path := filepath.Join(dir, "config")
	data, err := os.ReadFile(path)
	entries := []map[string]string{}
	if err != nil {
		return entries, "~/.ssh/config 中没有配置 Host 别名。"
	}
	current := ""
	hostConfigs := map[string]map[string]string{}
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
			current = value
			if !strings.ContainsAny(value, "*?") {
				hostConfigs[current] = map[string]string{}
			} else {
				current = ""
			}
		} else if current != "" {
			switch key {
			case "hostname", "user", "port", "identityfile":
				hostConfigs[current][key] = value
			}
		}
	}
	output := []string{"配置的主机别名："}
	for host := range hostConfigs {
		conf := hostConfigs[host]
		entry := map[string]string{"alias": host}
		if hn := conf["hostname"]; hn != "" {
			user := conf["user"]
			if user == "" {
				user = os.Getenv("USER")
			}
			port := conf["port"]
			if port == "" {
				port = "22"
			}
			entry["hostname"] = hn
			entry["user"] = user
			entry["port"] = port
			output = append(output, "  "+host+" → "+user+"@"+hn+":"+port)
		} else {
			output = append(output, "  "+host)
		}
		entries = append(entries, entry)
	}
	return entries, strings.Join(output, "\n")
}

func sshDir() string {
	if base := os.Getenv("USERPROFILE"); base != "" && os.PathSeparator == '\\' {
		return filepath.Join(base, ".ssh")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ssh"
	}
	return filepath.Join(home, ".ssh")
}

// intParam 提取 int 参数（args 为 mcp-go 的 map[string]any）。
func intParam(args any, key string, def int) int {
	m, ok := args.(map[string]interface{})
	if !ok {
		return def
	}
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case json.Number:
			if n, err := strconv.Atoi(t.String()); err == nil {
				return n
			}
		case string:
			if n, err := strconv.Atoi(t); err == nil {
				return n
			}
		}
	}
	return def
}

// strParam 提取 string 参数。
func strParam(args any, key string, def string) string {
	m, ok := args.(map[string]interface{})
	if !ok {
		return def
	}
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// boolParam 提取 bool 参数。
func boolParam(args any, key string, def bool) bool {
	m, ok := args.(map[string]interface{})
	if !ok {
		return def
	}
	if v, ok := m[key]; ok && v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

// requireHost 校验 host 参数。
func requireHost(args any) string {
	return strParam(args, "host", "")
}

var _ = context.Background
