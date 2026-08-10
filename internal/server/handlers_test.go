package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func call(t *testing.T, name string, args map[string]interface{}) *mcp.CallToolResult {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	var result *mcp.CallToolResult
	var err error
	switch name {
	case "ssh_exec":
		result, err = sshExecHandler(context.Background(), req)
	case "ssh_upload":
		result, err = sshUploadHandler(context.Background(), req)
	case "ssh_download":
		result, err = sshDownloadHandler(context.Background(), req)
	case "ssh_filesystem":
		result, err = sshFilesystemHandler(context.Background(), req)
	case "ssh_list_hosts":
		result, err = sshListHostsHandler(context.Background(), req)
	case "ssh_get_review_mode":
		result, err = sshGetReviewModeHandler(context.Background(), req)
	case "ssh_set_review_mode":
		result, err = sshSetReviewModeHandler(context.Background(), req)
	case "ssh_get_audit_logs":
		result, err = sshGetAuditLogsHandler(context.Background(), req)
	default:
		t.Fatalf("unknown tool: %s", name)
	}
	if err != nil {
		t.Fatalf("%s handler error: %v", name, err)
	}
	return result
}

// parseEnvelope 从工具结果提取 envelope JSON。
func parseEnvelope(t *testing.T, res *mcp.CallToolResult) map[string]interface{} {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("empty result content")
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("content type: %T", res.Content[0])
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(text.Text), &m); err != nil {
		t.Fatalf("envelope parse: %v\n%s", err, text.Text)
	}
	return m
}

// ---- ssh_exec 参数校验 ----

func TestSshExecHandlerEmptyHost(t *testing.T) {
	res := call(t, "ssh_exec", map[string]interface{}{"command": "ls"})
	env := parseEnvelope(t, res)
	if env["status"] != "failed" || env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("env = %+v", env)
	}
}

func TestSshExecHandlerNonPositiveTimeout(t *testing.T) {
	res := call(t, "ssh_exec", map[string]interface{}{"host": "h", "command": "ls", "timeout": 0})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("env = %+v", env)
	}
}

func TestSshExecHandlerInjectionFailsClosed(t *testing.T) {
	res := call(t, "ssh_exec", map[string]interface{}{
		"host": "h", "command": "cat /etc/passwd; chmod 777 /etc/passwd",
	})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("injection must fail closed: %+v", env)
	}
}

// ---- ssh_upload 参数校验 ----

func TestSshUploadHandlerMissingArgs(t *testing.T) {
	res := call(t, "ssh_upload", map[string]interface{}{"host": "h"})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("env = %+v", env)
	}
}

func TestSshUploadHandlerMissingLocalFile(t *testing.T) {
	res := call(t, "ssh_upload", map[string]interface{}{
		"host": "h", "local_path": "C:\\nonexistent\\file.txt", "remote_path": "/tmp/x",
	})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("env = %+v", env)
	}
}

func TestSshUploadHandlerSensitivePath(t *testing.T) {
	res := call(t, "ssh_upload", map[string]interface{}{
		"host": "h", "local_path": "C:\\Windows\\temp\\f", "remote_path": "/etc/passwd",
	})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("sensitive path must be blocked: %+v", env)
	}
}

// ---- ssh_download 校验 ----

func TestSshDownloadHandlerSensitivePath(t *testing.T) {
	res := call(t, "ssh_download", map[string]interface{}{
		"host": "h", "remote_path": "/etc/shadow", "local_path": "C:\\temp\\x",
	})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("sensitive path must be blocked: %+v", env)
	}
}

func TestSshDownloadHandlerTraversal(t *testing.T) {
	res := call(t, "ssh_download", map[string]interface{}{
		"host": "h", "remote_path": "/tmp/../etc/passwd", "local_path": "C:\\temp\\x",
	})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("traversal must be blocked: %+v", env)
	}
}

// ---- ssh_filesystem 校验 ----

func TestSshFilesystemEmptyPath(t *testing.T) {
	res := call(t, "ssh_filesystem", map[string]interface{}{
		"host": "h", "action": "list", "remote_path": "",
	})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("empty path must fail: %+v", env)
	}
}

func TestSshFilesystemInvalidAction(t *testing.T) {
	res := call(t, "ssh_filesystem", map[string]interface{}{
		"host": "h", "action": "explode", "remote_path": "/tmp",
	})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("invalid action must fail: %+v", env)
	}
}

func TestSshFilesystemSensitive(t *testing.T) {
	res := call(t, "ssh_filesystem", map[string]interface{}{
		"host": "h", "action": "list", "remote_path": "/etc/passwd",
	})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("sensitive path must fail: %+v", env)
	}
}

// ---- 审核模式工具 ----

func TestSetReviewModeInvalid(t *testing.T) {
	res := call(t, "ssh_set_review_mode", map[string]interface{}{"mode": "bogus"})
	env := parseEnvelope(t, res)
	if env["error"].(map[string]interface{})["code"] != "INVALID_ARGUMENT" {
		t.Errorf("env = %+v", env)
	}
}

func TestSetGetReviewModeRoundTrip(t *testing.T) {
	res := call(t, "ssh_set_review_mode", map[string]interface{}{"mode": "smart"})
	env := parseEnvelope(t, res)
	if env["ok"] != true {
		t.Errorf("set failed: %+v", env)
	}
	res = call(t, "ssh_get_review_mode", map[string]interface{}{})
	env = parseEnvelope(t, res)
	if env["data"].(map[string]interface{})["mode"] != "smart" {
		t.Errorf("get mode = %+v", env)
	}
	// 恢复
	call(t, "ssh_set_review_mode", map[string]interface{}{"mode": "whitelist"})
}

// ---- 其他工具 ----

func TestListHostsHandler(t *testing.T) {
	res := call(t, "ssh_list_hosts", map[string]interface{}{})
	env := parseEnvelope(t, res)
	if env["ok"] != true {
		t.Errorf("env = %+v", env)
	}
}

func TestGetAuditLogsHandler(t *testing.T) {
	res := call(t, "ssh_get_audit_logs", map[string]interface{}{"limit": 5})
	env := parseEnvelope(t, res)
	if env["ok"] != true {
		t.Errorf("env = %+v", env)
	}
}
