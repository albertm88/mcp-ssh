package server

import (
	"encoding/json"
	"testing"

	"github.com/albertm88/mcp-ssh/internal/results"
)

// envelope 结构契约：与 Python 版字段完全一致。
func TestEnvelopeJSONContract(t *testing.T) {
	env := results.MakeSuccess("ssh_exec", "h",
		map[string]interface{}{"exit_code": 0}, "ok",
		&results.ReviewInfo{Mode: "off", Decision: "approved", Risk: "unknown", Reason: "r", PlanID: "p"})
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	// Python 版 envelope 全部字段必须存在
	for _, field := range []string{
		"schema_version", "request_id", "ok", "tool", "host",
		"status", "duration_ms", "review", "data", "warnings", "text",
	} {
		if _, ok := m[field]; !ok {
			t.Errorf("envelope missing field: %s", field)
		}
	}
	// error 字段在成功时不应存在（omitempty）
	if _, ok := m["error"]; ok {
		t.Error("success envelope should omit error")
	}
}

func TestFailureEnvelopeHasError(t *testing.T) {
	env := results.MakeFailure(results.ErrorHostKeyMismatch, "bad key", "ssh_exec", "h", "", nil, nil)
	data, _ := json.Marshal(env)
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["error"]; !ok {
		t.Error("failure envelope must include error")
	}
	errObj := m["error"].(map[string]interface{})
	if errObj["code"] != results.ErrorHostKeyMismatch {
		t.Errorf("error code = %v", errObj["code"])
	}
}

// 防御纵深：注入命令必须返回 INVALID_ARGUMENT（off 模式也不可绕过）。
func TestSshExecInjectionFailsClosed(t *testing.T) {
	env := execWithReview("h", "cat /etc/passwd; chmod 777 /etc/passwd", 30, false, "", nil)
	if env.Status != results.StatusFailed || env.Error == nil || env.Error.Code != results.ErrorInvalidArgument {
		t.Errorf("injection should fail closed: %+v", env)
	}
}

func TestSshExecForkBombFailsClosed(t *testing.T) {
	for _, bomb := range []string{":(){ :|:& };:", ":(){:|:&};:"} {
		env := execWithReview("h", bomb, 30, false, "", nil)
		if env.Error == nil || env.Error.Code != results.ErrorInvalidArgument {
			t.Errorf("fork bomb should fail closed: %q -> %+v", bomb, env)
		}
	}
}

func TestSshExecDangerousExemptWithFlag(t *testing.T) {
	// allow_dangerous=True 时危险命令跳过 ValidateCommand，
	// 但审核引擎（默认 whitelist）会拒绝 → REVIEW_REJECTED（不触发连接）
	env := execWithReview("h", "rm -rf /", 30, true, "", nil)
	if env.Status != results.StatusRejected {
		t.Errorf("dangerous command should hit whitelist review: %+v", env)
	}
}

// shell 包装结构。
func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"pwd":     "pwd",
		"echo hi": "'echo hi'",
		"it's":    "'it'\"'\"'s'",
		"":        "''",
		"a=b":     "'a=b'",
		"$HOME":   "'$HOME'",
	}
	for input, want := range cases {
		got := shellQuote(input)
		if got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", input, got, want)
		}
	}
}

func TestNormalizeCommandShell(t *testing.T) {
	if got := normalizeCommand("echo hi", "bash", nil); got != "bash -c 'echo hi'" {
		t.Errorf("bash wrap = %s", got)
	}
	if got := normalizeCommand("ipconfig", "cmd", nil); got != "cmd /c ipconfig" {
		t.Errorf("cmd wrap = %s", got)
	}
	if got := normalizeCommand("Get-Process", "powershell", nil); !stringsHasPrefix(got, "powershell -NoProfile -EncodedCommand ") {
		t.Errorf("pwsh wrap = %s", got)
	}
	if got := normalizeCommand("ls -la", "", nil); got != "ls -la" {
		t.Errorf("no shell should pass through: %s", got)
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestListHostsParsing(t *testing.T) {
	// 不依赖真实 ~/.ssh/config：仅验证函数不 panic 且返回结构正确
	entries, _ := listHosts()
	if entries == nil {
		t.Error("listHosts should return non-nil entries")
	}
}

// 回归：int 参数（timeout/limit）在 mcp-go 直接构造（int 类型）与
// JSON 解码（float64 类型）两种输入下都必须正确解析。
func TestIntParamBothTypes(t *testing.T) {
	if got := intParam(map[string]interface{}{"timeout": 0}, "timeout", 30); got != 0 {
		t.Errorf("int literal: got %d, want 0", got)
	}
	if got := intParam(map[string]interface{}{"timeout": float64(5)}, "timeout", 30); got != 5 {
		t.Errorf("float64: got %d, want 5", got)
	}
	if got := intParam(map[string]interface{}{"timeout": int64(7)}, "timeout", 30); got != 7 {
		t.Errorf("int64: got %d, want 7", got)
	}
	if got := intParam(map[string]interface{}{"timeout": "9"}, "timeout", 30); got != 9 {
		t.Errorf("string: got %d, want 9", got)
	}
	// 缺失 → 默认
	if got := intParam(map[string]interface{}{}, "timeout", 30); got != 30 {
		t.Errorf("missing: got %d, want default 30", got)
	}
}
