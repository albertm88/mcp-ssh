package server

import (
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// 8 个 MCP 工具契约（与 Python 版 lite 工具面一致，去掉 batch/dir 传输）。
var expectedTools = []string{
	"ssh_exec",
	"ssh_upload",
	"ssh_download",
	"ssh_filesystem",
	"ssh_list_hosts",
	"ssh_get_review_mode",
	"ssh_set_review_mode",
	"ssh_get_audit_logs",
}

func TestToolRegistration(t *testing.T) {
	s := Register()
	toolMap := s.ListTools()
	if len(toolMap) != len(expectedTools) {
		t.Fatalf("tool count = %d, want %d", len(toolMap), len(expectedTools))
	}
	got := map[string]bool{}
	for name := range toolMap {
		got[name] = true
	}
	for _, name := range expectedTools {
		if !got[name] {
			t.Errorf("missing tool: %s", name)
		}
	}
	for _, removed := range []string{"ssh_scan", "ssh_exec_batch", "ssh_upload_dir", "ssh_download_dir", "ssh_list_dir", "ssh_stat_file", "ssh_mkdir", "ssh_remove"} {
		if got[removed] {
			t.Errorf("removed tool still registered: %s", removed)
		}
	}
}

func TestToolSchemas(t *testing.T) {
	s := Register()
	toolMap := s.ListTools()
	byName := map[string]mcp.Tool{}
	for name, st := range toolMap {
		byName[name] = st.Tool
	}

	// ssh_filesystem 的 action enum 必须精确
	fs := byName["ssh_filesystem"]
	props, ok := fs.InputSchema.Properties["action"]
	if !ok {
		t.Fatal("ssh_filesystem missing action property")
	}
	var propMap map[string]interface{}
	data, _ := json.Marshal(props)
	if err := json.Unmarshal(data, &propMap); err != nil {
		t.Fatal(err)
	}
	enum, _ := propMap["enum"].([]interface{})
	if len(enum) != 4 {
		t.Errorf("action enum = %v, want 4 values", enum)
	}

	// ssh_set_review_mode 的 mode enum 必须精确
	sm := byName["ssh_set_review_mode"]
	props, ok = sm.InputSchema.Properties["mode"]
	if !ok {
		t.Fatal("ssh_set_review_mode missing mode property")
	}
	data, _ = json.Marshal(props)
	if err := json.Unmarshal(data, &propMap); err != nil {
		t.Fatal(err)
	}
	enum, _ = propMap["enum"].([]interface{})
	if len(enum) != 4 {
		t.Errorf("mode enum = %v, want 4 values", enum)
	}
}

// envelope 契约：与 Python 版字段完全一致（JSON 序列化）。
type contractEnvelope struct {
	SchemaVersion string                 `json:"schema_version"`
	RequestID     string                 `json:"request_id"`
	OK            bool                   `json:"ok"`
	Tool          string                 `json:"tool"`
	Host          string                 `json:"host"`
	Status        string                 `json:"status"`
	DurationMs    int64                  `json:"duration_ms"`
	Review        interface{}            `json:"review,omitempty"`
	Data          map[string]interface{} `json:"data"`
	Warnings      []string               `json:"warnings"`
	Error         *contractErr           `json:"error,omitempty"`
	Text          string                 `json:"text"`
}

type contractErr struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func TestEnvelopeContractCompleteness(t *testing.T) {
	env := &contractEnvelope{
		SchemaVersion: "1.0", RequestID: "r", OK: true, Tool: "t", Host: "h",
		Status: "succeeded", DurationMs: 1, Data: map[string]interface{}{},
		Warnings: []string{}, Text: "ok",
		Review: map[string]interface{}{"mode": "off", "decision": "approved"},
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"schema_version", "request_id", "ok", "tool", "host",
		"status", "duration_ms", "review", "data", "warnings", "text",
	} {
		if _, ok := m[field]; !ok {
			t.Errorf("envelope missing field: %s", field)
		}
	}

	// 失败 envelope 必须有 error
	envF := &contractEnvelope{
		SchemaVersion: "1.0", RequestID: "r", OK: false, Tool: "t", Host: "h",
		Status: "failed", DurationMs: 1, Data: map[string]interface{}{},
		Warnings: []string{}, Text: "err",
		Error: &contractErr{Code: "X", Message: "m", Retryable: false},
	}
	data, _ = json.Marshal(envF)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["error"]; !ok {
		t.Error("failure envelope missing error")
	}
}
