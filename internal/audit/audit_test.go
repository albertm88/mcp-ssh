package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRedactArgs(t *testing.T) {
	args := map[string]interface{}{
		"command": "export PASSWORD=secret123; ls",
		"normal":  "hello",
	}
	redacted := RedactArgs(args)
	if redacted["command"] != "export PASSWORD=***; ls" {
		t.Errorf("redaction failed: %v", redacted["command"])
	}
	if redacted["normal"] != "hello" {
		t.Error("non-sensitive value should pass through")
	}
}

func TestAppendAndQuery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv("SSH_LOG_FILE", path)

	if err := Append(Record{Host: "h1", Tool: "ssh_exec", Status: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	if err := Append(Record{Host: "h2", Tool: "ssh_upload", Status: "failed"}); err != nil {
		t.Fatal(err)
	}

	// 过滤 host
	recs, total, err := Query(QueryOptions{Host: "h1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(recs) != 1 || recs[0].Tool != "ssh_exec" {
		t.Errorf("host filter: recs=%+v total=%d", recs, total)
	}

	// 过滤 tool
	recs, total, _ = Query(QueryOptions{Tool: "ssh_upload", Limit: 10})
	if total != 1 || recs[0].Host != "h2" {
		t.Errorf("tool filter: recs=%+v", recs)
	}

	// 全部
	recs, total, _ = Query(QueryOptions{Limit: 10})
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
}

func TestQueryLimit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SSH_LOG_FILE", filepath.Join(dir, "a.jsonl"))
	for i := 0; i < 5; i++ {
		Append(Record{Host: "h", Tool: "ssh_exec"})
	}
	recs, total, _ := Query(QueryOptions{Limit: 2})
	if len(recs) != 2 || total != 5 {
		t.Errorf("limit: len=%d total=%d", len(recs), total)
	}
}

func TestQueryMissingFile(t *testing.T) {
	t.Setenv("SSH_LOG_FILE", filepath.Join(t.TempDir(), "missing.jsonl"))
	_, _, err := Query(QueryOptions{})
	if err == nil {
		t.Error("missing file should error")
	}
}

func TestRenderText(t *testing.T) {
	text := RenderText([]Record{{Timestamp: "2026-01-01", Host: "h", Tool: "ssh_exec", Status: "succeeded"}}, 1)
	if text == "" {
		t.Error("render should produce text")
	}
	empty := RenderText(nil, 0)
	if empty == "" {
		t.Error("empty render should still produce text")
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("SSH_LOG_FILE", "/custom/log.jsonl")
	if DefaultPath() != "/custom/log.jsonl" {
		t.Error("SSH_LOG_FILE should take priority")
	}
	t.Setenv("SSH_LOG_FILE", "")
	p := DefaultPath()
	if p == "" {
		t.Error("default path should not be empty")
	}
	_ = os.Getenv("HOME")
}
