// Package audit 实现 JSONL 行为审计日志（与 Python 版一致）：
// 只读查询、脱敏、过滤、分页。
package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Record 是一条审计记录。
type Record struct {
	Timestamp  string                 `json:"timestamp"`
	Host       string                 `json:"host,omitempty"`
	Username   string                 `json:"username,omitempty"`
	Tool       string                 `json:"tool"`
	Args       map[string]interface{} `json:"args,omitempty"`
	Status     string                 `json:"status,omitempty"`
	DurationMs int64                  `json:"duration_ms,omitempty"`
}

var exportPattern = regexp.MustCompile(`(export\s+[A-Za-z_][A-Za-z0-9_]*=)[^;]+`)

// DefaultPath 返回默认日志路径（SSH_LOG_FILE 或 ~/.ssh/mcp-ssh.log）。
func DefaultPath() string {
	if v := os.Getenv("SSH_LOG_FILE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "mcp-ssh.log"
	}
	return filepath.Join(home, ".ssh", "mcp-ssh.log")
}

// Append 追加一条审计记录（脱敏 + JSONL）。
func Append(rec Record) error {
	rec.Timestamp = time.Now().UTC().Format(time.RFC3339)
	rec.Args = RedactArgs(rec.Args)
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path := DefaultPath()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// RedactArgs 脱敏 args 中的密码/私钥/环境变量值。
func RedactArgs(args map[string]interface{}) map[string]interface{} {
	if args == nil {
		return nil
	}
	out := map[string]interface{}{}
	for k, v := range args {
		if s, ok := v.(string); ok {
			redacted := exportPattern.ReplaceAllString(s, "${1}***")
			out[k] = redacted
		} else {
			out[k] = v
		}
	}
	return out
}

// QueryOptions 是查询过滤条件。
type QueryOptions struct {
	Host        string
	Tool        string
	SinceMinute int
	Limit       int
}

// Query 读取并过滤审计日志（与 Python 版 ssh_get_audit_logs 语义一致）。
func Query(opts QueryOptions) ([]Record, int, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	var cutoff time.Time
	if opts.SinceMinute > 0 {
		cutoff = time.Now().Add(-time.Duration(opts.SinceMinute) * time.Minute)
	}

	path := DefaultPath()
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, &LocalIOError{msg: "无法读取审计日志：" + err.Error()}
	}
	defer f.Close()

	records := []Record{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var rec Record
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if opts.Host != "" && rec.Host != opts.Host {
			continue
		}
		if opts.Tool != "" && rec.Tool != opts.Tool {
			continue
		}
		if !cutoff.IsZero() {
			ts, err := time.Parse(time.RFC3339, rec.Timestamp)
			if err != nil || ts.Before(cutoff) {
				continue
			}
		}
		records = append(records, rec)
	}
	total := len(records)
	// 最新优先（与 Python 版按 timestamp 倒序一致）
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp > records[j].Timestamp
	})
	if len(records) > limit {
		records = records[:limit]
	}
	return records, total, nil
}

// LocalIOError 表示本地文件 IO 错误（映射 LOCAL_IO_ERROR）。
type LocalIOError struct{ msg string }

func (e *LocalIOError) Error() string { return e.msg }

// RenderText 渲染人类可读查询结果。
func RenderText(records []Record, total int) string {
	if len(records) == 0 {
		return "未找到匹配日志（总数 0 条）。"
	}
	lines := []string{"最近 " + itoa(len(records)) + " 条行为日志（共 " + itoa(total) + " 条）:"}
	for _, r := range records {
		host := r.Host
		if host == "" {
			host = "-"
		}
		lines = append(lines, "["+r.Timestamp+"] "+host+" "+r.Tool+" → "+r.Status)
	}
	return strings.Join(lines, "\n")
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
