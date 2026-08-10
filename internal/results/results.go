// Package results 实现统一结果 envelope 契约（与 Python 版完全兼容）。
//
// envelope 字段：
//
//	schema_version / request_id / ok / tool / host / status / duration_ms
//	review / data / warnings / error / text
package results

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// 稳定状态码（与 Python 版 STABLE_STATUSES 一致）。
const (
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusRejected  = "rejected"
	StatusTimedOut  = "timed_out"
	StatusCancelled = "cancelled"
	StatusPartial   = "partial"
)

// 稳定错误码（与 Python 版 STABLE_ERROR_CODES 一致）。
const (
	ErrorInvalidArgument     = "INVALID_ARGUMENT"
	ErrorResourceLimit       = "RESOURCE_LIMIT"
	ErrorReviewRejected      = "REVIEW_REJECTED"
	ErrorHostKeyMismatch     = "HOST_KEY_MISMATCH"
	ErrorAuthFailed          = "AUTH_FAILED"
	ErrorConnectTimeout      = "CONNECT_TIMEOUT"
	ErrorConnectionLost      = "CONNECTION_LOST"
	ErrorExecTimeout         = "EXEC_TIMEOUT"
	ErrorExecCancelled       = "EXEC_CANCELLED"
	ErrorRemoteExitNonzero   = "REMOTE_EXIT_NONZERO"
	ErrorOutputLimit         = "OUTPUT_LIMIT"
	ErrorLocalIOError        = "LOCAL_IO_ERROR"
	ErrorRemoteIOError       = "REMOTE_IO_ERROR"
	ErrorChecksumMismatch    = "CHECKSUM_MISMATCH"
)

// ErrorInfo 是错误详情。
type ErrorInfo struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// ReviewInfo 是审核决策绑定（与 Python 版 review 字段一致）。
type ReviewInfo struct {
	Mode     string `json:"mode"`
	Decision string `json:"decision"`
	Risk     string `json:"risk"`
	Reason   string `json:"reason"`
	PlanID   string `json:"plan_id"`
}

// Envelope 是统一结果 envelope。
type Envelope struct {
	SchemaVersion string                 `json:"schema_version"`
	RequestID     string                 `json:"request_id"`
	OK            bool                   `json:"ok"`
	Tool          string                 `json:"tool"`
	Host          string                 `json:"host"`
	Status        string                 `json:"status"`
	DurationMs    int64                  `json:"duration_ms"`
	Review        *ReviewInfo            `json:"review,omitempty"`
	Data          map[string]interface{} `json:"data"`
	Warnings      []string               `json:"warnings"`
	Error         *ErrorInfo             `json:"error,omitempty"`
	Text          string                 `json:"text"`
}

// NewRequestID 生成随机请求 ID。
func NewRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(b)
}

// isRetryable 根据错误码判断是否可重试（与 Python 版 is_retryable 一致）。
func isRetryable(code string) bool {
	switch code {
	case ErrorConnectTimeout, ErrorConnectionLost, ErrorExecTimeout:
		return true
	default:
		return false
	}
}

func nowMs() int64 {
	return time.Now().UnixMilli()
}

// MakeSuccess 构造成功 envelope。
func MakeSuccess(tool, host string, data map[string]interface{}, text string, review *ReviewInfo) *Envelope {
	if data == nil {
		data = map[string]interface{}{}
	}
	return &Envelope{
		SchemaVersion: "1.0",
		RequestID:     NewRequestID(),
		OK:            true,
		Tool:          tool,
		Host:          host,
		Status:        StatusSucceeded,
		DurationMs:    nowMs(),
		Review:        review,
		Data:          data,
		Warnings:      []string{},
		Error:         nil,
		Text:          text,
	}
}

// MakeFailure 构造失败 envelope。
func MakeFailure(code, message, tool, host string, status string, data map[string]interface{}, review *ReviewInfo) *Envelope {
	if data == nil {
		data = map[string]interface{}{}
	}
	if status == "" {
		status = StatusFailed
	}
	return &Envelope{
		SchemaVersion: "1.0",
		RequestID:     NewRequestID(),
		OK:            false,
		Tool:          tool,
		Host:          host,
		Status:        status,
		DurationMs:    nowMs(),
		Review:        review,
		Data:          data,
		Warnings:      []string{},
		Error: &ErrorInfo{
			Code:      code,
			Message:   message,
			Retryable: isRetryable(code),
		},
		Text: message,
	}
}

// MakeRejected 构造审核拒绝 envelope。
func MakeRejected(reason, tool, host string) *Envelope {
	return MakeFailure(ErrorReviewRejected, reason, tool, host, StatusRejected, nil, nil)
}
