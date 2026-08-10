package results

import "testing"

func TestMakeSuccessEnvelope(t *testing.T) {
	env := MakeSuccess("ssh_exec", "myhost", map[string]interface{}{"exit_code": 0}, "ok", nil)
	if env.SchemaVersion != "1.0" {
		t.Errorf("schema_version = %s, want 1.0", env.SchemaVersion)
	}
	if !env.OK || env.Status != StatusSucceeded {
		t.Errorf("ok/status = %v/%s, want true/succeeded", env.OK, env.Status)
	}
	if env.RequestID == "" {
		t.Error("request_id should not be empty")
	}
	if env.Tool != "ssh_exec" || env.Host != "myhost" {
		t.Errorf("tool/host = %s/%s", env.Tool, env.Host)
	}
	if env.Error != nil {
		t.Error("error should be nil on success")
	}
}

func TestMakeFailureEnvelope(t *testing.T) {
	env := MakeFailure(ErrorChecksumMismatch, "bytes differ", "ssh_upload", "h", "", nil, nil)
	if env.OK {
		t.Error("ok should be false")
	}
	if env.Status != StatusFailed {
		t.Errorf("status = %s, want failed", env.Status)
	}
	if env.Error == nil || env.Error.Code != ErrorChecksumMismatch {
		t.Errorf("error = %+v", env.Error)
	}
	if env.Error.Retryable {
		t.Error("CHECKSUM_MISMATCH should not be retryable")
	}
}

func TestRetryableCodes(t *testing.T) {
	if !isRetryable(ErrorConnectTimeout) {
		t.Error("CONNECT_TIMEOUT should be retryable")
	}
	if !isRetryable(ErrorConnectionLost) {
		t.Error("CONNECTION_LOST should be retryable")
	}
	if isRetryable(ErrorHostKeyMismatch) {
		t.Error("HOST_KEY_MISMATCH should not be retryable")
	}
	if isRetryable(ErrorReviewRejected) {
		t.Error("REVIEW_REJECTED should not be retryable")
	}
}

func TestMakeRejected(t *testing.T) {
	env := MakeRejected("whitelist denied", "ssh_exec", "h")
	if env.Status != StatusRejected {
		t.Errorf("status = %s, want rejected", env.Status)
	}
	if env.Error == nil || env.Error.Code != ErrorReviewRejected {
		t.Errorf("error = %+v", env.Error)
	}
}

func TestAllStableCodes(t *testing.T) {
	codes := []string{
		ErrorInvalidArgument, ErrorResourceLimit, ErrorReviewRejected,
		ErrorHostKeyMismatch, ErrorAuthFailed, ErrorConnectTimeout,
		ErrorConnectionLost, ErrorExecTimeout, ErrorExecCancelled,
		ErrorRemoteExitNonzero, ErrorOutputLimit, ErrorLocalIOError,
		ErrorRemoteIOError, ErrorChecksumMismatch,
	}
	for _, c := range codes {
		if c == "" {
			t.Error("empty error code in stable set")
		}
	}
	statuses := []string{
		StatusSucceeded, StatusFailed, StatusRejected,
		StatusTimedOut, StatusCancelled, StatusPartial,
	}
	for _, s := range statuses {
		if s == "" {
			t.Error("empty status in stable set")
		}
	}
}
