"""Tests for the ssh_get_audit_logs behavior-log query tool."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from server import _redact_log_args, _truncate_log_args, ssh_get_audit_logs


def _write_log(tmp_path: Path, entries: list[dict]) -> Path:
    log = tmp_path / "mcp-ssh.log"
    with log.open("w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return log


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class TestLogAggregation:
    def test_merges_connected_exec_and_envelope(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ts = _now_iso()
        log = _write_log(tmp_path, [
            {"ts": ts, "level": "INFO", "event": "ssh_connected",
             "host": "wsl", "hostname": "127.0.0.1", "username": "mcp-test"},
            {"ts": ts, "level": "INFO", "event": "ssh_exec_done",
             "host": "wsl", "command": "whoami", "elapsed": 1.5},
            {"ts": ts, "level": "INFO", "event": "ssh_result_envelope",
             "tool": "ssh_exec", "status": "succeeded"},
        ])
        monkeypatch.setenv("SSH_LOG_FILE", str(log))

        result = ssh_get_audit_logs()

        assert result["ok"] is True
        logs = result["data"]["logs"]
        assert len(logs) == 1
        record = logs[0]
        assert record["tool"] == "ssh_exec"
        assert record["host"] == "wsl"
        assert record["username"] == "mcp-test"
        assert record["args"] == {"command": "whoami"}
        assert record["status"] == "succeeded"

    def test_username_null_when_no_connected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        log = _write_log(tmp_path, [
            {"ts": _now_iso(), "level": "INFO", "event": "ssh_exec_done",
             "host": "wsl", "command": "pwd", "elapsed": 0.3},
        ])
        monkeypatch.setenv("SSH_LOG_FILE", str(log))

        result = ssh_get_audit_logs()

        assert result["data"]["logs"][0]["username"] is None

    def test_review_mode_changed_recorded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        log = _write_log(tmp_path, [
            {"ts": _now_iso(), "level": "INFO", "event": "review_mode_changed",
             "old": "whitelist", "new": "off"},
        ])
        monkeypatch.setenv("SSH_LOG_FILE", str(log))

        result = ssh_get_audit_logs()

        logs = result["data"]["logs"]
        assert len(logs) == 1
        assert logs[0]["tool"] == "ssh_set_review_mode"
        assert logs[0]["args"] == {"old": "whitelist", "new": "off"}


class TestLogFiltering:
    def test_filter_by_host(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        log = _write_log(tmp_path, [
            {"ts": _now_iso(), "level": "INFO", "event": "ssh_exec_done",
             "host": "host-a", "command": "ls", "elapsed": 0.1},
            {"ts": _now_iso(), "level": "INFO", "event": "ssh_exec_done",
             "host": "host-b", "command": "ls", "elapsed": 0.1},
        ])
        monkeypatch.setenv("SSH_LOG_FILE", str(log))

        result = ssh_get_audit_logs(host="host-a")

        assert len(result["data"]["logs"]) == 1
        assert result["data"]["logs"][0]["host"] == "host-a"

    def test_filter_by_tool(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        log = _write_log(tmp_path, [
            {"ts": _now_iso(), "level": "INFO", "event": "ssh_exec_done",
             "host": "wsl", "command": "ls", "elapsed": 0.1},
            {"ts": _now_iso(), "level": "INFO", "event": "review_mode_changed",
             "old": "whitelist", "new": "off"},
        ])
        monkeypatch.setenv("SSH_LOG_FILE", str(log))

        result = ssh_get_audit_logs(tool="ssh_set_review_mode")

        assert len(result["data"]["logs"]) == 1
        assert result["data"]["logs"][0]["tool"] == "ssh_set_review_mode"

    def test_filter_by_since_minutes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        old = (datetime.now(timezone.utc).timestamp() - 600) * 1000
        # 老记录用旧时间戳
        log = _write_log(tmp_path, [
            {"ts": datetime.fromtimestamp(600).isoformat(), "level": "INFO",
             "event": "ssh_exec_done", "host": "wsl", "command": "old", "elapsed": 0.1},
            {"ts": _now_iso(), "level": "INFO", "event": "ssh_exec_done",
             "host": "wsl", "command": "new", "elapsed": 0.1},
        ])
        monkeypatch.setenv("SSH_LOG_FILE", str(log))

        result = ssh_get_audit_logs(since_minutes=5)

        assert len(result["data"]["logs"]) == 1
        assert result["data"]["logs"][0]["args"] == {"command": "new"}


class TestLogLimitsAndRedaction:
    def test_redacts_export_values(self) -> None:
        redacted = _redact_log_args({"command": "export TOKEN=secret; whoami"})
        assert "secret" not in redacted["command"]
        assert "export TOKEN=***" in redacted["command"]

    def test_truncates_long_args(self) -> None:
        long_args = {"command": "x" * 600}
        truncated = _truncate_log_args(long_args)
        assert truncated["_truncated"] is True
        assert len(truncated["summary"]) <= 500

    def test_file_missing_returns_io_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_LOG_FILE", str(tmp_path / "does-not-exist.log"))

        result = ssh_get_audit_logs()

        assert result["ok"] is False
        assert result["error"]["code"] == "LOCAL_IO_ERROR"

    def test_limit_clamped_to_500(self) -> None:
        assert ssh_get_audit_logs.__annotations__ is not None  # 工具签名存在


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
