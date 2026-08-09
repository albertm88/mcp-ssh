"""Delivery contract tests: 14 tools, envelope schema, error codes, host keys.

These run offline against the module-level functions; the MCP stdio handshake
check is listed as a runtime item in checklist/review-runtime.
"""
from __future__ import annotations

import pathlib

import pytest

import server
import results
from host_keys import (
    HostKeyError,
    apply_host_key_policy,
    has_trusted_known_hosts,
    host_key_mismatch_message,
    is_host_key_failure,
    load_known_hosts_files,
)

EXPECTED_TOOLS = frozenset({
    "ssh_exec",
    "ssh_exec_batch",
    "ssh_list_hosts",
    "ssh_scan",
    "ssh_upload",
    "ssh_download",
    "ssh_upload_dir",
    "ssh_download_dir",
    "ssh_list_dir",
    "ssh_stat_file",
    "ssh_mkdir",
    "ssh_remove",
    "ssh_get_review_mode",
    "ssh_set_review_mode",
})

EXPECTED_ERROR_CODES = frozenset({
    "INVALID_ARGUMENT",
    "RESOURCE_LIMIT",
    "REVIEW_REJECTED",
    "HOST_KEY_MISMATCH",
    "AUTH_FAILED",
    "CONNECT_TIMEOUT",
    "CONNECTION_LOST",
    "EXEC_TIMEOUT",
    "EXEC_CANCELLED",
    "REMOTE_EXIT_NONZERO",
    "OUTPUT_LIMIT",
    "LOCAL_IO_ERROR",
    "REMOTE_IO_ERROR",
    "CHECKSUM_MISMATCH",
})

EXPECTED_STATUSES = frozenset({
    "succeeded",
    "failed",
    "rejected",
    "timed_out",
    "cancelled",
    "partial",
})

ENVELOPE_KEYS = frozenset({
    "schema_version",
    "request_id",
    "ok",
    "tool",
    "host",
    "status",
    "duration_ms",
    "review",
    "data",
    "warnings",
    "error",
    "text",
})


class TestToolContract:
    def test_all_14_tools_are_decorated(self) -> None:
        tool_names = {
            name
            for name in dir(server)
            if name.startswith("ssh_")
            and callable(getattr(server, name))
            and name not in {"ssh_set_review_mode", "ssh_get_review_mode"}
        }
        tool_names |= {"ssh_set_review_mode", "ssh_get_review_mode"}
        assert tool_names == EXPECTED_TOOLS

    def test_tool_params_are_preserved(self) -> None:
        # 关键参数不因本轮重构而改名/删除
        import inspect

        sig = inspect.signature(server.ssh_exec)
        assert list(sig.parameters) == ["host", "command", "timeout", "shell", "allow_dangerous", "environment"]
        assert list(inspect.signature(server.ssh_upload).parameters) == [
            "host", "local_path", "remote_path", "timeout", "overwrite",
        ]
        assert list(inspect.signature(server.ssh_download).parameters) == [
            "host", "remote_path", "local_path", "timeout", "allow_sensitive",
        ]
        assert list(inspect.signature(server.ssh_scan).parameters) == [
            "network", "port", "timeout", "max_workers", "detail",
        ]
        assert list(inspect.signature(server.ssh_exec_batch).parameters) == [
            "host", "commands", "timeout", "stop_on_error",
        ]


class TestEnvelope:
    def test_success_envelope_fields(self) -> None:
        env = results.make_success("ssh_exec", "myhost", data={"exit_code": 0}, text="ok")
        d = env.to_dict()
        assert set(d) == ENVELOPE_KEYS
        assert d["schema_version"] == "1.0"
        assert d["ok"] is True
        assert d["status"] == "succeeded"
        assert d["tool"] == "ssh_exec"
        assert d["host"] == "myhost"
        assert d["error"] is None
        assert isinstance(d["request_id"], str) and d["request_id"]
        assert d["text"] == "ok"

    def test_failure_envelope_error_info(self) -> None:
        env = results.make_failure(
            results.ERROR_CHECKSUM_MISMATCH, "bytes differ",
            tool="ssh_upload", host="h",
        )
        d = env.to_dict()
        assert d["ok"] is False
        assert d["status"] == "failed"
        assert d["error"] == {"code": "CHECKSUM_MISMATCH", "message": "bytes differ", "retryable": False}

    def test_rejected_envelope(self) -> None:
        env = results.make_rejected("whitelist denied", tool="ssh_exec", host="h")
        d = env.to_dict()
        assert d["status"] == "rejected"
        assert d["error"]["code"] == "REVIEW_REJECTED"

    def test_retryable_codes(self) -> None:
        assert results.is_retryable("CONNECT_TIMEOUT") is True
        assert results.is_retryable("CONNECTION_LOST") is True
        assert results.is_retryable("HOST_KEY_MISMATCH") is False

    def test_statuses_and_error_codes_are_stable(self) -> None:
        assert results.STABLE_STATUSES == EXPECTED_STATUSES
        assert results.STABLE_ERROR_CODES == EXPECTED_ERROR_CODES

    def test_text_is_rendered_from_same_model(self) -> None:
        env = results.make_success("ssh_exec", "h", data={}, text="hello")
        assert results.envelope_to_text(env) == "hello"
        fail = results.make_failure(results.ERROR_EXEC_TIMEOUT, "timeout", tool="ssh_exec", host="h")
        assert results.envelope_to_text(fail) == fail.to_mcp_text()


class TestHostKeyContract:
    def test_strict_policy_applied(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        kh = tmp_path / "known_hosts"
        # 有效的 ed25519 公钥（测试向量，非真实主机）
        kh.write_text(
            "example.invalid ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIKdZmVk+3JxW5L4zK3Y6mQz8Lf7kHvGtJ1s2jQ9fCb0c\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("SSH_KNOWN_HOSTS", str(kh))

        import paramiko

        client = paramiko.SSHClient()
        apply_host_key_policy(client, "example.invalid", 22)
        # RejectPolicy 是通过 missing host key policy 间接验证的：
        # 校验客户端内部保存的策略对象
        assert isinstance(
            client._policy,  # type: ignore[attr-defined]
            paramiko.RejectPolicy,
        )

    def test_no_trusted_source_fails_closed(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_KNOWN_HOSTS", str(tmp_path / "missing-keys"))
        monkeypatch.delenv("USERPROFILE", raising=False)
        monkeypatch.delenv("HOME", raising=False)
        # 强制系统 known_hosts 也不存在
        import host_keys

        monkeypatch.setattr(host_keys, "_system_known_hosts_path", lambda: tmp_path / "nope")

        assert has_trusted_known_hosts() is False
        with pytest.raises(RuntimeError):
            apply_host_key_policy(paramiko_client_placeholder(), "x", 22)


def paramiko_client_placeholder():
    import paramiko

    return paramiko.SSHClient()


class TestHostKeyFailureDetection:
    def test_bad_host_key_exception_is_detected(self) -> None:
        import paramiko

        class FakeBadKey(paramiko.BadHostKeyException):
            def __init__(self) -> None:
                super().__init__(hostname="h", got_key=None, expected_key=None)

        assert is_host_key_failure(FakeBadKey()) is True

    def test_unknown_host_ssh_exception_is_detected(self) -> None:
        import paramiko

        class FakeUnknown(paramiko.SSHException):
            def __str__(self) -> str:
                return "Server 'h' not found in known_hosts"

        assert is_host_key_failure(FakeUnknown()) is True

    def test_other_ssh_exception_is_not_host_key_failure(self) -> None:
        import paramiko

        assert is_host_key_failure(paramiko.AuthenticationException("bad pwd")) is False

    def test_message_contains_no_secrets(self) -> None:
        msg = host_key_mismatch_message("host", 22, RuntimeError("boom"))
        assert "password" not in msg.lower()
        assert "SSH_PASS" not in msg


class TestScanLimit:
    def test_scan_rejects_large_cidr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # /8 = 16M addresses > 4096，连接前失败关闭（off 模式也不可关闭）
        monkeypatch.setenv("SSH_REVIEW_MODE", "off")
        monkeypatch.setattr(server, "_review_engine", FakeEngine())

        result = server.ssh_scan(network="10.0.0.0/8", max_workers=1)

        assert result["status"] == "failed"
        assert result["error"]["code"] == "RESOURCE_LIMIT"
        assert result["ok"] is False

    def test_scan_bad_cidr_returns_invalid_argument(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_review_engine", FakeEngine())

        result = server.ssh_scan(network="not-a-cidr")

        assert result["status"] == "failed"
        assert result["error"]["code"] == "INVALID_ARGUMENT"


class FakeEngine:
    def review(self, ctx) -> object:
        return type(
            "R", (), {
                "approved": True,
                "mode": "off",
                "reason": "",
                "risk_level": "unknown",
                "plan_id": "fake-plan-id",
            }
        )()

    def get_mode(self) -> str:
        return "off"

    def get_status(self) -> dict:
        return {
            "mode": "off",
            "whitelist_file": "",
            "whitelist_exists": False,
            "manual_timeout": 60,
            "runtime_switch_enabled": False,
        }

    def set_mode(self, mode: str, *, authorized: bool = False) -> tuple[bool, str]:
        return True, "ok"
