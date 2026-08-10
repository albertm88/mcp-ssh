"""Regression tests for review fixes: non-zero exit, connect mapping, batch
consistency, traversal guard, download sha256 and output limit.
"""
from __future__ import annotations

import pathlib

import pytest

import server
from server import (
    _connect_failure_envelope,
    _reject_remote_traversal,
)
from host_keys import HostKeyError


class FakeChannel:
    def __init__(self, exit_code: int = 0, out: bytes = b"", err: bytes = b"") -> None:
        self._exit_code = exit_code
        self._out = out
        self._err = err

    def exit_status_ready(self) -> bool:
        return True

    def recv_ready(self) -> bool:
        return False

    def recv(self, size: int) -> bytes:
        return b""

    def recv_exit_status(self) -> int:
        return self._exit_code


class FakeExecStreams:
    def __init__(self, code: int, out: bytes, err: bytes) -> None:
        self.channel = FakeChannel(code, out, err)


class FakeClient:
    def __init__(self) -> None:
        self.closed = False

    def exec_command(self, command: str, timeout: float, get_pty: bool):
        return None, FakeExecStreams(0, b"", b""), FakeExecStreams(0, b"", b"")

    def close(self) -> None:
        self.closed = True


class NonZeroClient(FakeClient):
    def exec_command(self, command: str, timeout: float, get_pty: bool):
        return None, FakeExecStreams(3, b"oops", b"boom"), FakeExecStreams(0, b"", b"")


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


def _off_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_REVIEW_MODE", "off")
    monkeypatch.setattr(server, "_review_engine", FakeEngine())


@pytest.fixture(autouse=True)
def no_real_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    """隔离测试，禁止真实网络连接。"""
    monkeypatch.setattr(server, "_connect", lambda host, timeout=10.0: FakeClient())


class TestNonZeroExit:
    def test_nonzero_exit_returns_failed_envelope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        monkeypatch.setattr(server, "_connect", lambda host, timeout=10.0: NonZeroClient())

        res = server.ssh_exec("h", "false")

        assert res["status"] == "failed"
        assert res["ok"] is False
        assert res["error"]["code"] == "REMOTE_EXIT_NONZERO"
        assert res["data"]["exit_code"] == 3


class TestConnectFailureEnvelope:
    def test_host_key_error_maps_to_mismatch(self) -> None:
        e = HostKeyError("unknown host key")
        env = _connect_failure_envelope(e, "ssh_upload", "h")
        assert env["error"]["code"] == "HOST_KEY_MISMATCH"

    def test_auth_error_maps_to_auth_failed(self) -> None:
        env = _connect_failure_envelope(
            RuntimeError("认证失败：user@h:22 — 密码错误"), "ssh_exec", "h"
        )
        assert env["error"]["code"] == "AUTH_FAILED"

    def test_missing_identity_maps_to_invalid_argument(self) -> None:
        env = _connect_failure_envelope(
            RuntimeError("SSH 身份文件不存在：/nope/key"), "ssh_exec", "h"
        )
        assert env["error"]["code"] == "INVALID_ARGUMENT"

    def test_connect_timeout_maps_to_connect_timeout(self) -> None:
        env = _connect_failure_envelope(
            RuntimeError("主机不可达：h:22 连接超时（10s）"), "ssh_exec", "h"
        )
        assert env["error"]["code"] == "CONNECT_TIMEOUT"

    def test_other_connect_error_maps_to_connection_lost(self) -> None:
        env = _connect_failure_envelope(RuntimeError("无法连接 h"), "ssh_exec", "h")
        assert env["error"]["code"] == "CONNECTION_LOST"

    def test_ssh_exec_missing_identity_maps_invalid_argument(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _off_mode(monkeypatch)

        def boom(host: str, timeout: float = 10.0):
            raise RuntimeError("SSH 身份文件不存在：/nope/key")

        monkeypatch.setattr(server, "_connect", boom)
        res = server.ssh_exec("h", "whoami")
        assert res["error"]["code"] == "INVALID_ARGUMENT"


class TestTraversalGuard:
    @pytest.mark.parametrize("bad", ["/etc/./shadow", "/tmp/x/../../etc/cron.d/evil", "a/../b"])
    def test_rejects_dot_components(self, bad: str) -> None:
        with pytest.raises(ValueError):
            _reject_remote_traversal(bad)

    @pytest.mark.parametrize("good", ["/etc/shadow", "/tmp/x/backup", "/home/user/file.txt"])
    def test_allows_plain_paths(self, good: str) -> None:
        _reject_remote_traversal(good)


class TestDownloadSha256:
    def test_get_atomic_returns_real_digest(self, tmp_path: pathlib.Path) -> None:
        from tests.test_sftp_control import FakeSFTP

        sftp = FakeSFTP()
        content = b"data" * 100
        sftp.files["/src/data.bin"] = (False, len(content), content)
        target = tmp_path / "data.bin"

        info = server._sftp_get_atomic(sftp, "/src/data.bin", target)

        assert info["sha256"] == server._sha256_local(target)
        assert info["sha256"] != ""


class TestBatchEnvelope:
    def test_batch_all_success_is_succeeded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        res = server.ssh_exec_batch("h", ["pwd", "ls"])

        assert res["status"] == "succeeded"
        assert res["ok"] is True
        assert res["error"] is None

    def test_batch_failure_ok_is_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        monkeypatch.setattr(server, "_connect", lambda host, timeout=10.0: NonZeroClient())

        res = server.ssh_exec_batch("h", ["false"], stop_on_error=True)

        assert res["status"] == "failed"
        assert res["ok"] is False
        assert res["error"]["code"] == "REMOTE_EXIT_NONZERO"
        assert res["data"]["items"][0]["ok"] is False

    def test_batch_embeds_review_binding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        res = server.ssh_exec_batch("h", ["pwd"])
        assert res["review"].get("plan_id") == "fake-plan-id"


class TestMkdirReviewBinding:
    def test_mkdir_embeds_review_binding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        res = server.ssh_filesystem("h", action="mkdir", remote_path="/tmp/review-test-dir")
        assert res["review"].get("plan_id") == "fake-plan-id"


class BigChannel:
    """产生大量输出的 fake channel，用于验证输出配额截断。"""

    def __init__(self, total: int) -> None:
        self._sent = 0
        self._total = total

    def exit_status_ready(self) -> bool:
        return self._sent >= self._total

    def recv_ready(self) -> bool:
        return self._sent < self._total

    def recv(self, size: int) -> bytes:
        remaining = self._total - self._sent
        n = min(size, remaining)
        self._sent += n
        return b"x" * n


class TestOutputLimit:
    def test_read_channel_truncates_over_quota(self) -> None:
        import time

        big = server._MAX_OUTPUT_BYTES + 4096
        res = server._read_channel(BigChannel(big), deadline=time.monotonic() + 60)

        assert res["truncated"] is True
        assert len(res["text"].encode("utf-8")) <= server._MAX_OUTPUT_BYTES

    def test_read_channel_under_quota_not_truncated(self) -> None:
        import time

        res = server._read_channel(BigChannel(1024), deadline=time.monotonic() + 60)
        assert res["truncated"] is False
        assert res["text"] == "x" * 1024
