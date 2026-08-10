"""Offline unit tests for the merged `ssh_filesystem` tool.

Covers all four actions (list / stat / mkdir / remove), security guards
(sensitive path, traversal), review binding and envelope shape, without
any real network connection (fake SFTP/exec clients).
"""
from __future__ import annotations

import pathlib

import pytest

import server
from server import _fs_list, _fs_mkdir, _fs_remove, _fs_stat, ssh_filesystem


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
    monkeypatch.setattr(server, "_connect", lambda host, timeout=10.0: _FakeClient())


class _FakeClient:
    """Fake SSH client: exec_command returns canned stdout for ls/stat."""

    def __init__(self, stdout: str = "") -> None:
        self._stdout = stdout
        self.closed = False

    def exec_command(self, command: str, timeout: float, get_pty: bool):
        if command.startswith("ls "):
            out = (
                "drwxr-xr-x 2 mcp-test mcp-test  4096 2026-08-10 12:00 .\n"
                "drwxr-xr-x 3 mcp-test mcp-test  4096 2026-08-10 12:00 ..\n"
                "-rw-r--r-- 1 mcp-test mcp-test  1024 2026-08-10 12:00 file.txt\n"
            )
        else:
            out = "  File: /tmp/x\n  Size: 1024      \tBlocks: 8          IO Block: 4096   regular file\n"
        return None, _FakeStreams(out), _FakeStreams("")

    def close(self) -> None:
        self.closed = True


class _FakeStreams:
    def __init__(self, out: bytes | str) -> None:
        self.channel = _FakeChannel(out)


class _FakeChannel:
    def __init__(self, out: bytes | str) -> None:
        self._out = out.encode() if isinstance(out, str) else out
        self._pos = 0

    def settimeout(self, t: float) -> None:
        pass

    def exit_status_ready(self) -> bool:
        return True

    def recv_ready(self) -> bool:
        return self._pos < len(self._out)

    def recv(self, size: int) -> bytes:
        chunk = self._out[self._pos:self._pos + size]
        self._pos += len(chunk)
        return chunk

    def recv_exit_status(self) -> int:
        return 0


class TestFilesystemDispatch:
    def test_invalid_action_returns_invalid_argument(self) -> None:
        res = ssh_filesystem("h", action="nope", remote_path="/tmp")
        assert res["status"] == "failed"
        assert res["error"]["code"] == "INVALID_ARGUMENT"

    def test_missing_remote_path_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        res = ssh_filesystem("h", action="list", remote_path="")
        assert res["status"] == "failed"

    def test_all_actions_return_success_envelope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        for action in ("list", "stat", "mkdir", "remove"):
            res = ssh_filesystem(
                "h", action=action, remote_path="/tmp/x",
                recursive=(action == "remove"),
                parents=(action == "mkdir"),
            )
            assert res["status"] == "succeeded", (action, res)
            assert res["ok"] is True
            assert res["tool"] == "ssh_filesystem"
            assert res["data"]["action"] == action


class TestFilesystemGuards:
    def test_sensitive_path_blocked_for_all_actions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        for action in ("list", "mkdir", "remove"):
            res = ssh_filesystem("h", action=action, remote_path="/etc/passwd")
            assert res["status"] == "failed", action
            assert res["error"]["code"] == "INVALID_ARGUMENT", action

    def test_traversal_blocked_for_all_actions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        for action in ("list", "mkdir", "remove"):
            res = ssh_filesystem("h", action=action, remote_path="/tmp/../etc")
            assert res["status"] == "failed", action
            assert res["error"]["code"] == "INVALID_ARGUMENT", action


class TestFilesystemList:
    def test_list_parses_entries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        res = _fs_list("h", "/tmp", False, 10)
        assert res["status"] == "succeeded"
        entries = res["data"]["entries"]
        assert len(entries) == 1  # hidden . and .. entries are filtered
        assert entries[0]["name"] == "file.txt"
        assert entries[0]["type"] == "-"
        assert entries[0]["size"] == "1.0KB"

    def test_list_strips_crlf_from_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)

        def fake_exec(host, command, timeout=10, allow_dangerous=False):
            return {
                "status": "succeeded", "ok": True, "error": None,
                "data": {
                    "exit_code": 0,
                    "stdout": (
                        "drwxr-xr-x 2 mcp-test mcp-test  4096 2026-08-10 12:00 .\r\n"
                        "-rw-r--r-- 1 mcp-test mcp-test  1024 2026-08-10 12:00 data.bin\r\n"
                    ),
                },
            }

        monkeypatch.setattr(server, "ssh_exec", fake_exec)
        res = _fs_list("h", "/tmp", False, 10)
        assert res["status"] == "succeeded"
        names = [e["name"] for e in res["data"]["entries"]]
        assert names == ["data.bin"]

    def test_list_hidden_respects_show_hidden(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        res = _fs_list("h", "/tmp", True, 10)
        assert res["status"] == "succeeded"
        names = [e["name"] for e in res["data"]["entries"]]
        assert names == ["file.txt"]  # fake output has no dotfiles besides . / ..


class TestFilesystemStat:
    def test_stat_passes_through_stdout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        res = _fs_stat("h", "/tmp/x", 10)
        assert res["status"] == "succeeded"
        assert "Size: 1024" in res["data"]["stat"]
        assert res["data"]["path"] == "/tmp/x"


class TestFilesystemMkdir:
    def test_mkdir_builds_mkdir_p_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        captured: list[str] = []

        def fake_exec(host, command, timeout=10, allow_dangerous=False):
            captured.append(command)
            return {
                "status": "succeeded", "ok": True,
                "data": {"exit_code": 0, "stdout": ""},
                "error": None,
            }

        monkeypatch.setattr(server, "ssh_exec", fake_exec)
        res = _fs_mkdir("h", "/tmp/new/dir", True, 10)
        assert res["status"] == "succeeded"
        assert captured and captured[0].startswith("mkdir -p")

    def test_mkdir_embeds_review_binding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        res = ssh_filesystem("h", action="mkdir", remote_path="/tmp/new")
        assert res["review"].get("plan_id") == "fake-plan-id"


class TestFilesystemRemove:
    def test_remove_builds_rm_rf_when_recursive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        captured: list[str] = []

        def fake_exec(host, command, timeout=10, allow_dangerous=False):
            captured.append(command)
            return {
                "status": "succeeded", "ok": True,
                "data": {"exit_code": 0, "stdout": ""},
                "error": None,
            }

        monkeypatch.setattr(server, "ssh_exec", fake_exec)
        res = _fs_remove("h", "/tmp/dir", True, 10)
        assert res["status"] == "succeeded"
        assert captured and captured[0].startswith("rm -rf")

    def test_remove_single_file_uses_rm_f(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        captured: list[str] = []

        def fake_exec(host, command, timeout=10, allow_dangerous=False):
            captured.append(command)
            return {
                "status": "succeeded", "ok": True,
                "data": {"exit_code": 0, "stdout": ""},
                "error": None,
            }

        monkeypatch.setattr(server, "ssh_exec", fake_exec)
        res = _fs_remove("h", "/tmp/file.txt", False, 10)
        assert res["status"] == "succeeded"
        assert captured and captured[0].startswith("rm -f")

    def test_remove_embeds_review_binding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        res = ssh_filesystem("h", action="remove", remote_path="/tmp/x")
        assert res["review"].get("plan_id") == "fake-plan-id"
