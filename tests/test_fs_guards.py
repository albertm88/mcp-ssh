"""Offline regression tests for the four standalone FS tools on `main`.

Covers the fixes backported from the `lite` branch:
1. Empty `remote_path` must fail closed (INVALID_ARGUMENT) instead of
   attempting a connection / executing `ls ''`.
2. `ssh_list_dir` entry parsing: name must be extracted after the
   "HH:MM" time column (historical offset bug) and CRLF stripped.
"""
from __future__ import annotations

import pytest

import server


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
    """隔离测试：任何 ssh_exec 调用都不走真实网络。"""
    monkeypatch.setattr(server, "_connect", lambda host, timeout=10.0: _FakeClient())


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


class _FakeStreams:
    def __init__(self, out: bytes | str) -> None:
        self.channel = _FakeChannel(out)


class _FakeClient:
    def __init__(self, stdout: str = "") -> None:
        self._stdout = stdout
        self.closed = False

    def exec_command(self, command: str, timeout: float, get_pty: bool):
        out = self._stdout
        if command.startswith("ls "):
            out = (
                "drwxr-xr-x 2 mcp-test mcp-test  4096 2026-08-10 12:00 .\r\n"
                "drwxr-xr-x 3 mcp-test mcp-test  4096 2026-08-10 12:00 ..\r\n"
                "-rw-r--r-- 1 mcp-test mcp-test  1024 2026-08-10 12:00 file.txt\r\n"
            )
        return None, _FakeStreams(out), _FakeStreams("")

    def close(self) -> None:
        self.closed = True


class TestEmptyRemotePathFailClosed:
    @pytest.mark.parametrize("tool", ["ssh_list_dir", "ssh_stat_file", "ssh_mkdir", "ssh_remove"])
    def test_empty_path_rejected_before_connect(self, monkeypatch: pytest.MonkeyPatch, tool: str) -> None:
        _off_mode(monkeypatch)
        called: list[str] = []

        def fake_connect(host, timeout=10.0):
            called.append(host)
            return _FakeClient()

        monkeypatch.setattr(server, "_connect", fake_connect)

        fn = getattr(server, tool)
        res = fn("h", remote_path="")

        assert res["status"] == "failed", tool
        assert res["error"]["code"] == "INVALID_ARGUMENT", tool
        assert called == [], f"{tool} 空路径不应触发连接"

    @pytest.mark.parametrize("tool", ["ssh_list_dir", "ssh_stat_file", "ssh_mkdir", "ssh_remove"])
    def test_blank_path_rejected(self, monkeypatch: pytest.MonkeyPatch, tool: str) -> None:
        _off_mode(monkeypatch)
        fn = getattr(server, tool)
        res = fn("h", remote_path="   ")
        assert res["status"] == "failed"
        assert res["error"]["code"] == "INVALID_ARGUMENT"


class TestListDirParsing:
    def test_parses_name_after_time_column(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)
        monkeypatch.setattr(server, "_connect", lambda host, timeout=10.0: _FakeClient())

        res = server.ssh_list_dir("h", "/tmp")

        assert res["status"] == "succeeded", res
        entries = res["data"]["entries"]
        # . / .. 必须被过滤，且 name 不含 \r 和 "12:00 " 前缀
        assert len(entries) == 1, entries
        assert entries[0]["name"] == "file.txt"
        assert entries[0]["type"] == "-"

    def test_hidden_files_filtered_when_not_requested(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _off_mode(monkeypatch)

        class HiddenClient(_FakeClient):
            def exec_command(self, command, timeout, get_pty):
                out = (
                    "-rw-r--r-- 1 mcp-test mcp-test  100 2026-08-10 12:00 .hidden\r\n"
                    "-rw-r--r-- 1 mcp-test mcp-test  200 2026-08-10 12:00 visible.txt\r\n"
                )
                return None, _FakeStreams(out), _FakeStreams("")

        monkeypatch.setattr(server, "_connect", lambda host, timeout=10.0: HiddenClient())

        res = server.ssh_list_dir("h", "/tmp", show_hidden=False)
        names = [e["name"] for e in res["data"]["entries"]]
        assert names == ["visible.txt"]

        res = server.ssh_list_dir("h", "/tmp", show_hidden=True)
        names = [e["name"] for e in res["data"]["entries"]]
        assert names == [".hidden", "visible.txt"]
