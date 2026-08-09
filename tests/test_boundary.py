"""行为边界钩子（_tool_boundary）专项回归测试。

验证：任何工具内部抛出的未捕获异常都会被钩子映射为稳定错误 envelope，
不会以裸异常逃逸出 MCP 边界。
"""
from __future__ import annotations

import socket

import pytest

import server


class _UncaughtError(Exception):
    pass


class _BrokenTool:
    """模拟一个工具，其内部抛出的异常类型各异。"""

    @staticmethod
    def raises_host_key():
        from host_keys import HostKeyError

        raise HostKeyError("unknown host key")

    @staticmethod
    def raises_runtime():
        raise RuntimeError("认证失败：user@h:22 — 密码错误")

    @staticmethod
    def raises_resource():
        raise server.ResourceLimitError("文件数超过限制 2000")

    @staticmethod
    def raises_checksum():
        raise server.ChecksumMismatchError("SHA-256 校验不一致")

    @staticmethod
    def raises_timeout():
        raise TimeoutError("远程命令超时")

    @staticmethod
    def raises_io():
        raise OSError("connection reset by peer")

    @staticmethod
    def raises_unknown():
        raise _UncaughtError("boom")


class _PatchedModule:
    """把 _BrokenTool 的异常注入一个带钩子的工具函数。"""

    @staticmethod
    def ssh_exec(host: str, command: str, timeout: float = 30):
        raise _UncaughtError("should not escape")


def test_boundary_catches_unknown_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """钩子必须捕获任意未处理异常并返回 envelope。"""
    from server import _tool_boundary

    @_tool_boundary("ssh_exec")
    def tool():
        raise _UncaughtError("boom")

    res = tool()
    assert res["ok"] is False
    assert res["status"] == "failed"
    assert res["error"]["code"] == "REMOTE_IO_ERROR"
    assert isinstance(res["error"]["retryable"], bool)


class TestBoundaryMapping:
    def test_host_key_maps_to_mismatch(self) -> None:
        from server import _tool_boundary

        @_tool_boundary("ssh_exec")
        def tool():
            _BrokenTool.raises_host_key()

        res = tool()
        assert res["error"]["code"] == "HOST_KEY_MISMATCH"

    def test_auth_maps_to_auth_failed(self) -> None:
        from server import _tool_boundary

        @_tool_boundary("ssh_exec")
        def tool():
            _BrokenTool.raises_runtime()

        res = tool()
        assert res["error"]["code"] == "AUTH_FAILED"

    def test_resource_maps_to_resource_limit(self) -> None:
        from server import _tool_boundary

        @_tool_boundary("ssh_upload_dir")
        def tool():
            _BrokenTool.raises_resource()

        res = tool()
        assert res["error"]["code"] == "RESOURCE_LIMIT"

    def test_checksum_maps_to_checksum_mismatch(self) -> None:
        from server import _tool_boundary

        @_tool_boundary("ssh_upload")
        def tool():
            _BrokenTool.raises_checksum()

        res = tool()
        assert res["error"]["code"] == "CHECKSUM_MISMATCH"

    def test_timeout_maps_to_exec_timeout_timed_out(self) -> None:
        from server import _tool_boundary

        @_tool_boundary("ssh_exec")
        def tool():
            _BrokenTool.raises_timeout()

        res = tool()
        assert res["error"]["code"] == "EXEC_TIMEOUT"
        assert res["status"] == "timed_out"

    def test_io_maps_to_connection_lost(self) -> None:
        from server import _tool_boundary

        @_tool_boundary("ssh_exec")
        def tool():
            _BrokenTool.raises_io()

        res = tool()
        assert res["error"]["code"] == "CONNECTION_LOST"


class TestTransmissionInterrupt:
    """传输中断（socket EOF）运行时语义：OSError → CONNECTION_LOST。"""

    def test_connection_lost_is_retryable(self) -> None:
        from server import _tool_boundary

        @_tool_boundary("ssh_exec")
        def tool():
            raise ConnectionResetError("connection reset by peer")

        res = tool()
        assert res["error"]["code"] == "CONNECTION_LOST"
        assert res["error"]["retryable"] is True

    def test_socket_timeout_maps_exec_timeout(self) -> None:
        import socket as _socket

        from server import _tool_boundary

        @_tool_boundary("ssh_download")
        def tool():
            raise _socket.timeout("timed out during transfer")

        res = tool()
        # Python 3.10+ socket.timeout 是 TimeoutError 别名，先被 TimeoutError 分支捕获
        assert res["error"]["code"] == "EXEC_TIMEOUT"
        assert res["status"] == "timed_out"


class TestBoundaryPreservesSignature:
    def test_wraps_keeps_params(self) -> None:
        import inspect

        from server import _tool_boundary

        @_tool_boundary("ssh_exec")
        def ssh_exec(host: str, command: str, timeout: float = 30) -> dict:
            return {"ok": True}

        sig = inspect.signature(ssh_exec)
        assert list(sig.parameters) == ["host", "command", "timeout"]
        ann = sig.return_annotation
        assert ann is dict or ann == dict or ann == "dict"

    def test_boundary_passes_through_success(self) -> None:
        from server import _tool_boundary

        @_tool_boundary("ssh_exec")
        def tool():
            return {"ok": True, "status": "succeeded"}

        assert tool() == {"ok": True, "status": "succeeded"}
