"""Unified 1.0 result envelope and stable error codes for all MCP tools.

Every tool returns a ResultEnvelope. The human-readable `text` field is
rendered from the same model so automation never parses prose to infer status.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Stable statuses
# ---------------------------------------------------------------------------

STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_REJECTED = "rejected"
STATUS_TIMED_OUT = "timed_out"
STATUS_CANCELLED = "cancelled"
STATUS_PARTIAL = "partial"

STABLE_STATUSES: frozenset[str] = frozenset({
    STATUS_SUCCEEDED,
    STATUS_FAILED,
    STATUS_REJECTED,
    STATUS_TIMED_OUT,
    STATUS_CANCELLED,
    STATUS_PARTIAL,
})

# ---------------------------------------------------------------------------
# Stable error codes
# ---------------------------------------------------------------------------

ERROR_INVALID_ARGUMENT = "INVALID_ARGUMENT"
ERROR_RESOURCE_LIMIT = "RESOURCE_LIMIT"
ERROR_REVIEW_REJECTED = "REVIEW_REJECTED"
ERROR_HOST_KEY_MISMATCH = "HOST_KEY_MISMATCH"
ERROR_AUTH_FAILED = "AUTH_FAILED"
ERROR_CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
ERROR_CONNECTION_LOST = "CONNECTION_LOST"
ERROR_EXEC_TIMEOUT = "EXEC_TIMEOUT"
ERROR_EXEC_CANCELLED = "EXEC_CANCELLED"
ERROR_REMOTE_EXIT_NONZERO = "REMOTE_EXIT_NONZERO"
ERROR_OUTPUT_LIMIT = "OUTPUT_LIMIT"
ERROR_LOCAL_IO_ERROR = "LOCAL_IO_ERROR"
ERROR_REMOTE_IO_ERROR = "REMOTE_IO_ERROR"
ERROR_CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"

STABLE_ERROR_CODES: frozenset[str] = frozenset({
    ERROR_INVALID_ARGUMENT,
    ERROR_RESOURCE_LIMIT,
    ERROR_REVIEW_REJECTED,
    ERROR_HOST_KEY_MISMATCH,
    ERROR_AUTH_FAILED,
    ERROR_CONNECT_TIMEOUT,
    ERROR_CONNECTION_LOST,
    ERROR_EXEC_TIMEOUT,
    ERROR_EXEC_CANCELLED,
    ERROR_REMOTE_EXIT_NONZERO,
    ERROR_OUTPUT_LIMIT,
    ERROR_LOCAL_IO_ERROR,
    ERROR_REMOTE_IO_ERROR,
    ERROR_CHECKSUM_MISMATCH,
})

# Error codes that may be safely retried by an automated caller.
_RETRYABLE_CODES: frozenset[str] = frozenset({
    ERROR_CONNECT_TIMEOUT,
    ERROR_CONNECTION_LOST,
    ERROR_EXEC_TIMEOUT,
    ERROR_REMOTE_IO_ERROR,
})


def is_retryable(code: str) -> bool:
    return code in _RETRYABLE_CODES


# ---------------------------------------------------------------------------
# Error + envelope
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ErrorInfo:
    code: str
    message: str
    retryable: bool = False


@dataclass(frozen=True)
class ResultEnvelope:
    schema_version: str = "1.0"
    request_id: str = ""
    ok: bool = False
    tool: str = ""
    host: str = ""
    status: str = STATUS_FAILED
    duration_ms: int = 0
    review: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    error: ErrorInfo | None = None
    text: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["error"] = asdict(self.error) if self.error else None
        return d

    def to_mcp_text(self) -> str:
        """Human-readable fallback rendering when `text` is empty."""
        if self.text:
            return self.text
        if self.ok:
            return f"[ok] {self.tool} {self.status}"
        code = self.error.code if self.error else "UNKNOWN"
        message = self.error.message if self.error else ""
        return f"[{self.status}] {self.tool} {code} {message}".rstrip()


def new_request_id() -> str:
    return uuid.uuid4().hex


def _now_ms() -> int:
    return int(time.monotonic() * 1000)


def make_success(
    tool: str,
    host: str,
    data: dict[str, Any] | None = None,
    text: str = "",
    warnings: list[str] | None = None,
    request_id: str | None = None,
    review: dict[str, Any] | None = None,
    duration_ms: int = 0,
    status: str = STATUS_SUCCEEDED,
) -> ResultEnvelope:
    return ResultEnvelope(
        request_id=request_id or new_request_id(),
        ok=True,
        tool=tool,
        host=host,
        status=status,
        duration_ms=duration_ms or _now_ms(),
        review=review or {},
        data=data or {},
        warnings=warnings or [],
        error=None,
        text=text,
    )


def make_failure(
    code: str,
    message: str,
    tool: str,
    host: str = "",
    status: str | None = None,
    data: dict[str, Any] | None = None,
    text: str = "",
    warnings: list[str] | None = None,
    request_id: str | None = None,
    review: dict[str, Any] | None = None,
    duration_ms: int = 0,
) -> ResultEnvelope:
    return ResultEnvelope(
        request_id=request_id or new_request_id(),
        ok=False,
        tool=tool,
        host=host,
        status=status or STATUS_FAILED,
        duration_ms=duration_ms or _now_ms(),
        review=review or {},
        data=data or {},
        warnings=warnings or [],
        error=ErrorInfo(code=code, message=message, retryable=is_retryable(code)),
        text=text,
    )


def make_rejected(
    reason: str,
    tool: str,
    host: str = "",
    request_id: str | None = None,
    review: dict[str, Any] | None = None,
) -> ResultEnvelope:
    return make_failure(
        code=ERROR_REVIEW_REJECTED,
        message=reason,
        tool=tool,
        host=host,
        status=STATUS_REJECTED,
        request_id=request_id,
        review=review,
    )


def envelope_to_text(env: ResultEnvelope) -> str:
    """Return the human-readable text for an envelope (compat render)."""
    return env.to_mcp_text()
