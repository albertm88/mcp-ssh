"""In-memory buffered logger for mcp-ssh.

Accumulates log entries in a ring buffer; flushes to disk only on:
- Periodic interval (default 60s)
- Buffer full (default 1000 entries)
- Process exit (atexit)

Configure via environment variables:
  SSH_LOG_FILE   — log file path (default: ~/.ssh/mcp-ssh.log)
  SSH_LOG_LEVEL  — DEBUG / INFO / WARNING / ERROR (default: INFO)
  SSH_LOG_FLUSH_INTERVAL — seconds between auto-flushes (default: 60)
  SSH_LOG_BUFFER_SIZE    — max in-memory entries before force-flush (default: 1000)
"""
from __future__ import annotations

import atexit
import json
import os
import pathlib
import threading
from collections import deque
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Level(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40

    @classmethod
    def from_env(cls, key: str = "SSH_LOG_LEVEL", default: Level | None = None) -> Level:
        if default is None:
            default = cls.INFO
        name = os.getenv(key, "").upper()
        try:
            return cls[name]
        except KeyError:
            return default


class BufferedLogger:
    """Thread-safe in-memory ring-buffer logger with lazy disk flush."""

    def __init__(
        self,
        file_path: str | pathlib.Path | None = None,
        level: Level = Level.INFO,
        flush_interval: float = 60.0,
        buffer_size: int = 1000,
    ) -> None:
        self._level = level
        self._flush_interval = flush_interval
        self._buffer_size = max(buffer_size, 10)

        # Resolve log file path
        if file_path is None:
            file_path = os.getenv("SSH_LOG_FILE", "")
        if not file_path:
            file_path = pathlib.Path.home() / ".ssh" / "mcp-ssh.log"
        self._path = pathlib.Path(file_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

        # Ring buffer
        self._buffer: deque[dict[str, Any]] = deque(maxlen=self._buffer_size)
        self._lock = threading.Lock()
        self._dirty = False  # True when there are unflushed entries

        # Background flush
        self._stop_event = threading.Event()
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="ssh-log-flusher"
        )
        self._flush_thread.start()

        # Ensure flush on normal exit
        atexit.register(self._shutdown)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def debug(self, event: str, **extra: Any) -> None:
        self._emit(Level.DEBUG, event, extra)

    def info(self, event: str, **extra: Any) -> None:
        self._emit(Level.INFO, event, extra)

    def warning(self, event: str, **extra: Any) -> None:
        self._emit(Level.WARNING, event, extra)

    def error(self, event: str, **extra: Any) -> None:
        self._emit(Level.ERROR, event, extra)

    def flush(self) -> None:
        """Force-flush all buffered entries to disk."""
        with self._lock:
            if not self._dirty:
                return
            entries = list(self._buffer)
            self._buffer.clear()
            self._dirty = False
        self._write_entries(entries)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit(self, level: Level, event: str, extra: dict[str, Any]) -> None:
        if level < self._level:
            return
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level.name,
            "event": event,
            **extra,
        }
        with self._lock:
            # If buffer is full, force-flush before appending
            maxlen = self._buffer.maxlen
            assert maxlen is not None
            if len(self._buffer) >= maxlen:
                entries = list(self._buffer)
                self._buffer.clear()
                self._write_entries(entries)
            self._buffer.append(entry)
            self._dirty = True

    def _flush_loop(self) -> None:
        """Background thread: periodically flush dirty buffer."""
        while not self._stop_event.wait(self._flush_interval):
            self.flush()

    def _shutdown(self) -> None:
        """Called on process exit — stop thread and final flush."""
        self._stop_event.set()
        self.flush()

    def _write_entries(self, entries: list[dict[str, Any]]) -> None:
        """Append JSON-lines to log file."""
        if not entries:
            return
        try:
            with self._path.open("a", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, ensure_ascii=False, default=str) + "\n")
        except OSError:
            pass  # Silently drop if disk is unavailable


# ------------------------------------------------------------------
# Singleton — shared across the process
# ------------------------------------------------------------------

_logger: BufferedLogger | None = None


def get_logger() -> BufferedLogger:
    global _logger
    if _logger is None:
        _logger = BufferedLogger(
            level=Level.from_env(),
            flush_interval=float(os.getenv("SSH_LOG_FLUSH_INTERVAL", "60")),
            buffer_size=int(os.getenv("SSH_LOG_BUFFER_SIZE", "1000")),
        )
    return _logger
