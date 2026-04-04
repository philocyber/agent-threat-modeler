"""Structured logging configuration for AgenticTM.

Provides JSON-formatted structured logging with:
- Correlation IDs per analysis (thread-local)
- Per-agent attribution
- Timing information
- Clean integration with Python's logging module

Usage::

    from agentictm.logging import configure_logging, set_correlation_id

    configure_logging()  # Call once at startup
    set_correlation_id("analysis-abc123")  # Set per-analysis
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any


# Thread-local storage for correlation IDs
_context = threading.local()


def set_correlation_id(correlation_id: str) -> None:
    """Set the correlation ID for the current thread (analysis run)."""
    _context.correlation_id = correlation_id


def get_correlation_id() -> str:
    """Get the correlation ID for the current thread."""
    return getattr(_context, "correlation_id", "")


def set_agent_name(agent_name: str) -> None:
    """Set the current agent name for the current thread."""
    _context.agent_name = agent_name


def get_agent_name() -> str:
    """Get the current agent name for the current thread."""
    return getattr(_context, "agent_name", "")


class StructuredFormatter(logging.Formatter):
    """Formats log records as JSON for structured logging.

    Output format::

        {
            "timestamp": "2025-01-01T00:00:00.000Z",
            "level": "INFO",
            "logger": "agentictm.agents.stride_analyst",
            "message": "STRIDE analysis complete",
            "correlation_id": "abc123",
            "agent": "stride_analyst",
            "module": "stride_analyst",
            "function": "analyze",
            "line": 42
        }
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add correlation ID if set
        correlation_id = get_correlation_id()
        if correlation_id:
            log_data["correlation_id"] = correlation_id

        # Add agent name if set
        agent_name = get_agent_name()
        if agent_name:
            log_data["agent"] = agent_name

        # Add source location
        log_data["module"] = record.module
        log_data["function"] = record.funcName
        log_data["line"] = record.lineno

        # Add exception info if present
        if record.exc_info and record.exc_info[1]:
            log_data["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }

        # Add any extra fields attached to the record
        for key in ("duration_ms", "threats_count", "token_count", "phase"):
            if hasattr(record, key):
                log_data[key] = getattr(record, key)

        return json.dumps(log_data, ensure_ascii=False, default=str)


class HumanReadableFormatter(logging.Formatter):
    """Pretty formatter for development/terminal output with correlation IDs."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        reset = self.RESET

        correlation_id = get_correlation_id()
        cid_part = f" [{correlation_id}]" if correlation_id else ""

        agent_name = get_agent_name()
        agent_part = f" [{agent_name}]" if agent_name else ""

        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S.%f")[:-3]

        return (
            f"{timestamp} "
            f"{color}{record.levelname:<5}{reset}"
            f"{cid_part}{agent_part} "
            f"{record.getMessage()}"
        )


class _AgenticTMDuplicateFilter(logging.Filter):
    """Suppress ``agentictm.*`` records on the root logger.

    When uvicorn (or any other library) adds a handler to the root logger
    those records would be emitted twice — once by our ``agentictm`` handler
    and once by the root handler.  This filter blocks the duplicate.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return not record.name.startswith("agentictm")


def configure_logging(
    *,
    json_output: bool = False,
    level: int = logging.INFO,
) -> None:
    """Configure structured logging for the entire application.

    Args:
        json_output: If True, use JSON format (for production).
                      If False, use human-readable format (for development).
        level: Minimum log level.
    """
    root_logger = logging.getLogger("agentictm")

    # Remove existing handlers to avoid duplicates on reload
    root_logger.handlers.clear()

    import sys
    import io

    stream = sys.stderr
    # On Windows the default console encoding (cp1252 / cp437) cannot render
    # Unicode symbols that agents commonly log (checkmarks, arrows, etc.).
    # Wrap the stream so encoding errors are replaced instead of crashing.
    if hasattr(stream, "encoding") and stream.encoding:
        try:
            "✓→•—".encode(stream.encoding)
        except (UnicodeEncodeError, LookupError):
            stream = io.TextIOWrapper(
                stream.buffer, encoding=stream.encoding, errors="replace",
                line_buffering=True,
            )

    handler = logging.StreamHandler(stream)
    if json_output:
        handler.setFormatter(StructuredFormatter())
    else:
        handler.setFormatter(HumanReadableFormatter())

    handler.setLevel(level)
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

    # Don't propagate to root logger (avoids duplicate output from
    # uvicorn's default handler picking up agentictm.* records)
    root_logger.propagate = False

    # Silence the root Python logger's default handler for our namespace
    # to prevent duplicate lines when uvicorn adds its own StreamHandler.
    for h in logging.root.handlers[:]:
        if isinstance(h, logging.StreamHandler) and h.stream in (sys.stdout, sys.stderr):
            h.addFilter(_AgenticTMDuplicateFilter())


class PipelineFileHandler(logging.Handler):
    """JSONL file handler that writes structured logs for a single analysis run.

    Each analysis gets its own ``logs/{correlation_id}.jsonl`` file.
    Attach at the start of ``analyze()`` and remove at the end.

    Usage::

        handler = PipelineFileHandler(correlation_id)
        handler.attach()
        try:
            # ... run analysis ...
        finally:
            handler.detach()
    """

    def __init__(self, correlation_id: str, logs_dir: str = "logs"):
        super().__init__(level=logging.DEBUG)
        from pathlib import Path
        self._logs_dir = Path(logs_dir)
        self._logs_dir.mkdir(exist_ok=True)
        self._path = self._logs_dir / f"{correlation_id}.jsonl"
        self._file = open(self._path, "a", encoding="utf-8")
        self._cid = correlation_id

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry: dict[str, Any] = {
                "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                "level": record.levelname,
                "node": get_agent_name() or record.module,
                "msg": record.getMessage(),
            }
            cid = get_correlation_id()
            if cid:
                entry["cid"] = cid

            data: dict[str, Any] = {}
            for key in ("duration_ms", "threats_count", "token_count", "phase",
                        "node_name", "input_keys", "output_keys", "error"):
                val = getattr(record, key, None)
                if val is not None:
                    data[key] = val
            if data:
                entry["data"] = data

            if record.exc_info and record.exc_info[1]:
                entry["exception"] = {
                    "type": type(record.exc_info[1]).__name__,
                    "message": str(record.exc_info[1]),
                }

            self._file.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            self._file.flush()
        except Exception:
            self.handleError(record)

    def attach(self) -> None:
        """Attach this handler to the agentictm logger."""
        logging.getLogger("agentictm").addHandler(self)

    def detach(self) -> None:
        """Remove this handler from the agentictm logger and close the file."""
        logging.getLogger("agentictm").removeHandler(self)
        try:
            self._file.close()
        except Exception:
            pass

    @property
    def log_path(self) -> str:
        return str(self._path)

    def close(self) -> None:
        self.detach()
        super().close()


class TimingContext:
    """Context manager for timing operations and logging duration.

    Usage::

        with TimingContext("stride_analysis", logger):
            # ... analysis code ...
    """

    def __init__(self, operation: str, log: logging.Logger, level: int = logging.INFO):
        self.operation = operation
        self.log = log
        self.level = level
        self._start: float = 0.0

    def __enter__(self) -> "TimingContext":
        self._start = time.monotonic()
        return self

    def __exit__(self, *args: Any) -> None:
        duration_ms = (time.monotonic() - self._start) * 1000
        self.log.log(
            self.level,
            "%s completed in %.1fms",
            self.operation,
            duration_ms,
            extra={"duration_ms": round(duration_ms, 1)},
        )

    @property
    def elapsed_ms(self) -> float:
        return (time.monotonic() - self._start) * 1000
