"""
Structured JSON Logger for the Detection Platform.

Produces machine-readable JSON log lines with:
  - ISO-8601 timestamp
  - Log level
  - Request ID (trace correlation)
  - Scan ID (when available)
  - Latency in milliseconds
  - Event type

Usage:
    from backend.logger import get_logger
    log = get_logger(__name__)
    log.info("scan_complete", scan_id=scan_id, latency_ms=145, verdict="PHISHING")
"""
import json
import logging
import sys
import time
import uuid
from typing import Any


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Include extra fields attached by the caller via extra={}
        skip = {
            "name", "msg", "args", "levelname", "levelno", "pathname",
            "filename", "module", "exc_info", "exc_text", "stack_info",
            "lineno", "funcName", "created", "msecs", "relativeCreated",
            "thread", "threadName", "processName", "process", "message",
            "taskName"
        }
        for key, val in record.__dict__.items():
            if key not in skip:
                try:
                    json.dumps(val)
                    log_obj[key] = val
                except (TypeError, ValueError):
                    log_obj[key] = str(val)

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj, ensure_ascii=False)


class StructuredLogger:
    """
    Thin wrapper around stdlib Logger that accepts **kwargs as structured fields.
    Usage: log.info("event_name", key=value, latency_ms=120)
    """
    def __init__(self, name: str):
        self._logger = logging.getLogger(name)
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(JSONFormatter())
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)
            self._logger.propagate = False

    def info(self, msg: str, **kwargs: Any) -> None:
        self._logger.info(msg, extra=kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._logger.warning(msg, extra=kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._logger.error(msg, extra=kwargs)

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._logger.debug(msg, extra=kwargs)


def get_logger(name: str) -> StructuredLogger:
    """Returns a structured JSON logger for the given module name."""
    return StructuredLogger(name)


class RequestTimer:
    """Context manager for timing request latency."""

    def __init__(self):
        self.start: float = 0.0
        self.elapsed_ms: float = 0.0

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *_):
        self.elapsed_ms = round((time.perf_counter() - self.start) * 1000, 2)


def new_request_id() -> str:
    """Generates a short unique request ID for trace correlation."""
    return uuid.uuid4().hex[:12]
