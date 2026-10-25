"""Operational logging for Mini SOC (spec section 27).

Design goals:

* every log line is machine readable (JSON) so ``/api/v1/system/logs`` and any
  external shipper can consume it without parsing prose;
* a request id is attached automatically to API, pipeline and collector logs,
  which makes the full chain - collector -> pipeline -> detection -> alert ->
  websocket - traceable;
* rotating files under ``<home>/logs`` keep disk usage bounded;
* secrets are never logged: a redaction filter drops known sensitive keys.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .settings import Settings, get_settings

#: Correlation id for the current request / pipeline unit of work.
request_id_var: ContextVar[str] = ContextVar("mini_soc_request_id", default="-")

LOG_FILE_NAME = "mini_soc.log"
ERROR_FILE_NAME = "mini_soc.error.log"

_REDACT_KEYS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "jwt",
    "credential",
    "refresh_token",
    "access_token",
)
_REDACT_PATTERN = re.compile(
    "|".join(rf'"{key}[^"]*"\s*:\s*"[^"]*"' for key in _REDACT_KEYS), re.IGNORECASE
)
_VALUE_PATTERN = re.compile(
    rf'({ "|".join(_REDACT_KEYS) })=([^\s,;]+)', re.IGNORECASE
)

_RESERVED = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "taskName",
    "message",
    "asctime",
}


class ExtraSafeLogger(logging.Logger):
    """Logger that cannot crash on a reserved ``extra`` key.

    ``logging`` raises ``KeyError`` when an ``extra`` key collides with a
    LogRecord attribute (``created``, ``message``, ``name`` ...). Since extras
    come from many call sites, they are renamed instead of blowing up a request
    or, worse, a pipeline worker.
    """

    def makeRecord(
        self,
        name: str,
        level: int,
        fn: str,
        lno: int,
        msg: object,
        args: Any,
        exc_info: Any,
        func: str | None = None,
        extra: dict[str, Any] | None = None,
        sinfo: str | None = None,
    ) -> logging.LogRecord:
        if extra:
            extra = {
                (f"ctx_{key}" if key in _RESERVED else key): value for key, value in extra.items()
            }
        return super().makeRecord(name, level, fn, lno, msg, args, exc_info, func, extra, sinfo)


# Installed at import time so every application logger created afterwards uses it.
logging.setLoggerClass(ExtraSafeLogger)


def redact(text: str) -> str:
    """Remove obvious secrets from a log/message string."""
    text = _REDACT_PATTERN.sub('"***"', text)
    return _VALUE_PATTERN.sub(r"\1=***", text)


class SecretRedactionFilter(logging.Filter):
    """Drop sensitive values from the rendered message and extras."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            message = str(record.msg)
        record.msg = redact(message)
        record.args = ()
        for key in list(getattr(record, "__dict__", {}).keys()):
            if any(sensitive in key.lower() for sensitive in _REDACT_KEYS):
                setattr(record, key, "***")
        return True


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON objects."""

    def __init__(self, *, include_extras: bool = True) -> None:
        super().__init__()
        self.include_extras = include_extras

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None) or request_id_var.get(),
            "module": record.module,
            "line": record.lineno,
        }
        if self.include_extras:
            for key, value in record.__dict__.items():
                if key not in _RESERVED and not key.startswith("_") and key not in payload:
                    if key == "request_id":
                        continue
                    try:
                        json.dumps(value)
                        payload[key] = value
                    except (TypeError, ValueError):
                        payload[key] = repr(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class HumanFormatter(logging.Formatter):
    """Readable console formatter for interactive development."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        rid = getattr(record, "request_id", None) or request_id_var.get()
        base = f"{stamp} {record.levelname:<8} [{rid}] {record.name}: {record.getMessage()}"
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def setup_logging(settings: Settings | None = None, *, force: bool = False) -> Path:
    """Configure application logging and return the log directory."""
    explicit_settings = settings is not None
    settings = settings or get_settings()
    paths = settings.paths.ensure()
    log_dir = paths.logs

    root = logging.getLogger()
    # Re-configure whenever settings are passed explicitly (tests and repeated
    # application factories pass their own settings); otherwise configure once.
    if getattr(root, "_mini_soc_configured", False) and not force and not explicit_settings:
        return log_dir

    for handler in list(root.handlers):
        root.removeHandler(handler)

    root.setLevel(settings.log_level)
    redaction = SecretRedactionFilter()

    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / LOG_FILE_NAME,
        maxBytes=settings.log_max_bytes,
        backupCount=settings.log_backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(JsonFormatter())
    file_handler.addFilter(redaction)
    root.addHandler(file_handler)

    error_handler = logging.handlers.RotatingFileHandler(
        log_dir / ERROR_FILE_NAME,
        maxBytes=settings.log_max_bytes,
        backupCount=settings.log_backup_count,
        encoding="utf-8",
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(JsonFormatter())
    error_handler.addFilter(redaction)
    root.addHandler(error_handler)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(JsonFormatter() if settings.log_json else HumanFormatter())
    console.addFilter(redaction)
    root.addHandler(console)

    if not settings.debug:
        for noisy in ("uvicorn.access", "scapy.runtime", "scapy.loading", "httpx", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    root._mini_soc_configured = True  # type: ignore[attr-defined]
    logging.getLogger(__name__).info(
        "logging configured",
        extra={"log_dir": str(log_dir), "environment": settings.env},
    )
    return log_dir


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced application logger."""
    return logging.getLogger(name)


__all__ = [
    "ERROR_FILE_NAME",
    "HumanFormatter",
    "JsonFormatter",
    "LOG_FILE_NAME",
    "SecretRedactionFilter",
    "get_logger",
    "redact",
    "request_id_var",
    "setup_logging",
]
