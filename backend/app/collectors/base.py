"""Collector base class.

A collector's only job is: acquire something security relevant, attach a
timestamp, and hand a :class:`RawRecord` to the pipeline sink. Collectors never
write to the database and never block the pipeline - if a source dies the rest
of the platform keeps working, and the failure is visible through ``status()``.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable

from ..config.logging_config import get_logger
from ..database.enums import EventType
from ..processors.models import RawRecord

logger = get_logger(__name__)

Sink = Callable[[RawRecord], bool | None]


class Collector(ABC):
    """Base class for every data source."""

    #: Stable identifier used in event records and the dashboard.
    name: str = "collector"

    def __init__(self, sink: Sink, **options: Any) -> None:
        self._sink = sink
        self.options = options
        self._lock = threading.RLock()
        self._running = False
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._records = 0
        self._errors = 0
        self._dropped = 0
        self._last_error: str | None = None
        self._last_record_at: datetime | None = None
        self._detail: dict[str, Any] = {}

    # --------------------------------------------------------- lifecycle
    @abstractmethod
    def _start(self) -> bool:
        """Start the underlying source; return False when unavailable."""

    @abstractmethod
    def _stop(self) -> None:
        """Stop the underlying source (idempotent)."""

    def start(self) -> bool:
        with self._lock:
            if self._running:
                return True
            try:
                started = bool(self._start())
            except Exception as exc:
                self._errors += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
                logger.error(
                    "collector failed to start",
                    extra={"collector": self.name, "error": self._last_error},
                )
                return False
            self._running = started
            if started:
                self._started_at = datetime.now(timezone.utc).replace(tzinfo=None)
                logger.info("collector started", extra={"collector": self.name, **(self._detail or {})})
            else:
                logger.warning(
                    "collector unavailable",
                    extra={"collector": self.name, "reason": self._last_error},
                )
            return started

    def stop(self) -> None:
        with self._lock:
            if not self._running and self._stopped_at is not None:
                return
            self._running = False
            try:
                self._stop()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "collector stop raised", extra={"collector": self.name, "error": str(exc)}
                )
            self._stopped_at = datetime.now(timezone.utc).replace(tzinfo=None)
            logger.info("collector stopped", extra={"collector": self.name})

    # ------------------------------------------------------------ emit
    def source_label(self) -> str | None:
        """Interface or endpoint this collector reads from.

        Stamped onto every record so the dashboard can show where an event
        actually came from. Subclasses override it with the resource they really
        attached to (the resolved NIC, the bound UDP port, the lab scenario).
        """
        return self.options.get("interface")

    def emit(
        self,
        payload: dict[str, Any],
        *,
        event_type: str = EventType.UNKNOWN.value,
        source_host: str | None = None,
        timestamp: datetime | None = None,
    ) -> bool:
        """Send one record to the pipeline. Never raises."""
        record = RawRecord(
            collector=self.name,
            received_at=timestamp or datetime.now(timezone.utc).replace(tzinfo=None),
            event_type=event_type,
            payload=payload,
            interface=self.source_label(),
            source_host=source_host,
        )
        try:
            accepted = self._sink(record)
        except Exception as exc:  # pragma: no cover - sink failures are fatal for the collector
            self._errors += 1
            self._last_error = f"sink error: {exc}"
            return False
        with self._lock:
            if accepted is False:
                self._dropped += 1
            else:
                self._records += 1
            self._last_record_at = record.received_at
        return accepted is not False

    # ----------------------------------------------------------- status
    @property
    def running(self) -> bool:
        return self._running

    def set_detail(self, **detail: Any) -> None:
        self._detail.update(detail)

    def record_error(self, error: Exception | str) -> None:
        with self._lock:
            self._errors += 1
            self._last_error = str(error)

    def status(self) -> dict:
        with self._lock:
            uptime = None
            if self._started_at:
                uptime = (
                    datetime.now(timezone.utc).replace(tzinfo=None) - self._started_at
                ).total_seconds()
            return {
                "collector": self.name,
                "running": self._running,
                "records": self._records,
                "errors": self._errors,
                "dropped": self._dropped,
                "last_error": self._last_error,
                "last_record_at": self._last_record_at.isoformat() if self._last_record_at else None,
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "uptime_seconds": round(uptime, 1) if uptime is not None else None,
                "detail": dict(self._detail),
            }


__all__ = ["Collector", "Sink"]
