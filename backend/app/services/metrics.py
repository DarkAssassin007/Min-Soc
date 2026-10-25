"""Performance metrics (spec section 26).

The platform measures itself instead of claiming performance:

* events per second (observed, computed from a moving window)
* processing / detection / alert / database / websocket latency
* queue depth, dropped events, collector counters
* CPU and memory utilisation of the SOC process

Values are published both in-memory (``/api/v1/system/metrics``) and
periodically persisted so the dashboard can chart a trend.
"""

from __future__ import annotations

import json
import os
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable

from ..config.logging_config import get_logger
from ..database.base import utcnow
from ..database.models import MetricsSnapshot

logger = get_logger(__name__)

#: How many samples of each latency series to keep for percentiles.
LATENCY_WINDOW = 500


@dataclass
class LatencySeries:
    """A bounded latency series with percentile helpers."""

    name: str
    values: deque[float] = field(default_factory=lambda: deque(maxlen=LATENCY_WINDOW))

    def add(self, value_ms: float) -> None:
        self.values.append(float(value_ms))

    def summary(self) -> dict[str, float]:
        if not self.values:
            return {"count": 0, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
        ordered = sorted(self.values)
        index = max(0, int(len(ordered) * 0.95) - 1)
        return {
            "count": len(ordered),
            "mean_ms": round(statistics.fmean(ordered), 3),
            "p50_ms": round(ordered[len(ordered) // 2], 3),
            "p95_ms": round(ordered[index], 3),
            "max_ms": round(ordered[-1], 3),
        }


class MetricsCollector:
    """Central performance telemetry for the running platform."""

    def __init__(self, *, started_at: float | None = None) -> None:
        self.started_at = started_at or time.time()
        self._lock = threading.RLock()
        self.external = LatencySeries("processing")
        self.detection = LatencySeries("detection")
        self.alert = LatencySeries("alert")
        self.database = LatencySeries("database")
        self.websocket = LatencySeries("websocket")
        self.collector_latency = LatencySeries("collector")
        self.events_total = 0
        self.events_rejected = 0
        self.events_duplicate = 0
        self.alerts_created = 0
        self.alerts_updated = 0
        #: Alerts that ended up (created or deduplicated) inside an incident.
        self.alerts_correlated = 0
        self.dropped_events = 0
        self.broadcasts = 0
        self.broadcast_failures = 0
        self._recent_events: deque[float] = deque(maxlen=2000)
        self._process = None
        try:  # psutil is a hard dependency, but metrics must never break ingest
            import psutil

            self._process = psutil.Process(os.getpid())
            self._process.cpu_percent(interval=None)  # prime the counter
        except Exception:  # pragma: no cover
            self._process = None

    # ------------------------------------------------------------ recording
    def record_event(self, *, accepted: bool, duplicate: bool = False) -> None:
        with self._lock:
            self._recent_events.append(time.time())
            if accepted:
                self.events_total += 1
            elif duplicate:
                self.events_duplicate += 1
            else:
                self.events_rejected += 1

    def record_alert(self, *, created: bool, linked_to_incident: bool = False) -> None:
        with self._lock:
            if created:
                self.alerts_created += 1
            else:
                self.alerts_updated += 1
            if linked_to_incident:
                self.alerts_correlated += 1

    def record_drop(self, count: int = 1) -> None:
        with self._lock:
            self.dropped_events += count

    def events_per_second(self, window_seconds: float = 5.0) -> float:
        with self._lock:
            if not self._recent_events:
                return 0.0
            now = time.time()
            recent = [stamp for stamp in self._recent_events if now - stamp <= window_seconds]
            if not recent:
                return 0.0
            span = max(now - min(recent), 1e-3)
            return round(len(recent) / span, 2)

    # ------------------------------------------------------------- snapshot
    def snapshot(self, *, queue_depth: int = 0, collectors: dict | None = None) -> dict[str, Any]:
        cpu = memory = 0.0
        if self._process is not None:
            try:
                cpu = float(self._process.cpu_percent(interval=None))
                memory = round(self._process.memory_info().rss / (1024 * 1024), 2)
            except Exception:  # pragma: no cover
                cpu = memory = 0.0
        with self._lock:
            snapshot = {
                "captured_at": utcnow().isoformat(),
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "events_per_second": self.events_per_second(),
                "events_total": self.events_total,
                "events_rejected": self.events_rejected,
                "events_duplicate": self.events_duplicate,
                "dropped_events": self.dropped_events,
                "alerts_created": self.alerts_created,
                "alerts_updated": self.alerts_updated,
                "alerts_correlated": self.alerts_correlated,
                "broadcasts": self.broadcasts,
                "broadcast_failures": self.broadcast_failures,
                "queue_depth": queue_depth,
                "cpu_percent": round(cpu, 2),
                "memory_mb": memory,
                "latency": {
                    "processing": self.external.summary(),
                    "detection": self.detection.summary(),
                    "alert": self.alert.summary(),
                    "database": self.database.summary(),
                    "websocket": self.websocket.summary(),
                    "collection": self.collector_latency.summary(),
                },
                "collectors": collectors or {},
            }
        return snapshot

    def to_model(self, snapshot: dict[str, Any]) -> MetricsSnapshot:
        latency = snapshot.get("latency", {})
        return MetricsSnapshot(
            captured_at=utcnow(),
            events_per_second=float(snapshot.get("events_per_second") or 0.0),
            events_total=int(snapshot.get("events_total") or 0),
            alerts_total=int(snapshot.get("alerts_created") or 0),
            queue_depth=int(snapshot.get("queue_depth") or 0),
            dropped_events=int(snapshot.get("dropped_events") or 0),
            processing_latency_ms=float(latency.get("processing", {}).get("mean_ms") or 0.0),
            detection_latency_ms=float(latency.get("detection", {}).get("mean_ms") or 0.0),
            alert_latency_ms=float(latency.get("alert", {}).get("mean_ms") or 0.0),
            db_write_latency_ms=float(latency.get("database", {}).get("mean_ms") or 0.0),
            ws_delivery_ms=float(latency.get("websocket", {}).get("mean_ms") or 0.0),
            cpu_percent=float(snapshot.get("cpu_percent") or 0.0),
            memory_mb=float(snapshot.get("memory_mb") or 0.0),
            uptime_seconds=float(snapshot.get("uptime_seconds") or 0.0),
            collectors=snapshot.get("collectors") or {},
        )


def json_dump(payload: Any) -> str:
    """Small helper used by tests and the CLI."""
    return json.dumps(payload, default=str)


__all__ = ["LATENCY_WINDOW", "LatencySeries", "MetricsCollector", "json_dump"]
