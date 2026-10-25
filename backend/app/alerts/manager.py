"""Alert management (spec section 12).

Responsibilities:

* turn detections into alerts with a stable, human-readable id;
* **dedupe**: the same behaviour from the same entities inside the dedupe window
  updates the existing alert instead of flooding the analyst with duplicates;
* enforce the ``NEW -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED`` lifecycle;
* publish every change to listeners (the WebSocket layer) exactly once.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Callable

from ..config.logging_config import get_logger
from ..database.base import utcnow
from ..database.enums import ALERT_TRANSITIONS, AlertStatus, LogCategory
from ..database.models import Alert, Detection, Event
from ..database.repository import Repository, RepositoryError
from ..detection.engine import DetectionResult
from ..processors.models import NormalizedEvent
from ..provenance import normalize_collector
from ..risk.scoring import RiskAssessment

logger = get_logger(__name__)

AlertListener = Callable[[str, dict], None]

#: Alerts below this score are recorded as detections but never raised.
DEFAULT_MIN_ALERT_SCORE = 25.0


@dataclass
class AlertOutcome:
    """What the alert manager did with one event."""

    alert: Alert | None
    created: bool
    updated: bool
    reason: str | None = None


class AlertManager:
    """Creates, deduplicates and updates alerts."""

    def __init__(
        self,
        repository: Repository,
        settings: Any,
        *,
        correlator: Any | None = None,
        min_score: float = DEFAULT_MIN_ALERT_SCORE,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.correlator = correlator
        self.min_score = float(min_score)
        self._listeners: list[AlertListener] = []
        self._lock = threading.RLock()
        self._created = 0
        self._deduplicated = 0
        self._suppressed = 0
        self._last_latency_ms = 0.0

    # ---------------------------------------------------------- listeners
    def add_listener(self, listener: AlertListener) -> None:
        self._listeners.append(listener)

    def _publish(self, action: str, alert: Alert) -> None:
        payload = alert.public_dict()
        for listener in list(self._listeners):
            try:
                listener(action, payload)
            except Exception as exc:  # pragma: no cover - a bad listener must not break ingest
                logger.warning("alert listener failed", extra={"error": str(exc)})

    # ------------------------------------------------------------ creation
    @staticmethod
    def dedupe_key(detection_type: str, event: NormalizedEvent | Event) -> str:
        source = getattr(event, "source_ip", None)
        destination = getattr(event, "destination_ip", None)
        return f"{detection_type}|{source or '-'}|{destination or '-'}"

    def process(
        self,
        event: Event,
        normalized: NormalizedEvent,
        detection: DetectionResult,
        assessment: RiskAssessment,
        detections: Sequence[Detection] | None = None,
    ) -> AlertOutcome:
        """Create or update an alert for a detected event."""
        import time

        started = time.perf_counter()
        try:
            outcome = self._process(event, normalized, detection, assessment, detections)
        except Exception as exc:
            logger.error("alert processing failed", extra={"error": str(exc)}, exc_info=True)
            outcome = AlertOutcome(alert=None, created=False, updated=False, reason=str(exc))
        self._last_latency_ms = (time.perf_counter() - started) * 1000.0
        return outcome

    @staticmethod
    def _provenance_fields(
        normalized: NormalizedEvent, existing: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Collector/interface that produced this alert, cumulative across updates.

        The first feed that raised an alert stays the primary source; every feed
        and interface that keeps matching is appended so an analyst can see when
        an alert spans both real and lab traffic.
        """
        previous = existing or {}
        collectors = list(
            previous.get("collectors")
            or ([previous["collector"]] if previous.get("collector") else [])
        )
        interfaces = list(
            previous.get("interfaces")
            or ([previous["interface"]] if previous.get("interface") else [])
        )
        name = normalize_collector(normalized.collector)
        interface = (normalized.interface or "").strip() or None
        if name and name not in collectors:
            collectors.append(name)
        if interface and interface not in interfaces:
            interfaces.append(interface)
        return {
            "collector": previous.get("collector") or name,
            "interface": previous.get("interface") or interface,
            "collectors": collectors,
            "interfaces": interfaces,
        }

    def _process(
        self,
        event: Event,
        normalized: NormalizedEvent,
        detection: DetectionResult,
        assessment: RiskAssessment,
        detections: Sequence[Detection] | None = None,
    ) -> AlertOutcome:
        if not detection.triggered:
            return AlertOutcome(None, False, False, "no detection")
        if assessment.score < self.min_score:
            with self._lock:
                self._suppressed += 1
            return AlertOutcome(None, False, False, "below alert threshold")

        provenance_fields = self._provenance_fields(normalized)
        strongest = detection.strongest_rule()
        detection_type = (
            strongest.detection_type
            if strongest is not None
            else ("ML_ANOMALY" if detection.anomaly and detection.anomaly.is_anomaly else "UNKNOWN")
        )
        engine = strongest.engine if strongest is not None else "ML"
        rule_key = strongest.rule_key if strongest is not None else None
        key = self.dedupe_key(detection_type, normalized)

        window = int(self.settings.pipeline_dedupe_window_seconds or 60) * 12
        existing = self.repository.find_active_alert_for_dedupe(key, window_seconds=window)

        if existing is not None:
            previous_score = float(existing.risk_score or 0.0)
            previous_status = existing.status
            existing.last_seen = event.timestamp
            existing.event_count = int(existing.event_count or 0) + 1
            existing.risk_score = max(previous_score, assessment.score)
            existing.confidence = max(float(existing.confidence or 0.0), assessment.confidence)
            existing.severity = self.settings.severity_for(existing.risk_score)
            # A burst that gets worse should be visible again, but a resolved
            # alert is never silently reopened.
            if previous_status == AlertStatus.RESOLVED.value and assessment.score > previous_score:
                existing.status = AlertStatus.NEW.value
            evidence = dict(existing.evidence or {})
            evidence["occurrences"] = int(existing.event_count)
            evidence["last_event_id"] = event.event_id
            evidence["last_score"] = round(assessment.score, 2)
            samples = list(evidence.get("samples", []))[-4:]
            samples.append(
                {
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "destination_port": event.destination_port,
                    "score": round(assessment.score, 2),
                }
            )
            evidence["samples"] = samples
            evidence.update(self._provenance_fields(normalized, evidence))
            existing.evidence = evidence
            self._link_detections(detections, existing.alert_id)
            self.repository.session.flush()
            with self._lock:
                self._deduplicated += 1
            self._publish("alert.updated", existing)
            self._maybe_correlate(existing)
            return AlertOutcome(existing, False, True, "deduplicated")

        alert = Alert(
            alert_id=self.repository.next_id("alert", "ALT"),
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            detection_type=detection_type,
            rule_key=rule_key,
            engine=engine,
            risk_score=assessment.score,
            severity=assessment.severity,
            confidence=assessment.confidence,
            description=(
                strongest.description
                if strongest is not None
                else f"ML anomaly detected for {normalized.source_ip or 'unknown source'}"
            ),
            evidence={
                **provenance_fields,
                "classification": assessment.classification,
                "reasons": assessment.reasons,
                "components": assessment.components,
                "boosts": assessment.boosts,
                "first_event_id": event.event_id,
                "event_type": normalized.event_type,
                "protocol": normalized.protocol,
                "source_port": normalized.source_port,
                "destination_port": normalized.destination_port,
                "direction": normalized.direction,
                "rule_evidence": strongest.evidence if strongest is not None else {},
                "model": detection.anomaly.to_dict() if detection.anomaly else None,
            },
            recommended_action=strongest.recommended_action if strongest is not None else (
                "Compare the event against the host's normal behaviour and confirm whether the "
                "activity is expected."
            ),
            status=AlertStatus.NEW.value,
            dedupe_key=key,
            event_count=1,
        )
        self.repository.add_alert(alert)
        self._link_detections(detections, alert.alert_id)
        self.repository.log_system(
            message=f"alert {alert.alert_id} created ({detection_type}, score {assessment.score:.0f})",
            category=LogCategory.DETECTION.value,
            level="INFO" if assessment.severity in {"LOW", "MEDIUM"} else "WARNING",
            details={
                "alert_id": alert.alert_id,
                "detection_type": detection_type,
                "severity": assessment.severity,
                "source_ip": alert.source_ip,
                "event_id": event.event_id,
            },
        )
        with self._lock:
            self._created += 1
        self._publish("alert.created", alert)
        self._maybe_correlate(alert)
        return AlertOutcome(alert, True, False, None)

    @staticmethod
    def _link_detections(detections: "Sequence[Detection] | None", alert_id: str) -> None:
        """Attach the detections that produced this alert (Event -> Detection -> Alert)."""
        for detection in detections or []:
            detection.alert_id = alert_id

    def _maybe_correlate(self, alert: Alert) -> None:
        if self.correlator is None:
            return
        try:
            self.correlator.correlate(alert)
        except Exception as exc:  # correlation must never break ingest
            logger.error("correlation failed", extra={"alert": alert.alert_id, "error": str(exc)})

    # ------------------------------------------------------------ lifecycle
    def set_status(
        self,
        alert_id: str,
        status: str,
        *,
        actor_id: int | None = None,
        resolution: str | None = None,
        note: str | None = None,
    ) -> Alert:
        alert = self.repository.get_alert(alert_id)
        if alert is None:
            raise RepositoryError(f"unknown alert {alert_id!r}")
        if not AlertStatus.has(status):
            raise RepositoryError(f"invalid alert status {status!r}")
        allowed = ALERT_TRANSITIONS.get(alert.status, set())
        if status != alert.status and status not in allowed:
            raise RepositoryError(
                f"cannot move alert {alert_id} from {alert.status} to {status}"
            )
        alert.status = status
        now = utcnow()
        if status == AlertStatus.ACKNOWLEDGED.value:
            alert.acknowledged_at = now
            alert.acknowledged_by = actor_id
        if status in {AlertStatus.RESOLVED.value, AlertStatus.FALSE_POSITIVE.value}:
            alert.resolved_at = now
            alert.resolution = resolution
        if actor_id is not None:
            alert.assignee_id = alert.assignee_id or actor_id
        self.repository.session.flush()
        if note:
            self.repository.add_note(alert_id=alert_id, note=note, author_id=actor_id, action_taken=status)
        self.repository.log_system(
            message=f"alert {alert_id} moved to {status}",
            category=LogCategory.AUDIT.value,
            actor_id=actor_id,
            details={"alert_id": alert_id, "status": status, "resolution": resolution},
        )
        self._publish("alert.updated", alert)
        return alert

    def assign(self, alert_id: str, user_id: int) -> Alert:
        alert = self.repository.get_alert(alert_id)
        if alert is None:
            raise RepositoryError(f"unknown alert {alert_id!r}")
        alert.assignee_id = user_id
        self.repository.session.flush()
        self._publish("alert.updated", alert)
        return alert

    # -------------------------------------------------------------- status
    def statistics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "created": self._created,
                "deduplicated_updates": self._deduplicated,
                "suppressed_below_threshold": self._suppressed,
                "min_alert_score": self.min_score,
                "last_latency_ms": round(self._last_latency_ms, 3),
                "dedupe_window_seconds": int(self.settings.pipeline_dedupe_window_seconds or 60) * 12,
            }


__all__ = ["AlertManager", "AlertOutcome", "DEFAULT_MIN_ALERT_SCORE"]
