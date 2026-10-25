"""Alert correlation: turn related alerts into incidents.

Correlation policy (all thresholds configurable):

1. An alert always joins an existing open incident that shares a source entity.
2. Otherwise a new incident is opened when either
   * the alert is HIGH/CRITICAL, or
   * the same source produced ``min_alerts`` alerts with at least
     ``min_detection_types`` distinct detection types inside the window
     (the "multiple stages of one attack" case from the specification).
3. Alerts below those thresholds stay standalone alerts - not every event is an
   incident, and inventing incidents destroys analyst trust in the tool.
"""

from __future__ import annotations

import threading
from datetime import timedelta
from typing import Any

from ...config.logging_config import get_logger
from ...database.base import utcnow
from ...database.models import Alert, Incident
from ...database.repository import Repository

logger = get_logger(__name__)

#: Alerts at or above these severities always open an incident.
INCIDENT_SEVERITIES = {"HIGH", "CRITICAL"}


class Correlator:
    """Groups alerts into incidents using entities, time and detection types."""

    def __init__(
        self,
        repository: Repository,
        incident_manager: Any,
        settings: Any,
        *,
        min_alerts: int = 3,
        min_detection_types: int = 2,
    ) -> None:
        self.repository = repository
        self.incidents = incident_manager
        self.settings = settings
        self.min_alerts = int(min_alerts)
        self.min_detection_types = int(min_detection_types)
        self._lock = threading.RLock()
        self._linked = 0
        self._created = 0

    @property
    def window_minutes(self) -> int:
        return max(int(self.settings.correlation_window_seconds or 600) // 60, 1)

    # --------------------------------------------------------------- logic
    def correlate(self, alert: Alert) -> Incident | None:
        """Attach or create an incident for ``alert``; returns it when relevant."""
        sources = [entity for entity in (alert.source_ip, alert.destination_ip) if entity]
        try:
            open_incidents = self.repository.open_incidents_for_sources(
                sources, window_minutes=self.window_minutes
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("incident lookup failed", extra={"error": str(exc)})
            return None

        if open_incidents:
            incident = open_incidents[0]
            for extra in open_incidents[1:]:
                self.incidents.merge(incident, extra)
            self.incidents.attach_alert(incident, alert)
            with self._lock:
                self._linked += 1
            logger.debug(
                "alert correlated into existing incident",
                extra={"alert": alert.alert_id, "incident": incident.incident_id},
            )
            return incident

        if not self._should_open_incident(alert):
            return None

        incident = self.incidents.create(
            title=self._title_for(alert),
            severity=alert.severity,
            risk_score=float(alert.risk_score or 0.0),
            summary=self._summary_for(alert),
            source_entities=[alert.source_ip] if alert.source_ip else [],
            destination_entities=[alert.destination_ip] if alert.destination_ip else [],
            detection_types=[alert.detection_type],
        )
        self.incidents.attach_alert(incident, alert)
        with self._lock:
            self._created += 1
        logger.info(
            "incident created from alert",
            extra={"alert": alert.alert_id, "incident": incident.incident_id},
        )
        return incident

    def _should_open_incident(self, alert: Alert) -> bool:
        if alert.severity in INCIDENT_SEVERITIES:
            return True
        if not alert.source_ip:
            return False
        since = utcnow() - timedelta(minutes=self.window_minutes)
        recent = [
            candidate
            for candidate in self.repository.alerts_for_source(
                alert.source_ip, minutes=self.window_minutes, limit=100
            )
            if (candidate.last_seen or since) >= since
        ]
        detection_types = {candidate.detection_type for candidate in recent}
        return len(recent) >= self.min_alerts and len(detection_types) >= self.min_detection_types

    @staticmethod
    def _title_for(alert: Alert) -> str:
        entity = alert.source_ip or alert.destination_ip or "unknown entity"
        mapping = {
            "MULTI_STAGE": "Multi-stage attack activity",
            "PORT_SCAN": "Reconnaissance activity",
            "BRUTE_FORCE": "Credential attack",
            "CONNECTION_FLOOD": "Availability attack",
            "DNS_ANOMALY": "Suspicious DNS activity",
            "VOLUME_ANOMALY": "Unusual data transfer",
            "ML_ANOMALY": "Anomalous behaviour",
        }
        classification = (alert.evidence or {}).get("classification")
        prefix = mapping.get(classification or "", alert.detection_type.replace("_", " ").title())
        return f"{prefix} from {entity}"

    @staticmethod
    def _summary_for(alert: Alert) -> str:
        classification = (alert.evidence or {}).get("classification", "UNCLASSIFIED")
        return (
            f"Opened from alert {alert.alert_id} ({alert.detection_type}, severity {alert.severity}, "
            f"risk {float(alert.risk_score or 0):.0f}, classification {classification}). "
            f"{alert.description or ''}".strip()
        )

    # -------------------------------------------------------------- status
    def statistics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "incidents_created": self._created,
                "alerts_linked": self._linked,
                "window_minutes": self.window_minutes,
                "min_alerts": self.min_alerts,
                "min_detection_types": self.min_detection_types,
            }


__all__ = ["Correlator", "INCIDENT_SEVERITIES"]
