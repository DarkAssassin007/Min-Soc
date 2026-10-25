"""Incident management (spec section 13).

An incident is the analyst-facing unit of work: several related alerts, the
entities involved, a timeline of everything that happened, notes and a
resolution. The record exists so that "10 failed logins + a port scan + a weird
connection pattern" can be investigated as one story instead of ten alerts.
"""

from __future__ import annotations

import threading
from typing import Any

from ..config.logging_config import get_logger
from ..database.base import utcnow
from ..database.enums import INCIDENT_TRANSITIONS, IncidentStatus, LogCategory, SeverityLevel
from ..database.models import Alert, Incident
from ..database.repository import Repository, RepositoryError

logger = get_logger(__name__)

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class IncidentManager:
    """Creates and maintains incidents."""

    def __init__(self, repository: Repository, settings: Any) -> None:
        self.repository = repository
        self.settings = settings
        self._lock = threading.RLock()
        self._created = 0
        self._attached = 0

    # ------------------------------------------------------------ creation
    def create(
        self,
        *,
        title: str,
        severity: str,
        risk_score: float,
        summary: str | None = None,
        source_entities: list[str] | None = None,
        destination_entities: list[str] | None = None,
        detection_types: list[str] | None = None,
        owner_id: int | None = None,
    ) -> Incident:
        incident = Incident(
            incident_id=self.repository.next_id("incident", "INC", width=4),
            title=title[:255],
            summary=summary,
            severity=severity if severity in _SEVERITY_RANK else SeverityLevel.MEDIUM.value,
            risk_score=max(float(risk_score), 0.0),
            status=IncidentStatus.OPEN.value,
            source_entities=sorted({s for s in (source_entities or []) if s}),
            destination_entities=sorted({d for d in (destination_entities or []) if d}),
            detection_types=sorted({d for d in (detection_types or []) if d}),
            timeline=[
                {
                    "timestamp": utcnow().isoformat(),
                    "event": "incident_created",
                    "description": title,
                }
            ],
            alert_count=0,
            owner_id=owner_id,
        )
        self.repository.add_incident(incident)
        self.repository.log_system(
            message=f"incident {incident.incident_id} created: {title}",
            category=LogCategory.DETECTION.value,
            level="WARNING",
            details={"incident_id": incident.incident_id, "severity": severity},
        )
        with self._lock:
            self._created += 1
        return incident

    # ------------------------------------------------------------ attaching
    def attach_alert(self, incident: Incident, alert: Alert) -> Incident:
        """Attach an alert to an incident, keeping severity/timeline current."""
        if alert.incident_id == incident.incident_id:
            return incident
        alert.incident_id = incident.incident_id
        incident.alert_count = int(incident.alert_count or 0) + 1
        incident.risk_score = max(float(incident.risk_score or 0.0), float(alert.risk_score or 0.0))
        if _SEVERITY_RANK.get(alert.severity, 0) > _SEVERITY_RANK.get(incident.severity, 0):
            incident.severity = alert.severity
        if alert.source_ip and alert.source_ip not in (incident.source_entities or []):
            incident.source_entities = sorted({*(incident.source_entities or []), alert.source_ip})
        if alert.destination_ip and alert.destination_ip not in (incident.destination_entities or []):
            incident.destination_entities = sorted(
                {*(incident.destination_entities or []), alert.destination_ip}
            )
        if alert.detection_type and alert.detection_type not in (incident.detection_types or []):
            incident.detection_types = sorted({*(incident.detection_types or []), alert.detection_type})
        timeline = list(incident.timeline or [])
        timeline.append(
            {
                "timestamp": (alert.last_seen or utcnow()).isoformat(),
                "event": "alert_attached",
                "alert_id": alert.alert_id,
                "description": alert.description,
                "severity": alert.severity,
                "risk_score": round(float(alert.risk_score or 0.0), 2),
            }
        )
        incident.timeline = timeline[-200:]
        incident.updated_at = utcnow()
        # Re-open a closed incident if new activity arrives.
        if incident.status in {IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value}:
            incident.status = IncidentStatus.INVESTIGATING.value
        self.repository.session.flush()
        with self._lock:
            self._attached += 1
        return incident

    def merge(self, target: Incident, other: Incident) -> Incident:
        """Merge one incident into another (used when correlation finds a bridge)."""
        if target.incident_id == other.incident_id:
            return target
        for alert in self.repository.alerts_for_incident(other.incident_id):
            self.attach_alert(target, alert)
        timeline = list(target.timeline or [])
        timeline.append(
            {
                "timestamp": utcnow().isoformat(),
                "event": "incident_merged",
                "description": f"merged {other.incident_id} ({other.title})",
            }
        )
        target.timeline = timeline
        other.status = IncidentStatus.CLOSED.value
        other.resolution = f"merged into {target.incident_id}"
        other.closed_at = utcnow()
        self.repository.session.flush()
        return target

    # ------------------------------------------------------------ lifecycle
    def set_status(
        self,
        incident_id: str,
        status: str,
        *,
        actor_id: int | None = None,
        resolution: str | None = None,
        note: str | None = None,
    ) -> Incident:
        incident = self.repository.get_incident(incident_id)
        if incident is None:
            raise RepositoryError(f"unknown incident {incident_id!r}")
        if not IncidentStatus.has(status):
            raise RepositoryError(f"invalid incident status {status!r}")
        if status != incident.status and status not in INCIDENT_TRANSITIONS.get(incident.status, set()):
            raise RepositoryError(
                f"cannot move incident {incident_id} from {incident.status} to {status}"
            )
        incident.status = status
        incident.updated_at = utcnow()
        if resolution:
            incident.resolution = resolution
        if status in {IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value}:
            incident.closed_at = utcnow()
        if actor_id is not None:
            incident.owner_id = incident.owner_id or actor_id
        timeline = list(incident.timeline or [])
        timeline.append(
            {
                "timestamp": incident.updated_at.isoformat(),
                "event": f"status_{status.lower()}",
                "description": resolution or f"status changed to {status}",
            }
        )
        incident.timeline = timeline
        self.repository.session.flush()
        if note:
            self.repository.add_note(
                incident_id=incident_id, note=note, author_id=actor_id, action_taken=status
            )
        self.repository.log_system(
            message=f"incident {incident_id} moved to {status}",
            category=LogCategory.AUDIT.value,
            actor_id=actor_id,
            details={"incident_id": incident_id, "status": status, "resolution": resolution},
        )
        return incident

    def note(self, incident_id: str, note: str, *, author_id: int | None = None,
             action_taken: str | None = None) -> Incident:
        incident = self.repository.get_incident(incident_id)
        if incident is None:
            raise RepositoryError(f"unknown incident {incident_id!r}")
        self.repository.add_note(
            incident_id=incident_id, note=note, author_id=author_id, action_taken=action_taken
        )
        timeline = list(incident.timeline or [])
        timeline.append(
            {
                "timestamp": utcnow().isoformat(),
                "event": "analyst_note",
                "description": note[:200],
            }
        )
        incident.timeline = timeline
        incident.updated_at = utcnow()
        self.repository.session.flush()
        return incident

    # -------------------------------------------------------------- status
    def statistics(self) -> dict[str, Any]:
        with self._lock:
            return {"created": self._created, "alerts_attached": self._attached}


__all__ = ["IncidentManager"]
