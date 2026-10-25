"""Threat analytics and dashboard summary routes (spec sections 15 and 18).

Every visualisation here answers a specific analyst question - "what is
attacking us", "where is it coming from", "is it getting worse" - rather than
existing to fill a page.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ...database.base import utcnow
from ...database.enums import AlertStatus, IncidentStatus
from ...database.models import Alert, Detection, Event, Incident
from ...database.repository import Repository
from ..deps import CurrentUser, get_db

router = APIRouter(tags=["analytics"])


@router.get("/threats")
def threat_overview(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    minutes: int = Query(default=1440, ge=5, le=43200),
) -> dict[str, Any]:
    """Threat-centric view: who is attacking, how, and whether it is escalating."""
    repository = Repository(session)
    return {
        "window_minutes": minutes,
        "active_alerts": repository.alert_totals(minutes=minutes),
        "top_threat_sources": repository.high_risk_sources(minutes=minutes, limit=10),
        "detection_types": repository.alerts_by_detection_type(minutes=minutes, limit=15),
        "rule_frequency": repository.detection_rule_frequency(minutes=minutes, limit=15),
        "severity_distribution": repository.alerts_by_severity(minutes=minutes),
        "targeted_ports": repository.top_destination_ports(minutes=minutes, limit=10),
        "alerts_over_time": repository.timeseries(Alert, "last_seen", minutes=minutes, buckets=24),
        "ml_anomalies": repository.model_statistics(minutes=minutes),
    }


@router.get("/analytics")
def analytics(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    minutes: int = Query(default=1440, ge=5, le=43200),
    buckets: int = Query(default=24, ge=4, le=96),
) -> dict[str, Any]:
    """Historical analytics for the Analytics and Reports pages."""
    repository = Repository(session)
    return {
        "window_minutes": minutes,
        "events_over_time": repository.timeseries(Event, "timestamp", minutes=minutes, buckets=buckets),
        "alerts_over_time": repository.timeseries(Alert, "last_seen", minutes=minutes, buckets=buckets),
        "detections_over_time": repository.timeseries(
            Detection, "matched_at", minutes=minutes, buckets=buckets
        ),
        "severity_distribution": repository.severity_distribution(Alert, minutes=minutes),
        "detection_type_distribution": repository.alerts_by_detection_type(minutes=minutes),
        "protocol_distribution": repository.event_volume_by_protocol(minutes=minutes),
        "top_source_ips": repository.top_source_ips(minutes=minutes, limit=10),
        "top_destination_ips": repository.top_destination_ips(minutes=minutes, limit=10),
        "top_attacked_ports": repository.top_destination_ports(minutes=minutes, limit=10),
        "rule_frequency": repository.detection_rule_frequency(minutes=minutes, limit=15),
        "anomaly_distribution": repository.model_statistics(minutes=minutes),
        "incidents_by_severity": repository.severity_distribution(Incident, minutes=minutes),
    }


@router.get("/dashboard/summary")
def dashboard_summary(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    minutes: int = Query(default=1440, ge=5, le=43200),
) -> dict[str, Any]:
    """Overview page payload: totals, rates and the most recent activity."""
    repository = Repository(session)
    open_alert_states = [
        AlertStatus.NEW.value,
        AlertStatus.ACKNOWLEDGED.value,
        AlertStatus.INVESTIGATING.value,
    ]
    open_incident_states = [
        IncidentStatus.OPEN.value,
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.CONTAINED.value,
    ]
    totals = repository.alert_totals(minutes=minutes)
    incidents = repository.incident_totals()
    recent_alerts = repository.list_alerts(limit=10)
    recent_events = repository.list_events(limit=15)
    return {
        "generated_at": utcnow().isoformat(),
        "window_minutes": minutes,
        "events": {
            "total": repository.count_events(),
            "last_24h": repository.count_events(start=utcnow() - timedelta(minutes=minutes)),
            "per_second": repository.events_per_second(seconds=60),
        },
        "alerts": {
            **totals,
            "open": repository.count_alerts(status=open_alert_states[0]),
            "acknowledged": repository.count_alerts(status=open_alert_states[1]),
            "investigating": repository.count_alerts(status=open_alert_states[2]),
            "open_total": sum(repository.count_alerts(status=state) for state in open_alert_states),
        },
        "incidents": {**incidents, "open_list": list(open_incident_states)},
        "high_risk_sources": repository.high_risk_sources(minutes=minutes, limit=5),
        "network_activity": repository.timeseries(Event, "timestamp", minutes=minutes, buckets=12),
        "threat_activity": repository.timeseries(Alert, "last_seen", minutes=minutes, buckets=12),
        "severity_distribution": repository.alerts_by_severity(minutes=minutes),
        "recent_alerts": [alert.public_dict() for alert in recent_alerts],
        "recent_events": [event.to_public_dict() for event in recent_events],
        "detection_types": repository.alerts_by_detection_type(minutes=minutes, limit=8),
        "models": repository.model_statistics(minutes=minutes) or [],
    }


__all__ = ["router"]
