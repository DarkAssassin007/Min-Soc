"""Alert routes: stream/history, detail, lifecycle, assignment and notes."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...database.models import Alert
from ...database.repository import Repository, RepositoryError
from ...services.audit import audit
from ...services.bootstrap import Runtime
from ..deps import CurrentUser, RequireAnalyst, get_db, get_runtime, pagination
from ..schemas import AlertAssignRequest, AlertUpdateRequest, NoteCreateRequest, Page

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=Page[dict])
def list_alerts(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    page: Annotated[dict, Depends(pagination)],
    severity: str | None = Query(default=None, max_length=16),
    alert_status: str | None = Query(default=None, alias="status", max_length=16),
    detection_type: str | None = Query(default=None, max_length=64),
    rule_key: str | None = Query(default=None, max_length=64),
    source_ip: str | None = Query(default=None, max_length=64),
    engine: str | None = Query(default=None, max_length=16),
    incident_id: str | None = Query(default=None, max_length=32),
    min_risk: float | None = Query(default=None, ge=0, le=100),
    start: datetime | None = None,
    end: datetime | None = None,
    search: str | None = Query(default=None, max_length=128),
) -> Page[dict]:
    """Alert history with the filters the specification calls for."""
    repository = Repository(session)
    alerts = repository.list_alerts(
        limit=page["limit"],
        offset=page["offset"],
        severity=severity.upper() if severity else None,
        status=alert_status.upper() if alert_status else None,
        detection_type=detection_type,
        rule_key=rule_key,
        source_ip=source_ip,
        engine=engine,
        incident_id=incident_id,
        min_risk=min_risk,
        start=start,
        end=end,
        search=search,
    )
    total = repository.count_alerts(
        severity=severity.upper() if severity else None,
        status=alert_status.upper() if alert_status else None,
        detection_type=detection_type,
        source_ip=source_ip,
        start=start,
        end=end,
    )
    items = [alert.public_dict() for alert in alerts]
    return Page[dict](
        items=items,
        total=total,
        limit=page["limit"],
        offset=page["offset"],
        has_more=page["offset"] + len(items) < total,
    )


@router.get("/statistics")
def alert_statistics(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    minutes: int = Query(default=1440, ge=5, le=43200),
) -> dict[str, Any]:
    repository = Repository(session)
    return {
        "window_minutes": minutes,
        "totals": repository.alert_totals(minutes=minutes),
        "by_severity": repository.alerts_by_severity(minutes=minutes),
        "by_detection_type": repository.alerts_by_detection_type(minutes=minutes),
        "top_sources": repository.high_risk_sources(minutes=minutes, limit=10),
        "over_time": repository.timeseries(Alert, "last_seen", minutes=minutes, buckets=24),
    }


@router.get("/{alert_id}")
def get_alert(
    alert_id: str,
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    """Alert detail with the full Event -> Detection -> Alert trace."""
    repository = Repository(session)
    alert = repository.get_alert(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"alert {alert_id} not found"},
        )
    payload = alert.public_dict()
    detections = repository.list_detections_for_alert(alert_id)
    payload["detections"] = [detection.public_dict() for detection in detections]
    payload["events"] = []
    for detection in detections[:20]:
        event = repository.get_event(detection.event_id)
        if event is not None:
            payload["events"].append(event.to_public_dict())
    payload["notes"] = [note.public_dict() for note in repository.list_notes(alert_id=alert_id)]
    payload["incident"] = None
    if alert.incident_id:
        incident = repository.get_incident(alert.incident_id)
        payload["incident"] = incident.public_dict() if incident else None
    payload["related_alerts"] = [
        related.public_dict()
        for related in repository.alerts_for_source(alert.source_ip, minutes=1440, limit=10)
        if related.alert_id != alert_id
    ] if alert.source_ip else []
    return payload


@router.patch("/{alert_id}")
def update_alert(
    alert_id: str,
    payload: AlertUpdateRequest,
    analyst: Annotated[Any, RequireAnalyst],
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, Any]:
    """Move an alert through its lifecycle (RBAC: ANALYST or ADMIN)."""
    manager = runtime.alerts
    session_repository = Repository(session)
    manager.repository.bind(session_repository)
    try:
        alert = manager.set_status(
            alert_id,
            payload.status,
            actor_id=analyst.id,
            resolution=payload.resolution,
            note=payload.note,
        )
        data = alert.public_dict()
    except RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "invalid_transition", "message": str(exc)},
        ) from exc
    finally:
        manager.repository.unbind()
    session.commit()
    audit(
        f"alert {alert_id} status set to {payload.status}",
        actor=analyst.username,
        actor_id=analyst.id,
        details={"alert_id": alert_id, "status": payload.status, "resolution": payload.resolution},
    )
    return data


@router.post("/{alert_id}/assign")
def assign_alert(
    alert_id: str,
    payload: AlertAssignRequest,
    analyst: Annotated[Any, RequireAnalyst],
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, Any]:
    repository = Repository(session)
    if repository.get_user(payload.user_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"user {payload.user_id} not found"},
        )
    manager = runtime.alerts
    manager.repository.bind(repository)
    try:
        alert = manager.assign(alert_id, payload.user_id)
        data = alert.public_dict()
    except RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": str(exc)},
        ) from exc
    finally:
        manager.repository.unbind()
    session.commit()
    audit(
        f"alert {alert_id} assigned to user {payload.user_id}",
        actor=analyst.username,
        actor_id=analyst.id,
    )
    return data


@router.post("/{alert_id}/notes")
def add_alert_note(
    alert_id: str,
    payload: NoteCreateRequest,
    analyst: Annotated[Any, RequireAnalyst],
    session: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    repository = Repository(session)
    if repository.get_alert(alert_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"alert {alert_id} not found"},
        )
    note = repository.add_note(
        alert_id=alert_id,
        note=payload.note,
        author_id=analyst.id,
        action_taken=payload.action_taken,
    )
    session.commit()
    audit(
        f"note added to alert {alert_id}",
        actor=analyst.username,
        actor_id=analyst.id,
        details={"alert_id": alert_id},
    )
    return note.public_dict()


@router.get("/{alert_id}/notes")
def list_alert_notes(
    alert_id: str,
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
) -> Page[dict]:
    repository = Repository(session)
    notes = repository.list_notes(alert_id=alert_id)
    return Page[dict](items=[note.public_dict() for note in notes], limit=len(notes) or 1)


__all__ = ["router"]
