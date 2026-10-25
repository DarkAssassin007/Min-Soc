"""Incident routes: list, detail, lifecycle, analyst notes and manual creation."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...database.models import Incident
from ...database.repository import Repository, RepositoryError
from ...services.audit import audit
from ...services.bootstrap import Runtime
from ..deps import CurrentUser, RequireAnalyst, get_db, get_runtime, pagination
from ..schemas import IncidentCreateRequest, IncidentUpdateRequest, NoteCreateRequest, Page

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=Page[dict])
def list_incidents(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    page: Annotated[dict, Depends(pagination)],
    incident_status: str | None = Query(default=None, alias="status", max_length=16),
    severity: str | None = Query(default=None, max_length=16),
    search: str | None = Query(default=None, max_length=128),
) -> Page[dict]:
    repository = Repository(session)
    incidents = repository.list_incidents(
        limit=page["limit"],
        offset=page["offset"],
        status=incident_status.upper() if incident_status else None,
        severity=severity.upper() if severity else None,
        search=search,
    )
    items = [incident.public_dict() for incident in incidents]
    totals = repository.incident_totals()
    return Page[dict](
        items=items,
        total=totals["total"],
        limit=page["limit"],
        offset=page["offset"],
        has_more=page["offset"] + len(items) < totals["total"],
    )


@router.get("/statistics")
def incident_statistics(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    minutes: int = Query(default=1440, ge=5, le=43200),
) -> dict[str, Any]:
    repository = Repository(session)
    return {
        "totals": repository.incident_totals(),
        "by_severity": repository.severity_distribution(Incident, minutes=minutes),
        "over_time": repository.timeseries(Incident, "created_at", minutes=minutes, buckets=24),
    }


@router.get("/{incident_id}")
def get_incident(
    incident_id: str,
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    repository = Repository(session)
    incident = repository.get_incident(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"incident {incident_id} not found"},
        )
    payload = incident.public_dict()
    payload["alerts"] = [alert.public_dict() for alert in repository.alerts_for_incident(incident_id)]
    payload["notes"] = [note.public_dict() for note in repository.list_notes(incident_id=incident_id)]
    return payload


@router.post("", status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreateRequest,
    analyst: Annotated[Any, RequireAnalyst],
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, Any]:
    """Manually escalate one or more alerts into an incident."""
    repository = Repository(session)
    alerts = []
    for alert_id in payload.alert_ids:
        alert = repository.get_alert(alert_id)
        if alert is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "not_found", "message": f"alert {alert_id} not found"},
            )
        alerts.append(alert)

    manager = runtime.incidents
    manager.repository.bind(repository)
    try:
        incident = manager.create(
            title=payload.title,
            severity=payload.severity,
            risk_score=max((float(alert.risk_score or 0) for alert in alerts), default=0.0),
            summary=payload.summary,
            source_entities=[alert.source_ip for alert in alerts if alert.source_ip],
            destination_entities=[alert.destination_ip for alert in alerts if alert.destination_ip],
            detection_types=[alert.detection_type for alert in alerts],
            owner_id=analyst.id,
        )
        for alert in alerts:
            manager.attach_alert(incident, alert)
        data = incident.public_dict()
    finally:
        manager.repository.unbind()
    session.commit()
    audit(
        f"incident {data['incident_id']} created manually",
        actor=analyst.username,
        actor_id=analyst.id,
        details={"alerts": payload.alert_ids},
    )
    return data


@router.patch("/{incident_id}")
def update_incident(
    incident_id: str,
    payload: IncidentUpdateRequest,
    analyst: Annotated[Any, RequireAnalyst],
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, Any]:
    manager = runtime.incidents
    manager.repository.bind(Repository(session))
    try:
        incident = manager.set_status(
            incident_id,
            payload.status,
            actor_id=analyst.id,
            resolution=payload.resolution,
            note=payload.note,
        )
        data = incident.public_dict()
    except RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "invalid_transition", "message": str(exc)},
        ) from exc
    finally:
        manager.repository.unbind()
    session.commit()
    audit(
        f"incident {incident_id} status set to {payload.status}",
        actor=analyst.username,
        actor_id=analyst.id,
        details={"incident_id": incident_id, "resolution": payload.resolution},
    )
    return data


@router.post("/{incident_id}/notes")
def add_incident_note(
    incident_id: str,
    payload: NoteCreateRequest,
    analyst: Annotated[Any, RequireAnalyst],
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, Any]:
    manager = runtime.incidents
    manager.repository.bind(Repository(session))
    try:
        manager.note(incident_id, payload.note, author_id=analyst.id, action_taken=payload.action_taken)
    except RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": str(exc)},
        ) from exc
    finally:
        manager.repository.unbind()
    session.commit()
    audit(f"note added to incident {incident_id}", actor=analyst.username, actor_id=analyst.id)
    notes = Repository(session).list_notes(incident_id=incident_id)
    return notes[0].public_dict() if notes else {}


__all__ = ["router"]
