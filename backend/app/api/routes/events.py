"""Event routes: history, detail, related context and detections."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...database.repository import Repository
from ..deps import CurrentUser, get_db, pagination
from ..schemas import Page

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=Page[dict])
def list_events(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    page: Annotated[dict, Depends(pagination)],
    source_ip: str | None = Query(default=None, max_length=64),
    destination_ip: str | None = Query(default=None, max_length=64),
    severity: str | None = Query(default=None, max_length=16),
    event_type: str | None = Query(default=None, max_length=32),
    protocol: str | None = Query(default=None, max_length=16),
    collector: str | None = Query(default=None, max_length=32),
    min_risk: float | None = Query(default=None, ge=0, le=100),
    start: datetime | None = None,
    end: datetime | None = None,
    search: str | None = Query(default=None, max_length=128),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[dict]:
    """Paginated event history with analyst filters."""
    repository = Repository(session)
    filters = {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "severity": severity.upper() if severity else None,
        "event_type": event_type,
        "protocol": protocol.upper() if protocol else None,
        "collector": collector,
        "min_risk": min_risk,
        "start": start,
        "end": end,
        "search": search,
    }
    events = repository.list_events(limit=page["limit"], offset=page["offset"], order=order, **filters)
    total = repository.count_events(**filters)
    items = [event.to_public_dict() for event in events]
    return Page[dict](
        items=items,
        total=total,
        limit=page["limit"],
        offset=page["offset"],
        has_more=page["offset"] + len(items) < total,
    )


@router.get("/{event_id}")
def get_event(
    event_id: str,
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    """Full event detail including detections and protocol metadata."""
    repository = Repository(session)
    event = repository.get_event(event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"event {event_id} not found"},
        )
    network = repository.network_event_for(event_id)
    detections = repository.list_detections_for_event(event_id)
    payload = event.to_public_dict()
    payload["detections"] = [detection.public_dict() for detection in detections]
    payload["network"] = (
        {
            "tcp_flags": network.tcp_flags,
            "dns_query": network.dns_query,
            "dns_qtype": network.dns_qtype,
            "dns_rcode": network.dns_rcode,
            "http_host": network.http_host,
            "http_method": network.http_method,
            "tls_sni": network.tls_sni,
            "icmp_type": network.icmp_type,
            "arp_op": network.arp_op,
            "duration_ms": network.duration_ms,
            "capture_source": network.capture_source,
            "interface": network.interface,
        }
        if network
        else None
    )
    return payload


@router.get("/{event_id}/detections")
def event_detections(
    event_id: str,
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
) -> Page[dict]:
    repository = Repository(session)
    if repository.get_event(event_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"event {event_id} not found"},
        )
    detections = repository.list_detections_for_event(event_id)
    return Page[dict](items=[d.public_dict() for d in detections], limit=len(detections) or 1)


@router.get("/{event_id}/related")
def related_events(
    event_id: str,
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    minutes: int = Query(default=60, ge=1, le=1440),
    limit: int = Query(default=50, ge=1, le=200),
) -> Page[dict]:
    """Other events involving the same source entity (investigation context)."""
    repository = Repository(session)
    event = repository.get_event(event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"event {event_id} not found"},
        )
    entity = event.source_ip or event.destination_ip
    if not entity:
        return Page[dict](items=[], limit=limit)
    related = repository.related_events_for_ip(
        entity, minutes=minutes, limit=limit, exclude_event_id=event_id
    )
    return Page[dict](items=[item.to_public_dict() for item in related], limit=limit)


__all__ = ["router"]
