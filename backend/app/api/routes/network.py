"""Network routes: traffic view, statistics and asset inventory."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from ...database.models import Event
from ...database.repository import Repository
from ...services.audit import audit
from ..deps import CurrentUser, RequireAnalyst, get_db, pagination
from ..schemas import Page

router = APIRouter(prefix="/network", tags=["network"])


class AssetUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str | None = Field(default=None, max_length=255)
    asset_type: str | None = Field(default=None, max_length=32)
    importance: int | None = Field(default=None, ge=1, le=5)
    tags: list[str] | None = Field(default=None, max_length=20)
    notes: str | None = Field(default=None, max_length=2000)


@router.get("/traffic")
def network_traffic(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    minutes: int = Query(default=60, ge=5, le=1440),
    buckets: int = Query(default=24, ge=4, le=96),
) -> dict[str, Any]:
    """Traffic over time plus the noisiest talkers (Network page)."""
    repository = Repository(session)
    return {
        "window_minutes": minutes,
        "buckets": buckets,
        "events_over_time": repository.timeseries(
            Event, "timestamp", minutes=minutes, buckets=buckets
        ),
        "by_protocol": repository.event_volume_by_protocol(minutes=minutes),
        "top_sources": repository.top_source_ips(minutes=minutes, limit=10),
        "top_destinations": repository.top_destination_ips(minutes=minutes, limit=10),
        "top_destination_ports": repository.top_destination_ports(minutes=minutes, limit=10),
        "high_risk_sources": repository.high_risk_sources(minutes=minutes, limit=10),
        "events_per_second": repository.events_per_second(seconds=60),
    }


@router.get("/statistics")
def network_statistics(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    minutes: int = Query(default=1440, ge=5, le=43200),
) -> dict[str, Any]:
    repository = Repository(session)
    return {
        "window_minutes": minutes,
        "total_events": repository.count_events(start=None),
        "events_per_second": repository.events_per_second(seconds=300),
        "severity_distribution": repository.severity_distribution(Event, minutes=minutes),
        "event_type_distribution": repository.distribution(Event.event_type, minutes=minutes),
        "protocol_distribution": repository.event_volume_by_protocol(minutes=minutes),
        "connection_state_distribution": repository.distribution(
            Event.connection_state, minutes=minutes
        ),
        "direction_distribution": repository.distribution(Event.direction, minutes=minutes),
        "collectors": repository.distribution(Event.collector, minutes=minutes),
    }


@router.get("/assets")
def list_assets(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    page: Annotated[dict, Depends(pagination)],
) -> Page[dict]:
    repository = Repository(session)
    assets = repository.list_assets(limit=page["limit"])
    return Page[dict](items=[asset.public_dict() for asset in assets], limit=page["limit"])


@router.put("/assets/{ip_address}")
def update_asset(
    ip_address: str,
    payload: AssetUpdateRequest,
    analyst: Annotated[Any, RequireAnalyst],
    session: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    """Register or update an asset (drives the asset-importance risk signal)."""
    repository = Repository(session)
    import ipaddress

    try:
        ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_ip", "message": str(exc)},
        ) from exc
    asset = repository.upsert_asset(
        ip_address,
        hostname=payload.hostname,
        asset_type=payload.asset_type,
        importance=payload.importance,
        tags=payload.tags,
        notes=payload.notes,
    )
    session.commit()
    audit(
        f"asset {ip_address} updated",
        actor=analyst.username,
        actor_id=analyst.id,
        details={"importance": payload.importance},
    )
    return asset.public_dict()


__all__ = ["AssetUpdateRequest", "router"]
