"""Operational routes: health, readiness, metrics, logs, collectors, maintenance."""

from __future__ import annotations

import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ... import __version__
from ...collectors.network.synthetic import SCENARIOS, SyntheticCollector
from ...database.connection import healthcheck as db_healthcheck
from ...database.repository import Repository
from ...services.audit import audit
from ...services.bootstrap import Runtime
from ..deps import CurrentUser, RequireAdmin, get_db, get_runtime, pagination
from ..schemas import MessageResponse, Page

router = APIRouter(tags=["system"])

_STARTED_AT = time.time()


@router.get("/system/health")
def system_health(
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, Any]:
    """Detailed health probe (no authentication: used by orchestrators)."""
    database = db_healthcheck()
    pipeline = runtime.pipeline.status()
    detector = runtime.detector.statistics()
    components = {
        "database": database["status"],
        "pipeline": "ok" if pipeline["running"] else "stopped",
        "anomaly_model": "ok" if detector["ready"] else "unavailable",
        "collectors": {
            name: ("ok" if info["running"] else "unavailable")
            for name, info in pipeline["collectors"].items()
        },
    }
    overall = "ok"
    if components["database"] != "ok":
        overall = "error"
    elif components["pipeline"] != "ok":
        overall = "degraded"
    return {
        "status": overall,
        "version": __version__,
        "environment": runtime.settings.env,
        "uptime_seconds": round(time.time() - _STARTED_AT, 1),
        "components": components,
        "database": database,
        "warnings": runtime.warnings,
    }


@router.get("/system/ready")
def system_ready(
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, Any]:
    """Readiness: can this instance serve traffic?"""
    database = db_healthcheck()
    ready = database["status"] == "ok"
    if not ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "not_ready", "database": database},
        )
    return {"status": "ready", "database": database, "pipeline": runtime.pipeline.running}


@router.get("/system/metrics")
def system_metrics(
    runtime: Annotated[Runtime, Depends(get_runtime)],
    session: Annotated[Session, Depends(get_db)],
    history: int = Query(default=60, ge=0, le=1000),
) -> dict[str, Any]:
    """Live performance counters plus persisted history."""
    snapshot = runtime.pipeline.metrics_snapshot()
    snapshot["detection"] = runtime.engine.statistics()
    snapshot["risk"] = runtime.risk.statistics()
    snapshot["alerts"] = runtime.alerts.statistics()
    snapshot["incidents"] = runtime.incidents.statistics()
    snapshot["correlation"] = runtime.correlator.statistics()
    snapshot["pipeline"] = runtime.pipeline.status()
    snapshot["websocket"] = getattr(
        getattr(runtime, "websocket_manager", None), "statistics", lambda: {}
    )()
    snapshot["history"] = [
        item.public_dict() for item in Repository(session).metrics_series(limit=history)
    ] if history else []
    return snapshot


@router.get("/system/collectors")
def collectors_status(
    user: CurrentUser,
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> Page[dict]:
    statuses = [collector.status() for collector in runtime.pipeline.collectors]
    return Page[dict](items=statuses, limit=len(statuses) or 1)


@router.get("/system/logs")
def system_logs(
    admin: Annotated[Any, RequireAdmin],
    session: Annotated[Session, Depends(get_db)],
    page: Annotated[dict, Depends(pagination)],
    level: str | None = Query(default=None, max_length=16),
    category: str | None = Query(default=None, max_length=16),
    search: str | None = Query(default=None, max_length=128),
) -> Page[dict]:
    """Operational/audit log from the database (ADMIN only)."""
    repository = Repository(session)
    entries = repository.list_system_logs(
        limit=page["limit"], offset=page["offset"], level=level, category=category, search=search
    )
    return Page[dict](
        items=[entry.public_dict() for entry in entries],
        limit=page["limit"],
        offset=page["offset"],
    )


@router.get("/system/audit")
def audit_trail(
    admin: Annotated[Any, RequireAdmin],
    session: Annotated[Session, Depends(get_db)],
    page: Annotated[dict, Depends(pagination)],
) -> Page[dict]:
    """Security-relevant audit entries only."""
    repository = Repository(session)
    entries = repository.list_system_logs(limit=page["limit"], offset=page["offset"], category="AUDIT")
    return Page[dict](items=[entry.public_dict() for entry in entries], limit=page["limit"])


@router.post("/system/maintenance/purge")
def purge_retention(
    admin: Annotated[Any, RequireAdmin],
    session: Annotated[Session, Depends(get_db)],
    days: int = Query(default=30, ge=1, le=3650),
    dry_run: bool = Query(default=True),
) -> MessageResponse:
    """Delete data older than the retention window (dry-run by default)."""
    repository = Repository(session)
    counts = repository.purge_older_than(days=days, dry_run=dry_run)
    session.commit()
    audit(
        f"retention purge {'previewed' if dry_run else 'executed'} for data older than {days} days",
        actor=admin.username,
        actor_id=admin.id,
        details={"days": days, "dry_run": dry_run, "counts": counts},
    )
    return MessageResponse(
        message="retention preview" if dry_run else "retention purge complete",
        detail={"days": days, "dry_run": dry_run, "counts": counts},
    )


@router.post("/system/simulator")
def control_simulator(
    admin: Annotated[Any, RequireAdmin],
    runtime: Annotated[Runtime, Depends(get_runtime)],
    scenario: str = Query(default="normal"),
    eps: float = Query(default=5.0, ge=0.1, le=500),
    action: str = Query(default="start", pattern="^(start|stop)$"),
) -> MessageResponse:
    """Start/stop the authorized-lab synthetic event generator.

    This exists so a deployment can be validated end to end (spec section 32)
    without touching production traffic. ADMIN only, and every use is audited.

    Mini SOC is real-time only: the generator is refused unless the operator
    has explicitly opted in with ``MINI_SOC_SIMULATOR_ENABLED=true`` on an
    isolated lab host, so no deployment can quietly mix fabricated events into
    a production dashboard. The offline lab scripts
    (``scripts/lab_validation.py``, ``scripts/benchmark_pipeline.py``) keep
    their own isolated databases and are unaffected.
    """
    if not runtime.settings.simulator_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "simulator_disabled",
                "message": (
                    "this deployment is real-time only; the authorized-lab event "
                    "generator requires MINI_SOC_SIMULATOR_ENABLED=true"
                ),
            },
        )

    if scenario not in SCENARIOS and action == "start":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_scenario", "message": f"scenario must be one of {list(SCENARIOS)}"},
        )

    existing = [
        collector for collector in runtime.pipeline.collectors if collector.name == "synthetic"
    ]
    if action == "stop":
        for collector in existing:
            collector.stop()
            runtime.pipeline.collectors.remove(collector)
        audit(f"synthetic generator stopped by {admin.username}", actor=admin.username, actor_id=admin.id)
        return MessageResponse(message="simulator stopped", detail={"scenario": scenario})

    for collector in existing:
        collector.stop()
        runtime.pipeline.collectors.remove(collector)
    collector = SyntheticCollector(runtime.pipeline.submit, eps=eps, scenario=scenario)
    runtime.pipeline.attach_collector(collector)
    started = collector.start()
    audit(
        f"synthetic generator started ({scenario} @ {eps} eps) by {admin.username}",
        actor=admin.username,
        actor_id=admin.id,
        details={"scenario": scenario, "eps": eps, "started": started},
    )
    return MessageResponse(
        message="simulator started" if started else "simulator failed to start",
        detail=collector.status(),
    )


__all__ = ["router"]
