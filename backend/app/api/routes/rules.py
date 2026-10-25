"""Detection rule and ML model management routes (spec section 8/10).

Rules are configuration, so they are editable at runtime - but only by an
administrator, reloaded by the pipeline automatically, and every change bumps
the rule version and is written to the audit log.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...database.repository import Repository, RepositoryError
from ...services.audit import audit
from ...services.bootstrap import Runtime
from ..deps import CurrentUser, RequireAdmin, get_db, get_runtime, pagination
from ..schemas import ModelActivateRequest, Page, RuleUpdateRequest

router = APIRouter(tags=["detection"])


@router.get("/rules")
def list_rules(
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
    page: Annotated[dict, Depends(pagination)],
    enabled_only: bool = Query(default=False),
) -> Page[dict]:
    repository = Repository(session)
    rules = repository.list_rules(enabled_only=enabled_only)
    return Page[dict](items=[rule.public_dict() for rule in rules], limit=len(rules) or 1)


@router.get("/rules/{rule_key}")
def get_rule(
    rule_key: str,
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    rule = Repository(session).get_rule(rule_key)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"rule {rule_key} not found"},
        )
    return rule.public_dict()


@router.patch("/rules/{rule_key}")
def update_rule(
    rule_key: str,
    payload: RuleUpdateRequest,
    admin: Annotated[Any, RequireAdmin],
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, Any]:
    """Enable/disable a rule or tune its thresholds (ADMIN only)."""
    repository = Repository(session)
    try:
        if payload.enabled is not None:
            repository.set_rule_enabled(rule_key, payload.enabled)
        if payload.params or payload.threshold is not None or payload.window_seconds is not None:
            repository.update_rule_params(
                rule_key,
                payload.params or {},
                threshold=payload.threshold,
                window_seconds=payload.window_seconds,
            )
    except RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": str(exc)},
        ) from exc
    rule = repository.get_rule(rule_key)
    session.commit()
    runtime.rule_registry.refresh()
    audit(
        f"rule {rule_key} updated (version {rule.version})",
        actor=admin.username,
        actor_id=admin.id,
        details={
            "rule_key": rule_key,
            "enabled": rule.enabled,
            "threshold": rule.threshold,
            "window_seconds": rule.window_seconds,
            "params": rule.params,
        },
    )
    return rule.public_dict() if rule else {}


@router.get("/models")
def list_models(
    user: CurrentUser,
    runtime: Annotated[Runtime, Depends(get_runtime)],
    session: Annotated[Session, Depends(get_db)],
    minutes: int = Query(default=1440, ge=5, le=43200),
) -> dict[str, Any]:
    """Deployed model artifacts plus their measured inference behaviour."""
    artifacts = runtime.model_registry.list_models()
    active = runtime.model_registry.active()
    return {
        "active": active.to_dict() if active else None,
        "detector": runtime.detector.statistics(),
        "artifacts": [artifact.to_dict() for artifact in artifacts],
        "runtime_statistics": Repository(session).model_statistics(minutes=minutes),
    }


@router.post("/models/activate")
def activate_model(
    payload: ModelActivateRequest,
    admin: Annotated[Any, RequireAdmin],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, Any]:
    """Promote a deployed model version and hot-reload the detector."""
    target = next(
        (artifact for artifact in runtime.model_registry.list_models() if artifact.version == payload.version),
        None,
    )
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"model version {payload.version} is not deployed"},
        )
    manifest = runtime.model_registry.manifest() or {"models": []}
    manifest["active"] = target.identifier
    import json

    (runtime.paths.artifacts / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    reloaded = runtime.detector.reload()
    audit(
        f"model {target.identifier} activated",
        actor=admin.username,
        actor_id=admin.id,
        details={"version": target.version, "reloaded": reloaded},
    )
    return {"message": "model activated", "detail": {"model": target.identifier, "reloaded": reloaded}}


__all__ = ["router"]
