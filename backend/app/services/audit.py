"""Audit logging service (spec sections 25/27).

Two sinks for every auditable action:

* the rotating JSON log file (forensics, shipping to a SIEM), and
* the ``system_logs`` table (visible in the dashboard with the audit trail an
  analyst needs to answer "who acknowledged that alert?").

Audit writes must never break the request they describe: failures are logged
and swallowed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..config.logging_config import get_logger, request_id_var
from ..database.connection import session_scope
from ..database.enums import LogCategory
from ..database.repository import Repository

logger = get_logger(__name__)

_AUDIT_LOGGER = get_logger("mini_soc.audit")


def audit(
    event: str,
    *,
    category: str = LogCategory.AUDIT.value,
    level: str = "INFO",
    actor: str | None = None,
    actor_id: int | None = None,
    source: str | None = None,
    details: dict[str, Any] | None = None,
    persist: bool = True,
) -> None:
    """Record an auditable action."""
    payload = dict(details or {})
    payload.setdefault("event", event)
    request_id = request_id_var.get()
    _AUDIT_LOGGER.log(
        {"INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}.get(level.upper(), 20),
        event,
        extra={"actor": actor, "audit": True, "request_id": request_id, **payload},
    )
    if not persist:
        return
    try:
        with session_scope() as session:
            Repository(session).log_system(
                message=event,
                level=level.upper(),
                category=category,
                actor=actor,
                actor_id=actor_id,
                request_id=request_id,
                source=source,
                details=payload,
            )
    except Exception as exc:  # pragma: no cover - auditing must never break the caller
        logger.warning("audit persistence failed", extra={"error": str(exc), "event": event})


def security_event(event: str, *, level: str = "WARNING", **kwargs: Any) -> None:
    """Shortcut for security-relevant audit entries (auth failures, blocks)."""
    audit(event, category=LogCategory.AUTH.value, level=level, **kwargs)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["audit", "security_event", "utc_timestamp"]
