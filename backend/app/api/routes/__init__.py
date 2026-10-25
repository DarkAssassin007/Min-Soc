"""API router aggregation."""

from __future__ import annotations

from fastapi import APIRouter

from . import (
    admin,
    alerts,
    analytics,
    auth,
    events,
    incidents,
    network,
    rules,
    system,
)

#: Every versioned API router, in a stable order.
ROUTERS = [
    auth.router,
    events.router,
    alerts.router,
    incidents.router,
    network.router,
    analytics.router,
    rules.router,
    system.router,
    admin.router,
]


def api_router() -> APIRouter:
    """Build the ``/api/v1`` router tree."""
    router = APIRouter()
    for module_router in ROUTERS:
        router.include_router(module_router)
    return router


__all__ = [
    "ROUTERS",
    "admin",
    "alerts",
    "analytics",
    "api_router",
    "auth",
    "events",
    "incidents",
    "network",
    "rules",
    "system",
]
