"""WebSocket endpoints: ``/ws/live``, ``/ws/alerts``, ``/ws/network``.

Authentication happens during the handshake: the client presents its access
token either as an ``Authorization: Bearer`` header (preferred) or as a
``token`` query parameter (needed because browser WebSocket clients cannot set
headers). The token is validated *before* the socket is accepted, and an
unauthorised handshake is closed with 4401 instead of silently streaming data.
"""

from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from ...config.logging_config import get_logger
from ...database.connection import get_session_factory
from ...database.repository import Repository
from ...security.tokens import TokenError, decode_access_token
from ...services.audit import audit
from ..deps import client_key
from .manager import Connection, ConnectionManager

logger = get_logger(__name__)

router = APIRouter()

CLOSE_UNAUTHORIZED = 4401
CLOSE_NOT_AVAILABLE = 4503


def _authenticate(websocket: WebSocket, manager: ConnectionManager) -> tuple[str, str] | None:
    """Validate the handshake credentials; returns (username, role)."""
    runtime = getattr(websocket.app.state, "runtime", None)
    if runtime is None:
        return None
    token: str | None = None
    header = websocket.headers.get("authorization")
    if header and header.lower().startswith("bearer "):
        token = header.split(" ", 1)[1].strip()
    if not token:
        token = websocket.query_params.get("token")
    if not token:
        return None
    try:
        payload = decode_access_token(
            token,
            secret=runtime.settings.resolved_jwt_secret(),
            algorithms={runtime.settings.jwt_algorithm},
        )
    except TokenError as exc:
        logger.info("websocket authentication failed", extra={"reason": str(exc)})
        return None
    session = get_session_factory()()
    try:
        user = Repository(session).get_user_by_username(str(payload.get("sub") or ""))
        if user is None or not user.is_active:
            return None
        return user.username, user.role
    finally:
        session.close()


async def _serve(websocket: WebSocket, manager: ConnectionManager, channel: str) -> None:
    if manager.count() >= manager.max_connections:
        await websocket.close(code=CLOSE_NOT_AVAILABLE, reason="connection limit reached")
        return
    identity = _authenticate(websocket, manager)
    if identity is None:
        await websocket.close(code=CLOSE_UNAUTHORIZED, reason="authentication required")
        return
    username, role = identity
    await websocket.accept()
    connection = Connection(
        id=uuid.uuid4().hex[:12],
        channel=channel,
        websocket=websocket,
        user=username,
        role=role,
    )
    if not manager.register(connection):
        await websocket.close(code=CLOSE_NOT_AVAILABLE, reason="connection limit reached")
        return

    audit(
        f"websocket {channel} connected for {username}",
        category="WEBSOCKET",
        actor=username,
        persist=False,
    )
    sender = asyncio.create_task(manager.sender(connection))
    try:
        await websocket.send_text(
            f'{{"type":"welcome","data":{{"channel":"{channel}","user":"{username}","role":"{role}"}}}}'
        )
        if channel == "network":
            await websocket.send_text(_network_snapshot())
        while True:
            # The client only sends keep-alive pings; anything else is ignored.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # pragma: no cover - transport level failures
        logger.debug("websocket terminated", extra={"channel": channel, "error": str(exc)})
    finally:
        sender.cancel()
        manager.unregister(connection.id)


def _network_snapshot() -> str:
    import json

    from ...database.connection import session_scope
    from ...database.models import Event

    with session_scope() as session:
        repository = Repository(session)
        snapshot = {
            "type": "network.snapshot",
            "data": {
                "events_per_second": repository.events_per_second(seconds=60),
                "by_protocol": repository.event_volume_by_protocol(minutes=60),
                "top_sources": repository.top_source_ips(minutes=60, limit=10),
                "top_destination_ports": repository.top_destination_ports(minutes=60, limit=10),
                "over_time": repository.timeseries(Event, "timestamp", minutes=60, buckets=12),
            },
        }
    return json.dumps(snapshot, default=str)


@router.websocket("/ws/live")
async def ws_live(websocket: WebSocket, token: str | None = Query(default=None)) -> None:
    """Live stream of normalised events."""
    from ...services.bootstrap import Runtime  # noqa: F401  (typing clarity)

    manager: ConnectionManager = websocket.app.state.websocket_manager
    await _serve(websocket, manager, "live")


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket, token: str | None = Query(default=None)) -> None:
    """Live alert stream (created/updated)."""
    manager: ConnectionManager = websocket.app.state.websocket_manager
    await _serve(websocket, manager, "alerts")


@router.websocket("/ws/network")
async def ws_network(websocket: WebSocket, token: str | None = Query(default=None)) -> None:
    """Network aggregate stream (lower frequency, still push based)."""
    manager: ConnectionManager = websocket.app.state.websocket_manager
    await _serve(websocket, manager, "network")


__all__ = ["CLOSE_NOT_AVAILABLE", "CLOSE_UNAUTHORIZED", "router"]
