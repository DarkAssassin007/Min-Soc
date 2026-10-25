"""WebSocket fan-out (spec section 14).

Channels:

* ``/ws/live``    - normalised events as they are stored
* ``/ws/alerts``  - alert created/updated stream
* ``/ws/network`` - network/volume aggregates (lower frequency)

Delivery strategy per client:

* a bounded outbound queue per connection, so a stalled browser cannot slow the
  pipeline down (slow consumers lose events and are told how many);
* the pipeline publishes from *worker threads*, so the manager hops back onto
  the event loop with ``call_soon_threadsafe``;
* connections are authenticated before subscribing, and dead sockets are pruned
  on every broadcast.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from ...config.logging_config import get_logger

logger = get_logger(__name__)

CHANNELS = ("live", "alerts", "network")


@dataclass
class Connection:
    """One authenticated dashboard connection."""

    id: str
    channel: str
    websocket: Any
    user: str | None = None
    role: str | None = None
    queue: "asyncio.Queue[str]" = field(default_factory=lambda: asyncio.Queue(maxsize=500))
    connected_at: float = field(default_factory=time.time)
    sent: int = 0
    dropped: int = 0
    queue_depth_samples: deque[int] = field(default_factory=lambda: deque(maxlen=50))

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "channel": self.channel,
            "user": self.user,
            "role": self.role,
            "connected_at": self.connected_at,
            "sent": self.sent,
            "dropped": self.dropped,
        }


class ConnectionManager:
    """Thread-safe registry of live dashboard connections."""

    def __init__(self, *, max_connections: int = 200, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self.max_connections = max_connections
        self._connections: dict[str, Connection] = {}
        self._lock = threading.RLock()
        self._loop: asyncio.AbstractEventLoop | None = loop
        self._delivered = 0
        self._dropped = 0
        self._broadcasts = 0

    # ---------------------------------------------------------------- setup
    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    @property
    def loop(self) -> asyncio.AbstractEventLoop | None:
        return self._loop

    # ----------------------------------------------------------- lifecycle
    def register(self, connection: Connection) -> bool:
        with self._lock:
            if len(self._connections) >= self.max_connections:
                logger.warning(
                    "websocket connection refused: limit reached",
                    extra={"limit": self.max_connections},
                )
                return False
            self._connections[connection.id] = connection
        logger.info(
            "websocket connected",
            extra={"channel": connection.channel, "user": connection.user, "id": connection.id},
        )
        return True

    def unregister(self, connection_id: str) -> None:
        with self._lock:
            connection = self._connections.pop(connection_id, None)
        if connection is not None:
            logger.info(
                "websocket disconnected",
                extra={"channel": connection.channel, "user": connection.user, "sent": connection.sent},
            )

    def count(self, channel: str | None = None) -> int:
        with self._lock:
            if channel is None:
                return len(self._connections)
            return sum(1 for conn in self._connections.values() if conn.channel == channel)

    def connections(self) -> list[dict[str, Any]]:
        with self._lock:
            return [conn.as_dict() for conn in self._connections.values()]

    # ----------------------------------------------------------- delivery
    def _serialise(self, payload: dict[str, Any]) -> str:
        return json.dumps(payload, default=str)

    def publish(self, channel: str, payload: dict[str, Any]) -> int:
        """Queue a payload for every subscriber of ``channel`` (thread safe)."""
        with self._lock:
            targets = [conn for conn in self._connections.values() if conn.channel == channel]
            self._broadcasts += 1
        if not targets:
            return 0
        message = self._serialise(payload)
        delivered = 0
        for connection in targets:
            try:
                connection.queue.put_nowait(message)
                connection.sent += 1
                delivered += 1
                self._delivered += 1
            except asyncio.QueueFull:
                connection.dropped += 1
                self._dropped += 1
                logger.debug(
                    "websocket consumer too slow - dropping message",
                    extra={"channel": channel, "user": connection.user},
                )
        return delivered

    def broadcast_threadsafe(self, channel: str, payload: dict[str, Any]) -> None:
        """Entry point used by collector/pipeline threads."""
        loop = self._loop
        if loop is None or loop.is_closed():
            # No running loop (e.g. during unit tests) - publish synchronously.
            self.publish(channel, payload)
            return
        try:
            loop.call_soon_threadsafe(self.publish, channel, payload)
        except RuntimeError:  # pragma: no cover - loop shutting down
            logger.debug("event loop closed while broadcasting", extra={"channel": channel})

    async def sender(self, connection: Connection) -> None:
        """Per-connection writer task."""
        while True:
            message = await connection.queue.get()
            await connection.websocket.send_text(message)

    # -------------------------------------------------------------- stats
    def statistics(self) -> dict[str, Any]:
        with self._lock:
            per_channel = {channel: 0 for channel in CHANNELS}
            for connection in self._connections.values():
                per_channel[connection.channel] = per_channel.get(connection.channel, 0) + 1
            slowest = sorted(
                self._connections.values(), key=lambda conn: conn.dropped, reverse=True
            )[:3]
            return {
                "connections": len(self._connections),
                "per_channel": per_channel,
                "messages_delivered": self._delivered,
                "messages_dropped": self._dropped,
                "broadcasts": self._broadcasts,
                "max_connections": self.max_connections,
                "slowest_consumers": [conn.as_dict() for conn in slowest if conn.dropped],
            }

    async def close_all(self) -> None:
        with self._lock:
            connections = list(self._connections.values())
            self._connections.clear()
        for connection in connections:
            try:
                await connection.websocket.close(code=1001)
            except Exception:  # pragma: no cover - shutdown best effort
                pass


__all__ = ["CHANNELS", "Connection", "ConnectionManager"]
