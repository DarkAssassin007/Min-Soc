"""WebSocket transport for real-time dashboard updates."""

from __future__ import annotations

from . import routes
from .manager import CHANNELS, Connection, ConnectionManager

__all__ = ["CHANNELS", "Connection", "ConnectionManager", "routes"]
