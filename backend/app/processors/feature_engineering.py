"""Feature extraction: behavioural signals per source entity.

Detection rules and the ML model both need "what has this host been doing
lately", not just the current packet. This module keeps a bounded sliding
window per source IP and derives exactly the features the specification lists:
connection frequency, unique destination ports/IPs, failed connections, DNS
request frequency, byte/packet volume and time-of-day activity.
"""

from __future__ import annotations

import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque

from ..config.logging_config import get_logger
from ..database.base import utcnow
from ..database.enums import ConnectionState, EventType
from .models import FeatureVector, NormalizedEvent

logger = get_logger(__name__)

#: Feature order consumed by the ML model (must stay stable across versions).
FEATURE_ORDER: list[str] = [
    "connection_count",
    "unique_destination_ports",
    "unique_destination_ips",
    "failed_connections",
    "dns_requests",
    "unique_dns_queries",
    "auth_failures",
    "bytes_total",
    "packets_total",
    "bytes_per_second",
    "packets_per_second",
    "avg_connection_duration_ms",
    "unique_protocols",
    "events_per_minute",
]

#: Activity outside this local-hour window counts as "off hours".
BUSINESS_HOURS = range(8, 19)


@dataclass
class _Observation:
    timestamp: datetime
    destination_ip: str | None
    destination_port: int | None
    protocol: str
    bytes: int
    packets: int
    connection_state: str
    event_type: str
    dns_query: str | None
    duration_ms: float | None


@dataclass
class _EntityWindow:
    observations: Deque[_Observation] = field(default_factory=deque)
    bytes_total: int = 0
    packets_total: int = 0


class FeatureExtractor:
    """Bounded, thread-safe sliding-window feature store."""

    def __init__(
        self,
        *,
        window_seconds: int = 300,
        max_entities: int = 5000,
        max_observations: int = 2000,
    ) -> None:
        self.window_seconds = max(int(window_seconds), 30)
        self.max_entities = max(int(max_entities), 64)
        self.max_observations = max(int(max_observations), 1)
        self._entities: "OrderedDict[str, _EntityWindow]" = OrderedDict()
        self._lock = threading.RLock()
        self.observations_seen = 0

    # ------------------------------------------------------------ ingest
    def add_event(self, event: NormalizedEvent) -> None:
        entity = event.source_ip or event.destination_ip
        if not entity:
            return
        observation = _Observation(
            timestamp=event.timestamp,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            protocol=event.protocol,
            bytes=int(event.bytes or 0),
            packets=int(event.packet_count or 0),
            connection_state=event.connection_state,
            event_type=event.event_type,
            dns_query=(event.network or {}).get("dns_query"),
            duration_ms=_optional_float((event.network or {}).get("duration_ms")),
        )
        now = utcnow()
        with self._lock:
            window = self._entities.get(entity)
            if window is None:
                window = _EntityWindow()
                self._entities[entity] = window
            window.observations.append(observation)
            window.bytes_total += observation.bytes
            window.packets_total += observation.packets
            while window.observations and window.observations[0].timestamp < now - timedelta(
                seconds=self.window_seconds * 4
            ):
                stale = window.observations.popleft()
                window.bytes_total -= stale.bytes
                window.packets_total -= stale.packets
            while len(window.observations) > self.max_observations:
                stale = window.observations.popleft()
                window.bytes_total -= stale.bytes
                window.packets_total -= stale.packets
            self._entities.move_to_end(entity)
            while len(self._entities) > self.max_entities:
                self._entities.popitem(last=False)
            self.observations_seen += 1

    # --------------------------------------------------------- features
    def features(self, entity: str, *, window_seconds: int | None = None) -> FeatureVector:
        window_seconds = int(window_seconds or self.window_seconds)
        cutoff = utcnow() - timedelta(seconds=window_seconds)
        with self._lock:
            window = self._entities.get(entity)
            observations = [obs for obs in window.observations if obs.timestamp >= cutoff] if window else []

        ports = {obs.destination_port for obs in observations if obs.destination_port}
        destinations = {obs.destination_ip for obs in observations if obs.destination_ip}
        protocols = {obs.protocol for obs in observations if obs.protocol}
        dns_queries = {
            obs.dns_query for obs in observations if obs.event_type == EventType.DNS_QUERY.value and obs.dns_query
        }
        failures = sum(
            1
            for obs in observations
            if obs.connection_state in {ConnectionState.FAILED.value, ConnectionState.RESET.value}
        )
        auth_failures = sum(
            1 for obs in observations if obs.event_type == EventType.AUTH_FAILURE.value
        )
        dns_requests = sum(
            1 for obs in observations if obs.event_type == EventType.DNS_QUERY.value
        )
        total_bytes = sum(obs.bytes for obs in observations)
        total_packets = sum(obs.packets for obs in observations)
        durations = [obs.duration_ms for obs in observations if obs.duration_ms]

        port_counts: dict[int, int] = {}
        for obs in observations:
            if obs.destination_port:
                port_counts[obs.destination_port] = port_counts.get(obs.destination_port, 0) + 1
        top_port = max(port_counts, key=port_counts.get) if port_counts else None

        hours = {obs.timestamp.hour for obs in observations}
        off_hours = bool(hours) and not hours.intersection(set(BUSINESS_HOURS))

        return FeatureVector(
            source_ip=entity,
            window_seconds=window_seconds,
            connection_count=len(observations),
            unique_destination_ports=len(ports),
            unique_destination_ips=len(destinations),
            failed_connections=failures,
            dns_requests=dns_requests,
            unique_dns_queries=len(dns_queries),
            auth_failures=auth_failures,
            bytes_total=total_bytes,
            packets_total=total_packets,
            bytes_per_second=round(total_bytes / window_seconds, 3),
            packets_per_second=round(total_packets / window_seconds, 3),
            avg_connection_duration_ms=round(sum(durations) / len(durations), 3) if durations else 0.0,
            unique_protocols=len(protocols),
            top_destination_port=top_port,
            off_hours=off_hours,
            events_per_minute=round(len(observations) * 60.0 / window_seconds, 3),
        )

    def features_for_all(self, *, limit: int = 200, window_seconds: int | None = None) -> list[FeatureVector]:
        with self._lock:
            entities = list(self._entities.keys())[-limit:]
        return [self.features(entity, window_seconds=window_seconds) for entity in entities]

    def entity_count(self) -> int:
        with self._lock:
            return len(self._entities)

    def statistics(self) -> dict:
        with self._lock:
            return {
                "entities": len(self._entities),
                "observations_seen": self.observations_seen,
                "window_seconds": self.window_seconds,
                "max_entities": self.max_entities,
            }

    def clear(self) -> None:
        with self._lock:
            self._entities.clear()
            self.observations_seen = 0


def _optional_float(value) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


__all__ = ["BUSINESS_HOURS", "FEATURE_ORDER", "FeatureExtractor"]
