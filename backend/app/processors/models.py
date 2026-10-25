"""Typed data structures that flow through the processing pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..database.enums import ConnectionState, EventType, Protocol


class RawRecord(BaseModel):
    """A single raw observation produced by a collector."""

    model_config = ConfigDict(extra="ignore")

    collector: str
    received_at: datetime
    event_type: str = EventType.UNKNOWN.value
    payload: dict[str, Any] = Field(default_factory=dict)
    interface: str | None = None
    source_host: str | None = None


class NormalizedEvent(BaseModel):
    """Canonical event schema (spec section 6) plus protocol enrichment."""

    model_config = ConfigDict(extra="ignore")

    event_id: str | None = None
    timestamp: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str = Protocol.OTHER.value
    packet_count: int = 1
    bytes: int = 0
    connection_state: str = ConnectionState.UNKNOWN.value
    event_type: str = EventType.UNKNOWN.value
    direction: str | None = None
    interface: str | None = None
    collector: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    dedupe_hash: str | None = None
    #: Protocol level detail persisted in ``network_events``.
    network: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def _known_event_type(cls, value: str) -> str:
        return value if EventType.has(value) else EventType.UNKNOWN.value

    def entity_key(self) -> str:
        """Primary entity used for behavioural feature windows."""
        return self.source_ip or self.destination_ip or "unknown"


class FeatureVector(BaseModel):
    """Behavioural features describing one source entity over a time window."""

    model_config = ConfigDict(extra="ignore")

    source_ip: str
    window_seconds: int
    connection_count: int = 0
    unique_destination_ports: int = 0
    unique_destination_ips: int = 0
    failed_connections: int = 0
    dns_requests: int = 0
    unique_dns_queries: int = 0
    auth_failures: int = 0
    bytes_total: int = 0
    packets_total: int = 0
    bytes_per_second: float = 0.0
    packets_per_second: float = 0.0
    avg_connection_duration_ms: float = 0.0
    unique_protocols: int = 0
    top_destination_port: int | None = None
    off_hours: bool = False
    events_per_minute: float = 0.0

    def as_vector(self, order: list[str]) -> list[float]:
        return [float(getattr(self, name, 0.0) or 0.0) for name in order]


class PipelineResult(BaseModel):
    """Outcome of processing a single raw record."""

    model_config = ConfigDict(extra="ignore")

    accepted: bool
    reason: str | None = None
    duplicate: bool = False
    event: NormalizedEvent | None = None
    features: FeatureVector | None = None


__all__ = ["FeatureVector", "NormalizedEvent", "PipelineResult", "RawRecord"]
