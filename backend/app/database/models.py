"""ORM models for the Mini SOC schema (spec section 22).

The schema is built so an analyst can always trace:

    Event -> Detection -> Alert -> Incident -> Investigation note

Every table the specification requires is present, plus the small number of
support tables needed to make the trace complete and the platform operable
(detections, refresh tokens, id sequences, config overrides, metrics).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..provenance import origin_for, provenance
from .base import Base, TimestampMixin, utcnow
from .enums import (
    AlertStatus,
    ConnectionState,
    EventType,
    IncidentStatus,
    LogCategory,
    Protocol,
    RuleType,
    SeverityLevel,
    UserRole,
)


class IdSequence(Base):
    """Atomic counters backing human-readable identifiers (EVT-000001...)."""

    __tablename__ = "id_sequences"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), default=UserRole.VIEWER.value, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime)

    notes: Mapped[list["InvestigationNote"]] = relationship(back_populates="author")

    def public_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class RefreshToken(Base):
    """Server-side record of issued refresh tokens (revocable sessions)."""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    user_agent: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(64))


class Asset(Base):
    """Known network asset; drives the asset-importance risk signal."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    mac_address: Mapped[str | None] = mapped_column(String(32))
    asset_type: Mapped[str] = mapped_column(String(32), default="unknown")
    importance: Mapped[int] = mapped_column(Integer, default=3, nullable=False)  # 1..5
    tags: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    def public_dict(self) -> dict:
        return self.to_dict()


class Event(Base, TimestampMixin):
    """Normalised security event — the common schema of the platform."""

    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_timestamp_severity", "timestamp", "severity"),
        Index("ix_events_source_destination", "source_ip", "destination_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False, index=True
    )
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(16), default=Protocol.OTHER.value, index=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    connection_state: Mapped[str] = mapped_column(
        String(16), default=ConnectionState.UNKNOWN.value
    )
    event_type: Mapped[str] = mapped_column(
        String(32), default=EventType.UNKNOWN.value, index=True
    )
    direction: Mapped[str | None] = mapped_column(String(16))
    interface: Mapped[str | None] = mapped_column(String(64))
    collector: Mapped[str | None] = mapped_column(String(32), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(16), default=SeverityLevel.LOW.value, nullable=False, index=True
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    detection_hits: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    dedupe_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    meta: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    #: Wall-clock time the event was stored (used for end-to-end latency stats).
    stored_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    network: Mapped["NetworkEvent | None"] = relationship(
        back_populates="event", uselist=False, cascade="all, delete-orphan"
    )
    detections: Mapped[list["Detection"]] = relationship(back_populates="event")

    def to_public_dict(self) -> dict:
        """Event schema exposed by REST and WebSocket (spec section 6)."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "bytes": self.bytes,
            "connection_state": self.connection_state,
            "event_type": self.event_type,
            "risk_score": round(self.risk_score or 0.0, 2),
            "severity": self.severity,
            "confidence": round(self.confidence or 0.0, 3),
            "anomaly_score": self.anomaly_score,
            "direction": self.direction,
            "interface": self.interface,
            "collector": self.collector,
            "data_origin": origin_for(self.collector),
            "detection_hits": self.detection_hits,
            "metadata": self.meta or {},
        }


class NetworkEvent(Base):
    """Protocol-level enrichment for a normalised event."""

    __tablename__ = "network_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("events.event_id", ondelete="CASCADE"), index=True, nullable=False
    )
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(16), index=True)
    tcp_flags: Mapped[str | None] = mapped_column(String(16))
    duration_ms: Mapped[float | None] = mapped_column(Float)
    packets: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    dns_query: Mapped[str | None] = mapped_column(String(255), index=True)
    dns_qtype: Mapped[str | None] = mapped_column(String(16))
    dns_rcode: Mapped[str | None] = mapped_column(String(16))
    http_host: Mapped[str | None] = mapped_column(String(255))
    http_method: Mapped[str | None] = mapped_column(String(16))
    tls_sni: Mapped[str | None] = mapped_column(String(255))
    icmp_type: Mapped[str | None] = mapped_column(String(32))
    arp_op: Mapped[str | None] = mapped_column(String(16))
    interface: Mapped[str | None] = mapped_column(String(64))
    capture_source: Mapped[str | None] = mapped_column(String(32))
    meta: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    event: Mapped[Event] = relationship(back_populates="network")


class DetectionRule(Base, TimestampMixin):
    """Configurable detection rule (loaded from YAML packs into the database)."""

    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_key: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(32), default="GENERIC", index=True)
    rule_type: Mapped[str] = mapped_column(String(16), default=RuleType.THRESHOLD.value)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    severity_hint: Mapped[str] = mapped_column(
        String(16), default=SeverityLevel.MEDIUM.value
    )
    description: Mapped[str | None] = mapped_column(Text)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    mitre_id: Mapped[str | None] = mapped_column(String(16))
    threshold: Mapped[float] = mapped_column(Float, default=0.0)
    window_seconds: Mapped[int] = mapped_column(Integer, default=60)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    source: Mapped[str] = mapped_column(String(16), default="file")

    def public_dict(self) -> dict:
        return {
            "rule_key": self.rule_key,
            "name": self.name,
            "category": self.category,
            "rule_type": self.rule_type,
            "enabled": self.enabled,
            "severity_hint": self.severity_hint,
            "description": self.description,
            "recommended_action": self.recommended_action,
            "mitre_id": self.mitre_id,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "params": self.params or {},
            "version": self.version,
            "source": self.source,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Detection(Base):
    """A single rule/ML hit on a single event (Event -> Detection link)."""

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    detection_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("events.event_id", ondelete="CASCADE"), index=True, nullable=False
    )
    alert_id: Mapped[str | None] = mapped_column(
        ForeignKey("alerts.alert_id", ondelete="SET NULL"), index=True
    )
    rule_key: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    detection_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    engine: Mapped[str] = mapped_column(String(16), default="RULE")
    matched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    rule_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)

    event: Mapped[Event] = relationship(back_populates="detections")

    def public_dict(self) -> dict:
        return {
            "detection_id": self.detection_id,
            "event_id": self.event_id,
            "alert_id": self.alert_id,
            "rule_key": self.rule_key,
            "detection_type": self.detection_type,
            "engine": self.engine,
            "matched_at": self.matched_at.isoformat() if self.matched_at else None,
            "rule_score": self.rule_score,
            "anomaly_score": self.anomaly_score,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence or {},
        }


class Alert(Base, TimestampMixin):
    """Generated alert (spec section 12)."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status_severity", "status", "severity"),
        Index("ix_alerts_dedupe_window", "dedupe_key", "last_seen"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    detection_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    rule_key: Mapped[str | None] = mapped_column(String(64), index=True)
    engine: Mapped[str] = mapped_column(String(16), default="RULE")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), default=SeverityLevel.LOW.value, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(16), default=AlertStatus.NEW.value, nullable=False, index=True
    )
    dedupe_key: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime)
    acknowledged_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    resolution: Mapped[str | None] = mapped_column(Text)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="SET NULL"), index=True
    )

    incident: Mapped["Incident | None"] = relationship(back_populates="alerts")
    notes: Mapped[list["InvestigationNote"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )

    def public_dict(self) -> dict:
        evidence = self.evidence or {}
        return {
            # Provenance: which collector raised this alert and from where, so a
            # lab-generated alert can never read like an observed one.
            **provenance(
                evidence.get("collector"),
                evidence.get("interface"),
                collectors=evidence.get("collectors"),
                interfaces=evidence.get("interfaces"),
            ),
            "alert_id": self.alert_id,
            "timestamp": self.first_seen.isoformat() if self.first_seen else None,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "detection_type": self.detection_type,
            "rule_key": self.rule_key,
            "engine": self.engine,
            "risk_score": round(self.risk_score or 0.0, 2),
            "severity": self.severity,
            "confidence": round(self.confidence or 0.0, 3),
            "description": self.description,
            "evidence": self.evidence or {},
            "recommended_action": self.recommended_action,
            "status": self.status,
            "event_count": self.event_count,
            "incident_id": self.incident_id,
            "assignee_id": self.assignee_id,
            "acknowledged_at": (
                self.acknowledged_at.isoformat() if self.acknowledged_at else None
            ),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution": self.resolution,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Incident(Base, TimestampMixin):
    """Correlated group of alerts (spec section 13)."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default=SeverityLevel.MEDIUM.value, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), default=IncidentStatus.OPEN.value, nullable=False, index=True
    )
    source_entities: Mapped[list] = mapped_column(JSON, default=list)
    destination_entities: Mapped[list] = mapped_column(JSON, default=list)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    detection_types: Mapped[list] = mapped_column(JSON, default=list)
    alert_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolution: Mapped[str | None] = mapped_column(Text)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime)

    alerts: Mapped[list[Alert]] = relationship(back_populates="incident")
    notes: Mapped[list["InvestigationNote"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )

    def public_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "risk_score": round(self.risk_score or 0.0, 2),
            "status": self.status,
            "source_entities": self.source_entities or [],
            "destination_entities": self.destination_entities or [],
            "timeline": self.timeline or [],
            "detection_types": self.detection_types or [],
            "alert_count": self.alert_count,
            "owner_id": self.owner_id,
            "resolution": self.resolution,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }


class InvestigationNote(Base):
    """Analyst note / action taken against an alert or an incident."""

    __tablename__ = "investigation_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str | None] = mapped_column(
        ForeignKey("alerts.alert_id", ondelete="CASCADE"), index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True
    )
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    note: Mapped[str] = mapped_column(Text, nullable=False)
    action_taken: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False, index=True
    )

    alert: Mapped[Alert | None] = relationship(back_populates="notes")
    incident: Mapped[Incident | None] = relationship(back_populates="notes")
    author: Mapped[User | None] = relationship(back_populates="notes")

    def public_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "incident_id": self.incident_id,
            "author": self.author.username if self.author else None,
            "author_id": self.author_id,
            "note": self.note,
            "action_taken": self.action_taken,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ModelPrediction(Base):
    """One ML inference result (keeps model behaviour auditable)."""

    __tablename__ = "model_predictions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str | None] = mapped_column(
        ForeignKey("events.event_id", ondelete="CASCADE"), index=True
    )
    model_name: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    threshold: Mapped[float] = mapped_column(Float, default=0.0)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False, index=True
    )

    def public_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "anomaly_score": self.anomaly_score,
            "is_anomaly": self.is_anomaly,
            "threshold": self.threshold,
            "latency_ms": self.latency_ms,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class SystemLog(Base):
    """Operational / audit log mirrored into the database (spec section 27)."""

    __tablename__ = "system_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False, index=True
    )
    level: Mapped[str] = mapped_column(String(16), default="INFO", index=True)
    category: Mapped[str] = mapped_column(
        String(16), default=LogCategory.SYSTEM.value, index=True
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    source: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    def public_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level": self.level,
            "category": self.category,
            "message": self.message,
            "actor": self.actor,
            "request_id": self.request_id,
            "source": self.source,
            "details": self.details or {},
        }


class MetricsSnapshot(Base):
    """Periodic performance sample used by the performance dashboard."""

    __tablename__ = "metrics_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False, index=True
    )
    events_per_second: Mapped[float] = mapped_column(Float, default=0.0)
    events_total: Mapped[int] = mapped_column(Integer, default=0)
    alerts_total: Mapped[int] = mapped_column(Integer, default=0)
    queue_depth: Mapped[int] = mapped_column(Integer, default=0)
    dropped_events: Mapped[int] = mapped_column(Integer, default=0)
    processing_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    detection_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    alert_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    db_write_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    ws_delivery_ms: Mapped[float] = mapped_column(Float, default=0.0)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0)
    memory_mb: Mapped[float] = mapped_column(Float, default=0.0)
    uptime_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    collectors: Mapped[dict] = mapped_column(JSON, default=dict)

    def public_dict(self) -> dict:
        data = self.to_dict()
        data["captured_at"] = self.captured_at.isoformat() if self.captured_at else None
        return data


class ConfigOverride(Base):
    """Runtime configuration overrides (severity bands, weights, thresholds)."""

    __tablename__ = "config_overrides"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_by: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


__all__ = [
    "Alert",
    "Asset",
    "ConfigOverride",
    "Detection",
    "DetectionRule",
    "Event",
    "IdSequence",
    "Incident",
    "InvestigationNote",
    "MetricsSnapshot",
    "ModelPrediction",
    "NetworkEvent",
    "RefreshToken",
    "SystemLog",
    "User",
]
