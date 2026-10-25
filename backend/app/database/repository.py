"""Repository layer — every read and write Mini SOC performs goes through here.

Keeping SQL in one module means the API, the pipeline and the CLI share exactly
the same semantics, and it keeps query construction (which is injection
sensitive) away from request handlers.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Select, and_, case, delete, desc, func, or_, select, update
from sqlalchemy.orm import Session

from ..config.logging_config import get_logger
from .base import utcnow
from .enums import AlertStatus, IncidentStatus, LogCategory
from .models import (
    Alert,
    Asset,
    ConfigOverride,
    Detection,
    DetectionRule,
    Event,
    IdSequence,
    Incident,
    InvestigationNote,
    MetricsSnapshot,
    ModelPrediction,
    NetworkEvent,
    RefreshToken,
    SystemLog,
    User,
)

logger = get_logger(__name__)


class RepositoryError(RuntimeError):
    """Raised when a repository operation cannot be satisfied."""


class Repository:
    """Data access object bound to a single SQLAlchemy session."""

    def __init__(self, session: Session) -> None:
        self.session = session

    # ------------------------------------------------------------- ids
    def next_id(self, name: str, prefix: str, width: int = 6) -> str:
        """Allocate the next human-readable identifier (e.g. ``EVT-000042``).

        Uses an atomic upsert so several pipeline workers allocating ids for the
        same table at the same time cannot collide (a plain "select then insert"
        races and raises a UNIQUE violation under load).
        """
        dialect = self.session.get_bind().dialect.name
        value: int | None = None

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            statement = sqlite_insert(IdSequence).values(name=name, value=1)
            statement = statement.on_conflict_do_update(
                index_elements=[IdSequence.name], set_={"value": IdSequence.value + 1}
            ).returning(IdSequence.value)
            value = self.session.execute(statement).scalar_one()
        elif dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            statement = pg_insert(IdSequence).values(name=name, value=1)
            statement = statement.on_conflict_do_update(
                index_elements=[IdSequence.name], set_={"value": IdSequence.value + 1}
            ).returning(IdSequence.value)
            value = self.session.execute(statement).scalar_one()
        else:  # pragma: no cover - other backends use a pessimistic lock
            row = self.session.get(IdSequence, name, with_for_update=True)
            if row is None:
                row = IdSequence(name=name, value=1)
                self.session.add(row)
                self.session.flush()
                value = 1
            else:
                row.value = int(row.value) + 1
                self.session.flush()
                value = row.value

        return f"{prefix}-{int(value):0{width}d}"

    # ------------------------------------------------------------ users
    def get_user_by_username(self, username: str) -> User | None:
        return self.session.scalar(select(User).where(User.username == username))

    def get_user(self, user_id: int) -> User | None:
        return self.session.get(User, user_id)

    def list_users(self) -> list[User]:
        return list(self.session.scalars(select(User).order_by(User.username)))

    def create_user(
        self,
        *,
        username: str,
        password_hash: str,
        role: str,
        email: str | None = None,
        is_active: bool = True,
    ) -> User:
        if self.get_user_by_username(username) is not None:
            raise RepositoryError(f"user {username!r} already exists")
        user = User(
            username=username,
            password_hash=password_hash,
            role=role,
            email=email,
            is_active=is_active,
        )
        self.session.add(user)
        self.session.flush()
        return user

    def touch_login(self, user: User, *, success: bool) -> None:
        if success:
            user.last_login_at = utcnow()
            user.failed_login_attempts = 0
            user.locked_until = None
        else:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        self.session.flush()

    # ------------------------------------------------------------ tokens
    def store_refresh_token(
        self,
        *,
        user_id: int,
        token_hash: str,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> RefreshToken:
        token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=(user_agent or "")[:255] or None,
        )
        self.session.add(token)
        self.session.flush()
        return token

    def get_refresh_token(self, token_hash: str) -> RefreshToken | None:
        return self.session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))

    def revoke_refresh_token(self, token: RefreshToken) -> None:
        token.revoked_at = utcnow()
        self.session.flush()

    def revoke_user_tokens(self, user_id: int) -> int:
        result = self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        return int(result.rowcount or 0)

    # ------------------------------------------------------------ events
    def add_event(self, event: Event) -> Event:
        self.session.add(event)
        return event

    def add_events(self, events: Sequence[Event]) -> int:
        self.session.add_all(list(events))
        return len(events)

    def get_event(self, event_id: str) -> Event | None:
        return self.session.scalar(select(Event).where(Event.event_id == event_id))

    def event_exists_by_dedupe(self, dedupe_hash: str, window_seconds: int) -> bool:
        since = utcnow() - timedelta(seconds=window_seconds)
        stmt = select(func.count(Event.id)).where(
            Event.dedupe_hash == dedupe_hash, Event.timestamp >= since
        )
        return bool(self.session.scalar(stmt) or 0)

    def _filtered_events(
        self,
        *,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        severity: str | None = None,
        event_type: str | None = None,
        protocol: str | None = None,
        collector: str | None = None,
        min_risk: float | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        search: str | None = None,
    ) -> Select:
        stmt = select(Event)
        conditions = []
        if source_ip:
            conditions.append(Event.source_ip == source_ip)
        if destination_ip:
            conditions.append(Event.destination_ip == destination_ip)
        if severity:
            conditions.append(Event.severity == severity)
        if event_type:
            conditions.append(Event.event_type == event_type)
        if protocol:
            conditions.append(Event.protocol == protocol)
        if collector:
            conditions.append(Event.collector == collector)
        if min_risk is not None:
            conditions.append(Event.risk_score >= min_risk)
        if start:
            conditions.append(Event.timestamp >= start)
        if end:
            conditions.append(Event.timestamp <= end)
        if search:
            like = f"%{search}%"
            conditions.append(
                or_(
                    Event.source_ip.like(like),
                    Event.destination_ip.like(like),
                    Event.event_id.like(like),
                    Event.event_type.like(like),
                )
            )
        if conditions:
            stmt = stmt.where(and_(*conditions))
        return stmt

    def list_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        order: str = "desc",
        **filters: Any,
    ) -> list[Event]:
        stmt = self._filtered_events(**filters)
        stmt = stmt.order_by(desc(Event.timestamp) if order == "desc" else Event.timestamp)
        stmt = stmt.limit(min(max(limit, 1), 1000)).offset(max(offset, 0))
        return list(self.session.scalars(stmt))

    def count_events(self, **filters: Any) -> int:
        stmt = self._filtered_events(**filters).with_only_columns(func.count(Event.id))
        return int(self.session.scalar(stmt) or 0)

    def network_event_for(self, event_id: str) -> NetworkEvent | None:
        return self.session.scalar(select(NetworkEvent).where(NetworkEvent.event_id == event_id))

    def related_events_for_ip(
        self, ip: str, *, minutes: int = 60, limit: int = 50, exclude_event_id: str | None = None
    ) -> list[Event]:
        since = utcnow() - timedelta(minutes=minutes)
        stmt = select(Event).where(
            or_(Event.source_ip == ip, Event.destination_ip == ip), Event.timestamp >= since
        )
        if exclude_event_id:
            stmt = stmt.where(Event.event_id != exclude_event_id)
        return list(self.session.scalars(stmt.order_by(desc(Event.timestamp)).limit(limit)))

    # ------------------------------------------------------- aggregations
    def events_per_second(self, *, seconds: int = 60) -> float:
        since = utcnow() - timedelta(seconds=seconds)
        count = int(
            self.session.scalar(
                select(func.count(Event.id)).where(Event.timestamp >= since)
            )
            or 0
        )
        return round(count / float(max(seconds, 1)), 3)

    def timeseries(
        self,
        model: type,
        field: str,
        *,
        minutes: int = 60,
        buckets: int = 12,
        extra_filters: list | None = None,
    ) -> list[dict]:
        """Bucket a timestamp column into ``buckets`` equal slices."""
        window = max(minutes, 1)
        bucket_seconds = max(window * 60 // max(buckets, 1), 1)
        since = utcnow() - timedelta(minutes=window)
        column = getattr(model, field)
        stmt = select(column).where(column >= since)
        if extra_filters:
            stmt = stmt.where(*extra_filters)
        stamps = [row[0] for row in self.session.execute(stmt)]
        now = utcnow()
        result: list[dict] = []
        for index in range(buckets):
            start = now - timedelta(seconds=bucket_seconds * (buckets - index))
            end = now - timedelta(seconds=bucket_seconds * (buckets - index - 1))
            total = sum(1 for stamp in stamps if stamp and start <= stamp < end)
            result.append({"bucket_start": start.isoformat(), "bucket_end": end.isoformat(), "count": total})
        return result

    def top_values(self, column, *, minutes: int = 1440, limit: int = 10, minimum: int = 1) -> list[dict]:
        since = utcnow() - timedelta(minutes=minutes)
        stmt = (
            select(column, func.count(Event.id).label("count"))
            .where(Event.timestamp >= since, column.is_not(None))
            .group_by(column)
            .order_by(desc("count"))
            .limit(limit)
        )
        rows = [{"value": value, "count": int(count)} for value, count in self.session.execute(stmt)]
        return [row for row in rows if row["count"] >= minimum]

    def distribution(self, column, *, minutes: int = 1440) -> list[dict]:
        since = utcnow() - timedelta(minutes=minutes)
        stmt = (
            select(column, func.count(Event.id))
            .where(Event.timestamp >= since)
            .group_by(column)
            .order_by(desc(func.count(Event.id)))
        )
        return [{"value": value, "count": int(count)} for value, count in self.session.execute(stmt)]

    def severity_distribution(self, model: type = Event, *, minutes: int = 1440) -> list[dict]:
        column = model.severity
        column_ts = model.created_at if hasattr(model, "created_at") else model.timestamp
        since = utcnow() - timedelta(minutes=minutes)
        stmt = (
            select(column, func.count())
            .where(column_ts >= since)
            .group_by(column)
        )
        return [{"value": value, "count": int(count)} for value, count in self.session.execute(stmt)]

    def event_volume_by_protocol(self, *, minutes: int = 1440) -> list[dict]:
        return self.distribution(Event.protocol, minutes=minutes)

    def top_destination_ports(self, *, minutes: int = 1440, limit: int = 10) -> list[dict]:
        return self.top_values(Event.destination_port, minutes=minutes, limit=limit)

    def top_source_ips(self, *, minutes: int = 1440, limit: int = 10) -> list[dict]:
        return self.top_values(Event.source_ip, minutes=minutes, limit=limit)

    def top_destination_ips(self, *, minutes: int = 1440, limit: int = 10) -> list[dict]:
        return self.top_values(Event.destination_ip, minutes=minutes, limit=limit)

    def high_risk_sources(self, *, minutes: int = 1440, limit: int = 10) -> list[dict]:
        since = utcnow() - timedelta(minutes=minutes)
        stmt = (
            select(Event.source_ip, func.max(Event.risk_score), func.count(Event.id))
            .where(Event.timestamp >= since, Event.source_ip.is_not(None))
            .group_by(Event.source_ip)
            .order_by(desc(func.max(Event.risk_score)))
            .limit(limit)
        )
        return [
            {"source_ip": ip, "max_risk": float(max_risk or 0), "events": int(count)}
            for ip, max_risk, count in self.session.execute(stmt)
        ]

    def failed_connection_count(self, source_ip: str, *, minutes: int = 5) -> int:
        since = utcnow() - timedelta(minutes=minutes)
        stmt = select(func.count(Event.id)).where(
            Event.source_ip == source_ip,
            Event.connection_state == "FAILED",
            Event.timestamp >= since,
        )
        return int(self.session.scalar(stmt) or 0)

    # ------------------------------------------------------------ assets
    def get_or_create_asset(self, ip_address: str, **defaults: Any) -> Asset:
        asset = self.session.scalar(select(Asset).where(Asset.ip_address == ip_address))
        if asset is None:
            asset = Asset(ip_address=ip_address, **defaults)
            self.session.add(asset)
            self.session.flush()
        else:
            asset.last_seen = utcnow()
        return asset

    def list_assets(self, *, limit: int = 200) -> list[Asset]:
        return list(self.session.scalars(select(Asset).order_by(Asset.ip_address).limit(limit)))

    def upsert_asset(
        self,
        ip_address: str,
        *,
        hostname: str | None = None,
        asset_type: str | None = None,
        importance: int | None = None,
        tags: list | None = None,
        notes: str | None = None,
    ) -> Asset:
        asset = self.get_or_create_asset(ip_address)
        if hostname is not None:
            asset.hostname = hostname
        if asset_type is not None:
            asset.asset_type = asset_type
        if importance is not None:
            asset.importance = max(1, min(5, int(importance)))
        if tags is not None:
            asset.tags = tags
        if notes is not None:
            asset.notes = notes
        self.session.flush()
        return asset

    def asset_importance(self, ip_address: str | None) -> int:
        if not ip_address:
            return 3
        asset = self.session.scalar(select(Asset).where(Asset.ip_address == ip_address))
        return int(asset.importance) if asset else 3

    # ------------------------------------------------------------- rules
    def list_rules(self, *, enabled_only: bool = False) -> list[DetectionRule]:
        stmt = select(DetectionRule).order_by(DetectionRule.rule_key)
        if enabled_only:
            stmt = stmt.where(DetectionRule.enabled.is_(True))
        return list(self.session.scalars(stmt))

    def get_rule(self, rule_key: str) -> DetectionRule | None:
        return self.session.scalar(select(DetectionRule).where(DetectionRule.rule_key == rule_key))

    def upsert_rule(self, payload: dict) -> DetectionRule:
        rule_key = payload["rule_key"]
        rule = self.get_rule(rule_key)
        if rule is None:
            rule = DetectionRule(**payload)
            self.session.add(rule)
        else:
            for key, value in payload.items():
                setattr(rule, key, value)
            rule.version = int(rule.version or 1) + 1
        self.session.flush()
        return rule

    def set_rule_enabled(self, rule_key: str, enabled: bool) -> DetectionRule:
        rule = self.get_rule(rule_key)
        if rule is None:
            raise RepositoryError(f"unknown rule {rule_key!r}")
        rule.enabled = enabled
        self.session.flush()
        return rule

    def update_rule_params(self, rule_key: str, params: dict, *, threshold: float | None = None,
                           window_seconds: int | None = None) -> DetectionRule:
        rule = self.get_rule(rule_key)
        if rule is None:
            raise RepositoryError(f"unknown rule {rule_key!r}")
        merged = dict(rule.params or {})
        merged.update(params)
        rule.params = merged
        if threshold is not None:
            rule.threshold = float(threshold)
        if window_seconds is not None:
            rule.window_seconds = int(window_seconds)
        rule.version = int(rule.version or 1) + 1
        self.session.flush()
        return rule

    # -------------------------------------------------------- detections
    def add_detection(self, detection: Detection) -> Detection:
        self.session.add(detection)
        return detection

    def add_detections(self, detections: Sequence[Detection]) -> int:
        self.session.add_all(list(detections))
        return len(detections)

    def list_detections_for_event(self, event_id: str) -> list[Detection]:
        stmt = (
            select(Detection)
            .where(Detection.event_id == event_id)
            .order_by(desc(Detection.rule_score))
        )
        return list(self.session.scalars(stmt))

    def list_detections_for_alert(self, alert_id: str) -> list[Detection]:
        return list(
            self.session.scalars(
                select(Detection)
                .where(Detection.alert_id == alert_id)
                .order_by(desc(Detection.matched_at))
            )
        )

    def detection_rule_frequency(self, *, minutes: int = 1440, limit: int = 15) -> list[dict]:
        since = utcnow() - timedelta(minutes=minutes)
        stmt = (
            select(Detection.rule_key, func.count(Detection.id))
            .where(Detection.matched_at >= since)
            .group_by(Detection.rule_key)
            .order_by(desc(func.count(Detection.id)))
            .limit(limit)
        )
        return [{"value": key, "count": int(count)} for key, count in self.session.execute(stmt)]

    # ------------------------------------------------------------- alerts
    def find_active_alert_for_dedupe(
        self, dedupe_key: str, *, window_seconds: int
    ) -> Alert | None:
        since = utcnow() - timedelta(seconds=window_seconds)
        stmt = (
            select(Alert)
            .where(
                Alert.dedupe_key == dedupe_key,
                Alert.last_seen >= since,
                Alert.status.in_(
                    [AlertStatus.NEW.value, AlertStatus.ACKNOWLEDGED.value,
                     AlertStatus.INVESTIGATING.value]
                ),
            )
            .order_by(desc(Alert.last_seen))
            .limit(1)
        )
        return self.session.scalar(stmt)

    def add_alert(self, alert: Alert) -> Alert:
        self.session.add(alert)
        self.session.flush()
        return alert

    def get_alert(self, alert_id: str) -> Alert | None:
        return self.session.scalar(select(Alert).where(Alert.alert_id == alert_id))

    def list_alerts(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        status: str | None = None,
        detection_type: str | None = None,
        rule_key: str | None = None,
        source_ip: str | None = None,
        engine: str | None = None,
        incident_id: str | None = None,
        min_risk: float | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        search: str | None = None,
    ) -> list[Alert]:
        stmt = select(Alert)
        conditions = []
        if severity:
            conditions.append(Alert.severity == severity)
        if status:
            conditions.append(Alert.status == status)
        if detection_type:
            conditions.append(Alert.detection_type == detection_type)
        if rule_key:
            conditions.append(Alert.rule_key == rule_key)
        if source_ip:
            conditions.append(Alert.source_ip == source_ip)
        if engine:
            conditions.append(Alert.engine == engine)
        if incident_id:
            conditions.append(Alert.incident_id == incident_id)
        if min_risk is not None:
            conditions.append(Alert.risk_score >= min_risk)
        if start:
            conditions.append(Alert.last_seen >= start)
        if end:
            conditions.append(Alert.last_seen <= end)
        if search:
            like = f"%{search}%"
            conditions.append(
                or_(
                    Alert.source_ip.like(like),
                    Alert.destination_ip.like(like),
                    Alert.description.like(like),
                    Alert.alert_id.like(like),
                    Alert.detection_type.like(like),
                )
            )
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(desc(Alert.last_seen)).limit(min(max(limit, 1), 500)).offset(max(offset, 0))
        return list(self.session.scalars(stmt))

    def count_alerts(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        detection_type: str | None = None,
        source_ip: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> int:
        stmt = select(func.count(Alert.id))
        conditions = []
        if severity:
            conditions.append(Alert.severity == severity)
        if status:
            conditions.append(Alert.status == status)
        if detection_type:
            conditions.append(Alert.detection_type == detection_type)
        if source_ip:
            conditions.append(Alert.source_ip == source_ip)
        if start:
            conditions.append(Alert.last_seen >= start)
        if end:
            conditions.append(Alert.last_seen <= end)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        return int(self.session.scalar(stmt) or 0)

    def alert_totals(self, *, minutes: int = 1440) -> dict:
        since = utcnow() - timedelta(minutes=minutes)
        open_states = [
            AlertStatus.NEW.value,
            AlertStatus.ACKNOWLEDGED.value,
            AlertStatus.INVESTIGATING.value,
        ]
        total = int(
            self.session.scalar(select(func.count(Alert.id)).where(Alert.last_seen >= since)) or 0
        )
        active = int(
            self.session.scalar(
                select(func.count(Alert.id)).where(
                    Alert.last_seen >= since, Alert.status.in_(open_states)
                )
            )
            or 0
        )
        critical = int(
            self.session.scalar(
                select(func.count(Alert.id)).where(
                    Alert.last_seen >= since,
                    Alert.severity == "CRITICAL",
                    Alert.status.in_(open_states),
                )
            )
            or 0
        )
        return {"total": total, "active": active, "critical": critical}

    def alerts_by_severity(self, *, minutes: int = 1440) -> list[dict]:
        return self.severity_distribution(Alert, minutes=minutes)

    def alerts_by_detection_type(self, *, minutes: int = 1440, limit: int = 15) -> list[dict]:
        since = utcnow() - timedelta(minutes=minutes)
        stmt = (
            select(Alert.detection_type, func.count(Alert.id))
            .where(Alert.last_seen >= since)
            .group_by(Alert.detection_type)
            .order_by(desc(func.count(Alert.id)))
            .limit(limit)
        )
        return [{"value": value, "count": int(count)} for value, count in self.session.execute(stmt)]

    def alerts_for_source(self, source_ip: str, *, minutes: int = 1440, limit: int = 25) -> list[Alert]:
        since = utcnow() - timedelta(minutes=minutes)
        stmt = (
            select(Alert)
            .where(Alert.source_ip == source_ip, Alert.last_seen >= since)
            .order_by(desc(Alert.last_seen))
            .limit(limit)
        )
        return list(self.session.scalars(stmt))

    def alerts_since(self, since: datetime) -> list[Alert]:
        return list(
            self.session.scalars(select(Alert).where(Alert.last_seen >= since).order_by(Alert.last_seen))
        )

    def alerts_for_incident(self, incident_id: str) -> list[Alert]:
        return list(
            self.session.scalars(
                select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.first_seen)
            )
        )

    # ---------------------------------------------------------- incidents
    def add_incident(self, incident: Incident) -> Incident:
        self.session.add(incident)
        self.session.flush()
        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        return self.session.scalar(select(Incident).where(Incident.incident_id == incident_id))

    def list_incidents(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
        severity: str | None = None,
        search: str | None = None,
    ) -> list[Incident]:
        stmt = select(Incident)
        conditions = []
        if status:
            conditions.append(Incident.status == status)
        if severity:
            conditions.append(Incident.severity == severity)
        if search:
            like = f"%{search}%"
            conditions.append(
                or_(Incident.title.like(like), Incident.summary.like(like), Incident.incident_id.like(like))
            )
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(desc(Incident.updated_at)).limit(min(max(limit, 1), 500)).offset(max(offset, 0))
        return list(self.session.scalars(stmt))

    def open_incidents_for_sources(self, sources: Iterable[str], *, window_minutes: int = 60) -> list[Incident]:
        sources = [s for s in sources if s]
        if not sources:
            return []
        since = utcnow() - timedelta(minutes=window_minutes)
        stmt = select(Incident).where(
            Incident.updated_at >= since,
            Incident.status.notin_([IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value]),
        )
        incidents = list(self.session.scalars(stmt))
        matching = []
        for incident in incidents:
            entities = set(incident.source_entities or [])
            if entities & set(sources):
                matching.append(incident)
        return matching

    def incident_totals(self) -> dict:
        open_states = [
            IncidentStatus.OPEN.value,
            IncidentStatus.INVESTIGATING.value,
            IncidentStatus.CONTAINED.value,
        ]
        total = int(self.session.scalar(select(func.count(Incident.id))) or 0)
        open_count = int(
            self.session.scalar(
                select(func.count(Incident.id)).where(Incident.status.in_(open_states))
            )
            or 0
        )
        return {"total": total, "open": open_count}

    # -------------------------------------------------------------- notes
    def add_note(
        self,
        *,
        note: str,
        alert_id: str | None = None,
        incident_id: str | None = None,
        author_id: int | None = None,
        action_taken: str | None = None,
    ) -> InvestigationNote:
        entry = InvestigationNote(
            note=note,
            alert_id=alert_id,
            incident_id=incident_id,
            author_id=author_id,
            action_taken=action_taken,
        )
        self.session.add(entry)
        self.session.flush()
        return entry

    def list_notes(
        self, *, alert_id: str | None = None, incident_id: str | None = None, limit: int = 100
    ) -> list[InvestigationNote]:
        stmt = select(InvestigationNote)
        if alert_id:
            stmt = stmt.where(InvestigationNote.alert_id == alert_id)
        if incident_id:
            stmt = stmt.where(InvestigationNote.incident_id == incident_id)
        return list(self.session.scalars(stmt.order_by(desc(InvestigationNote.created_at)).limit(limit)))

    # ------------------------------------------------------- predictions
    def add_prediction(self, prediction: ModelPrediction) -> ModelPrediction:
        self.session.add(prediction)
        return prediction

    def list_predictions(self, *, limit: int = 100, anomalies_only: bool = False) -> list[ModelPrediction]:
        stmt = select(ModelPrediction)
        if anomalies_only:
            stmt = stmt.where(ModelPrediction.is_anomaly.is_(True))
        return list(self.session.scalars(stmt.order_by(desc(ModelPrediction.created_at)).limit(limit)))

    def model_statistics(self, *, minutes: int = 1440) -> list[dict]:
        since = utcnow() - timedelta(minutes=minutes)
        stmt = (
            select(
                ModelPrediction.model_name,
                ModelPrediction.model_version,
                func.count(ModelPrediction.id),
                func.sum(case((ModelPrediction.is_anomaly.is_(True), 1), else_=0)),
                func.avg(ModelPrediction.anomaly_score),
                func.avg(ModelPrediction.latency_ms),
            )
            .where(ModelPrediction.created_at >= since)
            .group_by(ModelPrediction.model_name, ModelPrediction.model_version)
        )
        results = []
        for name, version, count, anomalies, avg_score, avg_latency in self.session.execute(stmt):
            results.append(
                {
                    "model_name": name,
                    "model_version": version,
                    "predictions": int(count or 0),
                    "anomalies": int(anomalies or 0),
                    "avg_score": float(avg_score or 0.0),
                    "avg_latency_ms": float(avg_latency or 0.0),
                }
            )
        return results

    # ------------------------------------------------------- system logs
    def log_system(
        self,
        *,
        message: str,
        level: str = "INFO",
        category: str = LogCategory.SYSTEM.value,
        actor: str | None = None,
        actor_id: int | None = None,
        request_id: str | None = None,
        source: str | None = None,
        details: dict | None = None,
    ) -> SystemLog:
        entry = SystemLog(
            message=message[:8000],
            level=level.upper(),
            category=category,
            actor=actor,
            actor_id=actor_id,
            request_id=request_id,
            source=source,
            details=details or {},
        )
        self.session.add(entry)
        return entry

    def list_system_logs(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        level: str | None = None,
        category: str | None = None,
        search: str | None = None,
    ) -> list[SystemLog]:
        stmt = select(SystemLog)
        conditions = []
        if level:
            conditions.append(SystemLog.level == level.upper())
        if category:
            conditions.append(SystemLog.category == category.upper())
        if search:
            conditions.append(SystemLog.message.like(f"%{search}%"))
        if conditions:
            stmt = stmt.where(and_(*conditions))
        return list(
            self.session.scalars(
                stmt.order_by(desc(SystemLog.timestamp)).limit(min(limit, 500)).offset(max(offset, 0))
            )
        )

    # ----------------------------------------------------------- metrics
    def add_metrics(self, snapshot: MetricsSnapshot) -> MetricsSnapshot:
        self.session.add(snapshot)
        return snapshot

    def latest_metrics(self) -> MetricsSnapshot | None:
        return self.session.scalar(select(MetricsSnapshot).order_by(desc(MetricsSnapshot.captured_at)).limit(1))

    def metrics_series(self, *, limit: int = 60) -> list[MetricsSnapshot]:
        rows = list(
            self.session.scalars(
                select(MetricsSnapshot).order_by(desc(MetricsSnapshot.captured_at)).limit(limit)
            )
        )
        return list(reversed(rows))

    # ------------------------------------------------- config overrides
    def get_config_overrides(self) -> dict[str, Any]:
        rows = self.session.scalars(select(ConfigOverride))
        return {row.key: row.value for row in rows}

    def set_config_override(self, key: str, value: Any, *, updated_by: str | None = None) -> ConfigOverride:
        row = self.session.get(ConfigOverride, key)
        if row is None:
            row = ConfigOverride(key=key, value=value, updated_by=updated_by)
            self.session.add(row)
        else:
            row.value = value
            row.updated_by = updated_by
            row.updated_at = utcnow()
        self.session.flush()
        return row

    # --------------------------------------------------------- retention
    def purge_older_than(self, *, days: int, dry_run: bool = False) -> dict[str, int]:
        """Delete data older than ``days`` (spec: historical data management)."""
        cutoff = utcnow() - timedelta(days=max(days, 1))
        counts: dict[str, int] = {}
        for model, column in (
            (Event, Event.timestamp),
            (Alert, Alert.last_seen),
            (Detection, Detection.matched_at),
            (ModelPrediction, ModelPrediction.created_at),
            (MetricsSnapshot, MetricsSnapshot.captured_at),
            (SystemLog, SystemLog.timestamp),
            (RefreshToken, RefreshToken.expires_at),
        ):
            condition = column < cutoff
            if dry_run:
                counts[model.__tablename__] = int(
                    self.session.scalar(select(func.count()).select_from(model).where(condition)) or 0
                )
            else:
                result = self.session.execute(delete(model).where(condition))
                counts[model.__tablename__] = int(result.rowcount or 0)
        return counts


__all__ = ["Repository", "RepositoryError"]
