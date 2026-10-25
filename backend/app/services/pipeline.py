"""Real-time processing pipeline (spec section 5).

    RawRecord -> parse -> validate -> normalise -> dedupe -> persist
              -> features -> detect (rules + ML) -> risk -> alerts/incidents
              -> broadcast -> metrics

Implementation notes that matter in production:

* Collector threads never touch the database. They push into a bounded queue;
  when the queue is full the record is dropped and the drop is counted, so a
  burst degrades by dropping rather than by freezing.
* Worker threads pull small batches and commit them in a single transaction,
  which keeps SQLite happy and keeps latency low (one commit per batch, not per
  event) without introducing a second write pipeline.
* Only the pipeline writes event/detection rows; the API writes go through their
  own session, and SQLite's WAL mode lets readers run concurrently.
* Everything after a successful commit (WebSocket broadcast, metrics) happens
  outside the transaction, so a slow subscriber can never block ingestion.
"""

from __future__ import annotations

import queue
import threading
import time
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable

from ..alerts.manager import AlertManager
from ..config.logging_config import get_logger, request_id_var
from ..database.connection import session_scope, write_lock
from ..database.context import RepositoryProxy
from ..database.models import Detection, Event, ModelPrediction, NetworkEvent
from ..database.repository import Repository
from ..detection.engine import DetectionEngine
from ..processors.feature_engineering import FeatureExtractor
from ..processors.deduplicator import Deduplicator
from ..processors.models import RawRecord
from ..processors.normalizer import normalise
from ..processors.parser import parse_record
from ..processors.validator import ValidationError, validate
from ..risk.scoring import RiskEngine
from .metrics import MetricsCollector

logger = get_logger(__name__)

Broadcaster = Callable[[str, dict], None]

#: How long a worker waits to gather more records into one transaction.
BATCH_WINDOW_SECONDS = 0.05


@dataclass
class PipelineStats:
    """Counters exposed by ``/api/v1/system/metrics``."""

    received: int = 0
    processed: int = 0
    rejected: int = 0
    duplicates: int = 0
    dropped: int = 0
    batches: int = 0
    errors: int = 0
    last_error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "received": self.received,
            "processed": self.processed,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "dropped": self.dropped,
            "batches": self.batches,
            "errors": self.errors,
            "last_error": self.last_error,
            **self.detail,
        }


@dataclass
class _PreparedRecord:
    """A record that passed preprocessing and is ready for detection."""

    record: RawRecord
    event: Event
    normalized: Any
    features: Any


class ProcessingPipeline:
    """Owns the worker threads, feature store and detection orchestration."""

    def __init__(
        self,
        settings: Any,
        *,
        broadcaster: Broadcaster | None = None,
        repository: "RepositoryProxy | None" = None,
        owner: str = "api",
    ) -> None:
        self.settings = settings
        self.owner = owner
        self.broadcaster = broadcaster
        self.repository = repository or RepositoryProxy()

        self.queue: "queue.Queue[RawRecord]" = queue.Queue(maxsize=settings.pipeline_queue_size)
        self.features = FeatureExtractor(
            window_seconds=settings.pipeline_feature_window_seconds,
            max_entities=5000,
            max_observations=2000,
        )
        self.dedupe = Deduplicator(
            window_seconds=settings.pipeline_dedupe_window_seconds,
            max_entries=settings.pipeline_dedupe_max_entries,
        )
        self.metrics = MetricsCollector()
        self.stats = PipelineStats()

        # wired by :func:`app.services.bootstrap.build_runtime`
        self.rules: Any | None = None
        self.detector: Any | None = None
        self.engine: DetectionEngine | None = None
        self.risk: RiskEngine | None = None
        self.alerts: AlertManager | None = None

        self.collectors: list[Any] = []
        self._workers: list[threading.Thread] = []
        self._maintenance: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._started_at: float | None = None
        self._last_maintenance: dict[str, float] = {}

    # --------------------------------------------------------------- wiring
    def attach(
        self,
        *,
        rules: Any,
        detector: Any,
        engine: DetectionEngine,
        risk: RiskEngine,
        alerts: AlertManager,
    ) -> None:
        self.rules = rules
        self.detector = detector
        self.engine = engine
        self.risk = risk
        self.alerts = alerts

    def attach_collector(self, collector: Any) -> None:
        self.collectors.append(collector)

    # ------------------------------------------------------------ ingestion
    def submit(self, record: RawRecord) -> bool:
        """Thread-safe, non-blocking record submission (collector sink)."""
        with self._lock:
            self.stats.received += 1
        try:
            self.queue.put_nowait(record)
            return True
        except queue.Full:
            with self._lock:
                self.stats.dropped += 1
            self.metrics.record_drop()
            if self.stats.dropped % 100 == 1:
                logger.warning(
                    "pipeline queue full - dropping records",
                    extra={"dropped": self.stats.dropped, "queue_size": self.settings.pipeline_queue_size},
                )
            return False

    # ----------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self._started_at is not None:
            return
        self._stop_event.clear()
        for index in range(max(int(self.settings.pipeline_workers), 1)):
            thread = threading.Thread(
                target=self._worker, name=f"pipeline-worker-{index}", daemon=True
            )
            thread.start()
            self._workers.append(thread)
        self._maintenance = threading.Thread(
            target=self._maintain, name="pipeline-maintenance", daemon=True
        )
        self._maintenance.start()
        self._started_at = time.time()
        for collector in self.collectors:
            started = collector.start()
            if not started:
                logger.warning(
                    "collector did not start",
                    extra={"collector": getattr(collector, "name", "unknown")},
                )
        logger.info(
            "pipeline started",
            extra={
                "workers": len(self._workers),
                "collectors": [getattr(c, "name", "?") for c in self.collectors],
            },
        )

    def stop(self, *, timeout: float = 5.0) -> None:
        self._stop_event.set()
        for collector in self.collectors:
            try:
                collector.stop()
            except Exception as exc:  # pragma: no cover
                logger.warning("collector stop failed", extra={"error": str(exc)})
        for thread in self._workers:
            thread.join(timeout=timeout)
        if self._maintenance is not None:
            self._maintenance.join(timeout=timeout)
            self._maintenance = None
        self._workers.clear()
        self._started_at = None
        logger.info("pipeline stopped", extra={"stats": self.stats.as_dict()})

    @property
    def running(self) -> bool:
        return self._started_at is not None

    # -------------------------------------------------------------- workers
    def _worker(self) -> None:  # pragma: no cover - threaded loop
        batch_size = max(int(self.settings.db_write_batch_size), 1)
        while not self._stop_event.is_set():
            records = self._collect_batch(batch_size)
            if not records:
                continue
            try:
                self._process_batch(records)
            except Exception as exc:
                with self._lock:
                    self.stats.errors += 1
                    self.stats.last_error = f"{type(exc).__name__}: {exc}"
                logger.error("pipeline batch failed", extra={"error": str(exc)}, exc_info=True)

    def _collect_batch(self, batch_size: int) -> list[RawRecord]:
        """Wait for work, then gather a small batch without adding much latency.

        The batch window trades commit count against end-to-end latency: at 40
        events/s it groups a few records per commit, at 1000 events/s it groups
        dozens, and a single event still flows through in well under 100 ms.
        """
        try:
            first = self.queue.get(timeout=0.5)
        except queue.Empty:
            return []
        batch = [first]
        deadline = time.monotonic() + BATCH_WINDOW_SECONDS
        while len(batch) < batch_size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                batch.append(self.queue.get(timeout=min(remaining, 0.02)))
            except queue.Empty:
                continue
        return batch

    # ------------------------------------------------------------ processing
    def _process_batch(self, records: list[RawRecord]) -> None:
        broadcast_events: list[dict[str, Any]] = []
        started = time.perf_counter()
        commit_ms = 0.0

        # SQLite is a single-writer engine: serialise whole batches so two
        # workers can never deadlock on a read-to-write upgrade (PostgreSQL and
        # other multi-writer backends skip the lock and keep full parallelism).
        with self._write_guard(), session_scope() as session:
            repository = Repository(session)
            self.repository.bind(repository)

            # Pass 1: preprocess every record. Detection runs in pass 2 so the
            # ML model scores the whole batch with one call - scikit-learn
            # dispatches a parallel job per scoring call, which would cost
            # milliseconds *per event* if each event were scored on its own.
            prepared: list[_PreparedRecord] = []
            for record in records:
                request_id_var.set(f"pipe-{record.collector}")
                try:
                    # A savepoint per record: one malformed record rolls back
                    # only its own work, never the rest of the batch.
                    with session.begin_nested():
                        context = self._prepare(repository, record)
                except Exception as exc:
                    with self._lock:
                        self.stats.errors += 1
                        self.stats.last_error = f"{type(exc).__name__}: {exc}"
                    logger.error(
                        "record processing failed",
                        extra={"collector": record.collector, "error": str(exc)},
                    )
                    self.metrics.record_event(accepted=False)
                    continue
                if context is not None:
                    prepared.append(context)

            # Pass 2: batch detection, then rules -> risk -> alerts per record.
            if prepared:
                detections = self._detect_batch(repository, prepared)
                for context, detection in zip(prepared, detections):
                    request_id_var.set(f"pipe-{context.record.collector}")
                    try:
                        with session.begin_nested():
                            self._finalise(repository, context, detection)
                    except Exception as exc:
                        with self._lock:
                            self.stats.errors += 1
                            self.stats.last_error = f"{type(exc).__name__}: {exc}"
                        logger.error(
                            "record finalisation failed",
                            extra={"collector": context.record.collector, "error": str(exc)},
                        )
                        self.metrics.record_event(accepted=False)
                        continue
                    broadcast_events.append(context.event.to_public_dict())

            # Commit explicitly so the measured database latency is the real
            # write cost (session_scope's own commit is then a no-op).
            commit_started = time.perf_counter()
            session.flush()
            session.commit()
            commit_ms = (time.perf_counter() - commit_started) * 1000.0
            self.repository.unbind()

        # ------------------------------------------------------- post-commit
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        # Processing latency is reported per event so it stays comparable when
        # the batch window changes with load.
        per_event_ms = elapsed_ms / max(len(broadcast_events), 1) if broadcast_events else elapsed_ms
        self.metrics.external.add(per_event_ms)
        self.metrics.database.add(commit_ms)
        with self._lock:
            self.stats.batches += 1
            self.stats.processed += len(broadcast_events)

        if broadcast_events and self.broadcaster is not None:
            broadcast_started = time.perf_counter()
            try:
                # Channel name must match the WebSocket route (/ws/live).
                self.broadcaster("live", {"type": "events", "data": broadcast_events})
                self.metrics.broadcasts += 1
            except Exception as exc:
                self.metrics.broadcast_failures += 1
                logger.warning("event broadcast failed", extra={"error": str(exc)})
            finally:
                self.metrics.websocket.add((time.perf_counter() - broadcast_started) * 1000.0)

    def _detect_batch(
        self, repository: Repository, prepared: list[_PreparedRecord]
    ) -> list[Any]:
        """Run detection for a whole batch (one ML model call for all events)."""
        if self.engine is None or self.risk is None or self.alerts is None:
            return [None] * len(prepared)
        items = [(context.normalized, context.features) for context in prepared]
        return self.engine.detect_many(items, repository=repository)

    def _prepare(self, repository: Repository, record: RawRecord) -> "_PreparedRecord | None":
        """Preprocess one record: parse, validate, normalise, persist, featurise."""
        collector_received = record.received_at
        candidate = parse_record(record)
        try:
            clean = validate(candidate)
        except ValidationError as exc:
            with self._lock:
                self.stats.rejected += 1
            self.metrics.record_event(accepted=False)
            logger.debug(
                "record rejected by validation",
                extra={"collector": record.collector, "reason": str(exc)},
            )
            return None

        normalized = normalise(clean)
        if normalized.dedupe_hash and self.dedupe.is_duplicate(normalized.dedupe_hash):
            with self._lock:
                self.stats.duplicates += 1
            self.metrics.record_event(accepted=False, duplicate=True)
            return None

        event = Event(
            event_id=repository.next_id("event", "EVT"),
            timestamp=normalized.timestamp,
            source_ip=normalized.source_ip,
            destination_ip=normalized.destination_ip,
            source_port=normalized.source_port,
            destination_port=normalized.destination_port,
            protocol=normalized.protocol,
            packet_count=normalized.packet_count,
            bytes=normalized.bytes,
            connection_state=normalized.connection_state,
            event_type=normalized.event_type,
            direction=normalized.direction,
            interface=normalized.interface,
            collector=normalized.collector,
            dedupe_hash=normalized.dedupe_hash,
            meta=normalized.metadata or {},
        )
        repository.add_event(event)
        repository.session.flush()

        network = normalized.network or {}
        if network or normalized.protocol not in {"OTHER"}:
            nature = NetworkEvent(
                event_id=event.event_id,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                source_port=event.source_port,
                destination_port=event.destination_port,
                protocol=event.protocol,
                tcp_flags=network.get("tcp_flags"),
                duration_ms=_optional_float(network.get("duration_ms")),
                packets=event.packet_count,
                bytes=event.bytes,
                dns_query=network.get("dns_query"),
                dns_qtype=network.get("dns_qtype"),
                dns_rcode=network.get("dns_rcode"),
                http_host=network.get("http_host"),
                http_method=network.get("http_method"),
                tls_sni=network.get("tls_sni"),
                icmp_type=network.get("icmp_type"),
                arp_op=network.get("arp_op"),
                interface=network.get("interface") or event.interface,
                capture_source=network.get("capture_source") or record.collector,
                meta=network.get("meta") or {},
            )
            repository.session.add(nature)

        # Features include the current event so a burst sees itself immediately.
        self.features.add_event(normalized)
        features = self.features.features(normalized.entity_key())
        self.metrics.collector_latency.add(
            max((normalized.timestamp - collector_received).total_seconds() * 1000.0, 0.0)
        )
        return _PreparedRecord(record=record, event=event, normalized=normalized, features=features)

    def _finalise(self, repository: Repository, context: "_PreparedRecord", detection: Any) -> None:
        """Risk-score and alert for one prepared record (after batch detection)."""
        event = context.event
        normalized = context.normalized
        detection_rows: list[Detection] = []
        outcome = None
        processing_events = 0
        if detection is not None:
            self.metrics.detection.add(float(detection.latency_ms))
            assessment = self.risk.assess(
                normalized,
                detection,
                context.features,
                asset_importance=repository.asset_importance(normalized.source_ip),
            )
            event.risk_score = assessment.score
            event.severity = assessment.severity
            event.confidence = assessment.confidence
            event.detection_hits = len(detection.rule_hits)
            if detection.anomaly is not None:
                event.anomaly_score = detection.anomaly.anomaly_score

            for hit in detection.rule_hits:
                detection_rows.append(
                    Detection(
                        detection_id=repository.next_id("detection", "DET"),
                        event_id=event.event_id,
                        rule_key=hit.rule_key,
                        detection_type=hit.detection_type,
                        engine="RULE",
                        matched_at=event.timestamp,
                        rule_score=hit.score,
                        confidence=hit.confidence,
                        description=hit.description,
                        evidence=hit.evidence,
                    )
                )
            anomaly = detection.anomaly
            if anomaly is not None and anomaly.is_anomaly:
                detection_rows.append(
                    Detection(
                        detection_id=repository.next_id("detection", "DET"),
                        event_id=event.event_id,
                        rule_key="ML_ANOMALY",
                        detection_type="ML_ANOMALY",
                        engine="ML",
                        matched_at=event.timestamp,
                        rule_score=anomaly.risk_contribution(),
                        anomaly_score=anomaly.anomaly_score,
                        confidence=anomaly.confidence,
                        description=(
                            f"ML anomaly detected by {anomaly.model_name}:{anomaly.model_version} "
                            f"(score {anomaly.anomaly_score:.3f})"
                        ),
                        evidence={
                            "model": anomaly.model_name,
                            "version": anomaly.model_version,
                            "threshold": anomaly.threshold,
                            "features": anomaly.features,
                        },
                    )
                )
            if anomaly is not None:
                repository.add_prediction(
                    ModelPrediction(
                        event_id=event.event_id,
                        model_name=anomaly.model_name,
                        model_version=anomaly.model_version,
                        anomaly_score=anomaly.anomaly_score,
                        is_anomaly=anomaly.is_anomaly,
                        threshold=anomaly.threshold,
                        features=anomaly.features,
                        latency_ms=anomaly.latency_ms,
                    )
                )

            if detection_rows:
                repository.add_detections(detection_rows)

            alert_started = time.perf_counter()
            outcome = self.alerts.process(event, normalized, detection, assessment, detection_rows)
            self.metrics.alert.add((time.perf_counter() - alert_started) * 1000.0)
            processing_events = len(detection_rows)
            if outcome is not None and outcome.alert is not None:
                self.metrics.record_alert(
                    created=outcome.created,
                    linked_to_incident=self._alert_in_incident(outcome),
                )

        self.metrics.record_event(accepted=True)
        if outcome is not None and outcome.alert is not None:
            repository.log_system(
                message=f"event {event.event_id} produced alert {outcome.alert.alert_id}",
                category="DETECTION",
                level="WARNING" if event.severity in {"HIGH", "CRITICAL"} else "INFO",
                request_id=request_id_var.get(),
                details={
                    "event_id": event.event_id,
                    "alert_id": outcome.alert.alert_id,
                    "severity": event.severity,
                    "risk_score": event.risk_score,
                    "detections": processing_events,
                },
            )
        return None

    @staticmethod
    def _alert_in_incident(outcome: Any) -> bool:
        """Whether the alert produced by this event belongs to an incident."""
        try:
            alert = outcome.alert
            return bool(alert is not None and alert.incident_id)
        except Exception:  # pragma: no cover - defensive
            return False

    # -------------------------------------------------------- maintenance
    def _maintain(self) -> None:  # pragma: no cover - timed loop
        while not self._stop_event.is_set():
            self._stop_event.wait(5)
            if self._stop_event.is_set():
                break
            now = time.monotonic()
            try:
                if self.rules is not None and self._due("rules", now, self.settings.rules_reload_seconds):
                    with session_scope() as session:
                        self.repository.bind(Repository(session))
                        try:
                            self.rules.refresh()
                        finally:
                            self.repository.unbind()
                    logger.debug("detection rules reloaded")
                if self._due("metrics", now, 15):
                    self._persist_metrics()
                if self._due("retention", now, 6 * 3600):
                    self._purge_retention()
            except Exception as exc:
                logger.error("pipeline maintenance failed", extra={"error": str(exc)})

    def _due(self, key: str, now: float, interval: float) -> bool:
        last = self._last_maintenance.get(key, 0.0)
        if now - last >= max(float(interval), 1.0):
            self._last_maintenance[key] = now
            return True
        return False

    def _write_guard(self) -> Any:
        """Serialise our own writes on single-writer backends (SQLite)."""
        if str(self.settings.database_url or "").startswith("sqlite"):
            return write_lock
        return nullcontext()

    def _persist_metrics(self) -> None:
        snapshot = self.metrics.snapshot(
            queue_depth=self.queue.qsize(),
            collectors={getattr(c, "name", "?"): c.status() for c in self.collectors},
        )
        with self._write_guard(), session_scope() as session:
            Repository(session).add_metrics(self.metrics.to_model(snapshot))

    def _purge_retention(self) -> None:
        with self._write_guard(), session_scope() as session:
            deleted = Repository(session).purge_older_than(days=self.settings.pipeline_retention_days)
        logger.info("retention purge complete", extra={"deleted": deleted})

    # -------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "owner": self.owner,
            "queue_depth": self.queue.qsize(),
            "queue_capacity": self.settings.pipeline_queue_size,
            "workers": len(self._workers),
            "stats": self.stats.as_dict(),
            "feature_store": self.features.statistics(),
            "deduplicator": self.dedupe.stats(),
            "collectors": {getattr(c, "name", "?"): c.status() for c in self.collectors},
        }

    def metrics_snapshot(self) -> dict[str, Any]:
        return self.metrics.snapshot(
            queue_depth=self.queue.qsize(),
            collectors={getattr(c, "name", "?"): c.status() for c in self.collectors},
        )


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


__all__ = ["Broadcaster", "PipelineStats", "ProcessingPipeline"]
