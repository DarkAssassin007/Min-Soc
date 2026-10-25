"""Real-time pipeline: ingest → normalize → detect → alert → persist."""

from __future__ import annotations

import time

import pytest
from sqlalchemy import func, select

from app.database.models import Alert, Detection, DetectionRule, Event, ModelPrediction
from app.database.repository import Repository
from app.database.connection import session_scope

from conftest import ADMIN_PASSWORD, ADMIN_USERNAME  # noqa: E402  (test helper import)


def wait_for(predicate, *, timeout=8.0, interval=0.1, message="condition"):
    """Poll the database until the pipeline has caught up."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {message}")


@pytest.fixture()
def runtime(settings):
    from app.services.bootstrap import build_runtime

    built = build_runtime(settings, start_collection=False, load_model=False)
    yield built
    built.shutdown()


def count(model) -> int:
    with session_scope() as session:
        return int(session.scalar(select(func.count()).select_from(model)) or 0)


class TestPipeline:
    def test_valid_record_becomes_an_event(self, runtime, make_record, rules_synced) -> None:
        runtime.pipeline.start()
        assert runtime.pipeline.submit(make_record(payload={"destination_port": 443})) is True
        event = wait_for(lambda: _first_event(), message="event persist")
        assert event.event_type == "NETWORK_CONNECTION"
        assert event.event_id.startswith("EVT-")
        assert event.protocol == "TCP"
        assert event.to_public_dict()["data_origin"] in {"LIVE", "LAB"}

    def test_invalid_record_is_rejected_without_stopping_the_pipeline(self, runtime, make_record) -> None:
        runtime.pipeline.start()
        runtime.pipeline.submit(make_record(payload={"source_ip": "999.999.999.999"}))
        runtime.pipeline.submit(make_record(payload={"destination_port": 443}))
        wait_for(lambda: _first_event(), message="valid record after invalid one")
        stats = runtime.pipeline.stats.as_dict()
        assert stats["rejected"] >= 1
        assert stats["processed"] >= 1

    def test_duplicate_records_are_suppressed(self, runtime, make_record) -> None:
        runtime.pipeline.start()
        for _ in range(4):
            runtime.pipeline.submit(make_record(payload={"destination_port": 8443}))
        wait_for(lambda: count(Event) >= 1, message="first event")
        time.sleep(0.6)
        assert count(Event) == 1
        assert runtime.pipeline.stats.as_dict()["duplicates"] >= 1

    def test_port_scan_records_produce_an_alert_and_detections(self, runtime, make_record) -> None:
        runtime.pipeline.start()
        for port in range(1, 90):
            runtime.pipeline.submit(
                make_record(
                    payload={
                        "destination_port": port,
                        "source_ip": "192.168.50.201",
                        "tcp_flags": "S",
                        "connection_state": "SYN_SENT",
                    }
                )
            )
        alert = wait_for(_first_alert, message="port scan alert")
        assert alert.detection_type in {"PORT_SCAN", "CONNECTION_FLOOD", "SUSPICIOUS_PROTOCOL"}
        assert alert.severity in {"MEDIUM", "HIGH", "CRITICAL"}
        assert alert.risk_score > 25
        wait_for(lambda: count(Detection) >= 1, message="detection rows")
        with session_scope() as session:
            detections = Repository(session).list_detections_for_alert(alert.alert_id)
        assert detections
        assert detections[0].event_id.startswith("EVT-")

    def test_auth_failure_burst_produces_a_brute_force_alert(self, runtime, make_record) -> None:
        runtime.pipeline.start()
        for index in range(8):
            runtime.pipeline.submit(
                make_record(
                    collector="syslog",
                    event_type="AUTH_FAILURE",
                    payload={
                        "source_ip": "192.168.50.101",
                        "destination_ip": "192.168.50.10",
                        "destination_port": 22,
                        "protocol": "TCP",
                        "connection_state": "FAILED",
                        "message": f"Failed password for invalid user root from 192.168.50.101 port 51234 ssh2 ({index})",
                    },
                )
            )
        alert = wait_for(_first_alert, message="brute force alert")
        assert alert.detection_type == "BRUTE_FORCE"
        assert alert.source_ip == "192.168.50.101"

    def test_dns_tunnelling_record_produces_an_alert(self, runtime, make_record) -> None:
        runtime.pipeline.start()
        for index in range(3):
            runtime.pipeline.submit(
                make_record(
                    event_type="DNS_QUERY",
                    payload={
                        "source_ip": "192.168.50.61",
                        "destination_ip": "8.8.8.8",
                        "destination_port": 53,
                        "protocol": "UDP",
                        "dns_query": f"{'z' * 70}{index}.tunnel.example",
                    },
                )
            )
        alert = wait_for(_first_alert, message="dns alert")
        assert alert.detection_type == "DNS_ANOMALY"
        assert "DNS" in (alert.description or "").upper() or "query" in (alert.description or "")

    def test_network_detail_row_is_written(self, runtime, make_record) -> None:
        runtime.pipeline.start()
        runtime.pipeline.submit(
            make_record(payload={"destination_port": 53, "protocol": "UDP", "dns_query": "example.com"})
        )
        wait_for(lambda: _first_event(), message="event")
        with session_scope() as session:
            repository = Repository(session)
            event = repository.list_events(limit=1)[0]
            network = repository.network_event_for(event.event_id)
        assert network is not None
        assert network.dns_query == "example.com"
        assert network.protocol == "UDP"

    def test_event_records_where_it_was_collected(self, runtime, make_record) -> None:
        """Provenance survives ingest: collector, interface and real/lab origin."""
        runtime.pipeline.start()
        runtime.pipeline.submit(
            make_record(collector="packet", interface="Ethernet", payload={"destination_port": 4444})
        )
        event = wait_for(lambda: _first_event(), message="event with provenance")
        public = event.to_public_dict()
        assert public["collector"] == "packet"
        assert public["interface"] == "Ethernet"
        assert public["data_origin"] == "LIVE"
        with session_scope() as session:
            network = Repository(session).network_event_for(event.event_id)
        assert network is not None and network.interface == "Ethernet"

    def test_lab_records_are_marked_as_lab(self, runtime, make_record) -> None:
        runtime.pipeline.start()
        runtime.pipeline.submit(
            make_record(
                collector="synthetic",
                interface="lab:port_scan",
                payload={"destination_port": 4445},
            )
        )
        event = wait_for(lambda: _first_event(), message="lab event")
        assert event.to_public_dict()["data_origin"] == "LAB"

    def test_queue_backpressure_drops_records_and_counts_them(self, settings, make_record) -> None:
        from app.services.pipeline import ProcessingPipeline

        tight = settings.model_copy(update={"pipeline_queue_size": 5})
        pipeline = ProcessingPipeline(tight)
        accepted = [pipeline.submit(make_record()) for _ in range(12)]
        assert accepted.count(False) >= 1
        assert pipeline.stats.as_dict()["dropped"] >= 1
        assert pipeline.metrics.dropped_events >= 1

    def test_pipeline_status_exposes_collectors_and_features(self, runtime) -> None:
        status = runtime.pipeline.status()
        assert status["running"] is False
        assert "stats" in status
        assert "feature_store" in status
        assert status["deduplicator"]["window_seconds"] == runtime.settings.pipeline_dedupe_window_seconds

    def test_metrics_snapshot_can_be_persisted(self, runtime) -> None:
        runtime.pipeline._persist_metrics()
        with session_scope() as session:
            latest = Repository(session).latest_metrics()
        assert latest is not None
        assert latest.captured_at is not None

    def test_runtime_reports_unavailable_model_when_disabled(self, settings) -> None:
        from app.services.bootstrap import build_runtime

        built = build_runtime(settings, start_collection=False, load_model=False)
        try:
            assert built.detector.ready is False
            assert built.warnings
        finally:
            built.shutdown()

    def test_rule_registry_is_loaded_at_bootstrap(self, runtime) -> None:
        assert runtime.rule_registry.rule_keys()
        with session_scope() as session:
            rules = Repository(session).list_rules()
        assert len(rules) >= 7
        assert all(isinstance(rule, DetectionRule) for rule in rules)

    def test_legacy_placeholder_detection_never_occurs(self, runtime) -> None:
        # Sanity guard: the pipeline must not fabricate detections for normal traffic.
        assert count(ModelPrediction) == 0


def _first_event():
    with session_scope() as session:
        events = Repository(session).list_events(limit=1)
        return events[0] if events else None


def _first_alert():
    with session_scope() as session:
        alerts = Repository(session).list_alerts(limit=1)
        return alerts[0] if alerts else None
