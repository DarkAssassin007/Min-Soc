"""Detection rules, the detection engine and the risk engine."""

from __future__ import annotations

import pytest

from app.database.repository import Repository
from app.detection.engine import DetectionEngine
from app.detection.rules.registry import RuleRegistry, load_rule_packs
from app.processors.feature_engineering import FeatureExtractor
from app.risk.scoring import RiskEngine


@pytest.fixture()
def registry(settings, rules_synced) -> RuleRegistry:
    from app.database.connection import session_scope

    with session_scope() as session:
        registry = RuleRegistry(Repository(session), settings.rules_path)
        registry.refresh()
        return registry


@pytest.fixture()
def detection_engine(registry, settings) -> DetectionEngine:
    return DetectionEngine(registry, anomaly_detector=None, settings=settings)


def detect(detection_engine, repository, event, features):
    return detection_engine.detect(event, features, repository=repository)


def build_features(extractor, event):
    extractor.add_event(event)
    return extractor.features(event.source_ip)


class TestRulePacks:
    def test_shipped_packs_are_valid_and_complete(self, settings) -> None:
        packs = load_rule_packs(settings.rules_path)
        keys = {entry["rule_key"] for entry in packs}
        assert {
            "PORT_SCAN",
            "BRUTE_FORCE",
            "FAILED_CONNECTIONS",
            "CONNECTION_FLOOD",
            "SUSPICIOUS_PROTOCOL",
            "DNS_ANOMALY",
            "VOLUME_ANOMALY",
        } <= keys
        for entry in packs:
            assert entry["name"]
            assert entry["window_seconds"] > 0
            assert isinstance(entry["params"], dict)

    def test_rules_are_loaded_into_the_database(self, registry) -> None:
        assert "PORT_SCAN" in registry.rule_keys()
        assert len(registry.rules) >= 7

    def test_disabled_rules_are_skipped(self, settings, rules_synced, registry) -> None:
        from app.database.connection import session_scope

        with session_scope() as session:
            Repository(session).set_rule_enabled("PORT_SCAN", False)
        registry.refresh()
        assert "PORT_SCAN" not in registry.rule_keys()


class TestPortScanRule:
    def test_scan_fires_on_many_ports(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = None
        for port in range(1, 60):
            event = make_event(destination_port=port, connection_state="SYN_SENT")
            extractor.add_event(event)
        features = extractor.features("192.168.50.10")
        result = detect(detection_engine, repository, event, features)
        assert "PORT_SCAN" in {hit.rule_key for hit in result.rule_hits}
        hit = next(hit for hit in result.rule_hits if hit.rule_key == "PORT_SCAN")
        assert hit.score > 50
        assert hit.evidence["unique_destination_ports"] >= 15

    def test_quiet_host_does_not_fire(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event(destination_port=443)
        features = build_features(extractor, event)
        result = detect(detection_engine, repository, event, features)
        assert result.rule_hits == []


class TestBruteForceRule:
    def test_repeated_auth_failures_fire(self, detection_engine, repository, make_event, session) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = None
        for index in range(6):
            event = make_event(
                source_ip="10.0.0.9",
                event_type="AUTH_FAILURE",
                destination_port=22,
                connection_state="FAILED",
                metadata={"username": "root", "message": f"Failed password for root ({index})"},
            )
            from app.database.models import Event

            session.add(
                Event(
                    event_id=f"EVT-{index:06d}",
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    destination_port=22,
                    protocol="TCP",
                    event_type="AUTH_FAILURE",
                    severity="LOW",
                    risk_score=0,
                    meta=dict(event.metadata),
                )
            )
            session.commit()
            extractor.add_event(event)
        features = extractor.features("10.0.0.9")
        result = detect(detection_engine, repository, event, features)
        assert "BRUTE_FORCE" in {hit.rule_key for hit in result.rule_hits}

    def test_single_failure_does_not_fire(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event(event_type="AUTH_FAILURE", connection_state="FAILED")
        features = build_features(extractor, event)
        result = detect(detection_engine, repository, event, features)
        assert "BRUTE_FORCE" not in {hit.rule_key for hit in result.rule_hits}


class TestConnectionFloodRule:
    def test_high_connection_rate_fires(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = None
        for index in range(70):
            event = make_event(destination_port=443, connection_state="ESTABLISHED")
            extractor.add_event(event)
        features = extractor.features("192.168.50.10")
        result = detect(detection_engine, repository, event, features)
        assert "CONNECTION_FLOOD" in {hit.rule_key for hit in result.rule_hits}


class TestFailedConnectionsRule:
    def test_failure_storm_fires(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = None
        for index in range(14):
            event = make_event(destination_port=8080, connection_state="FAILED")
            extractor.add_event(event)
        features = extractor.features("192.168.50.10")
        result = detect(detection_engine, repository, event, features)
        assert "FAILED_CONNECTIONS" in {hit.rule_key for hit in result.rule_hits}
        hit = next(hit for hit in result.rule_hits if hit.rule_key == "FAILED_CONNECTIONS")
        assert hit.evidence["failure_ratio"] >= 0.5


class TestSuspiciousProtocolRule:
    def test_telnet_outbound_is_flagged(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event(destination_ip="203.0.113.10", destination_port=23, direction="outbound")
        features = build_features(extractor, event)
        result = detect(detection_engine, repository, event, features)
        assert "SUSPICIOUS_PROTOCOL" in {hit.rule_key for hit in result.rule_hits}

    def test_normal_https_is_not_flagged(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event(destination_port=443, direction="outbound")
        features = build_features(extractor, event)
        result = detect(detection_engine, repository, event, features)
        assert "SUSPICIOUS_PROTOCOL" not in {hit.rule_key for hit in result.rule_hits}

    def test_large_icmp_payload_is_flagged(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event(protocol="ICMP", destination_port=None, bytes=9000)
        features = build_features(extractor, event)
        result = detect(detection_engine, repository, event, features)
        assert "SUSPICIOUS_PROTOCOL" in {hit.rule_key for hit in result.rule_hits}


class TestDnsAnomalyRule:
    def test_long_query_names_fire(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event(
            event_type="DNS_QUERY",
            protocol="UDP",
            destination_port=53,
            network={"dns_query": f"{'a' * 70}.example.com"},
        )
        features = build_features(extractor, event)
        result = detect(detection_engine, repository, event, features)
        assert "DNS_ANOMALY" in {hit.rule_key for hit in result.rule_hits}

    def test_normal_dns_lookup_does_not_fire(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event(
            event_type="DNS_QUERY", protocol="UDP", destination_port=53, network={"dns_query": "example.com"}
        )
        features = build_features(extractor, event)
        result = detect(detection_engine, repository, event, features)
        assert "DNS_ANOMALY" not in {hit.rule_key for hit in result.rule_hits}


class TestVolumeAnomalyRule:
    def test_large_transfer_fires(self, detection_engine, repository, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event(bytes=90_000_000, packet_count=60000)
        features = build_features(extractor, event)
        result = detect(detection_engine, repository, event, features)
        assert "VOLUME_ANOMALY" in {hit.rule_key for hit in result.rule_hits}


class TestRiskEngine:
    def test_score_increases_with_detections(self, settings, detection_engine, repository, make_event) -> None:
        risk = RiskEngine(settings)
        extractor = FeatureExtractor(window_seconds=300)
        quiet = make_event(destination_port=443)
        quiet_features = build_features(extractor, quiet)
        quiet_detection = detect(detection_engine, repository, quiet, quiet_features)
        quiet_assessment = risk.assess(quiet, quiet_detection, quiet_features)

        noisy_features = FeatureExtractor(window_seconds=300)
        noisy_event = None
        for port in range(1, 80):
            noisy_event = make_event(destination_port=port, connection_state="SYN_SENT")
            noisy_features.add_event(noisy_event)
        features = noisy_features.features("192.168.50.10")
        noisy_detection = detect(detection_engine, repository, noisy_event, features)
        noisy_assessment = risk.assess(noisy_event, noisy_detection, features)

        assert noisy_assessment.score > quiet_assessment.score
        assert noisy_assessment.severity in {"HIGH", "CRITICAL"}
        assert quiet_assessment.severity == "LOW"
        assert noisy_assessment.components["rule"] > 0
        assert noisy_assessment.reasons

    def test_asset_importance_raises_the_score(self, settings, detection_engine, repository, make_event) -> None:
        risk = RiskEngine(settings)
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event(destination_ip="203.0.113.5", destination_port=23, direction="outbound")
        features = build_features(extractor, event)
        detection = detect(detection_engine, repository, event, features)
        low_asset = risk.assess(event, detection, features, asset_importance=1)
        critical_asset = risk.assess(event, detection, features, asset_importance=5)
        assert critical_asset.score >= low_asset.score
        assert critical_asset.components["asset"] > low_asset.components["asset"]

    def test_classification_maps_detection_types(self, settings, detection_engine, repository, make_event) -> None:
        risk = RiskEngine(settings)
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event(destination_port=23, destination_ip="203.0.113.5", direction="outbound")
        features = build_features(extractor, event)
        detection = detect(detection_engine, repository, event, features)
        assessment = risk.assess(event, detection, features)
        assert assessment.classification in {"POLICY_VIOLATION", "MULTI_STAGE", "OTHER"}

    def test_weights_are_normalised(self, settings) -> None:
        weights = RiskEngine(settings).weights()
        assert pytest.approx(sum(weights.values()), rel=1e-6) == 1.0

    def test_statistics_track_assessments(self, settings, detection_engine, repository, make_event) -> None:
        risk = RiskEngine(settings)
        extractor = FeatureExtractor(window_seconds=300)
        event = make_event()
        features = build_features(extractor, event)
        risk.assess(event, detect(detection_engine, repository, event, features), features)
        assert risk.statistics()["assessments"] == 1
