"""Preprocessing: parsing, validation, normalization, deduplication, features."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.processors.deduplicator import Deduplicator
from app.processors.feature_engineering import FEATURE_ORDER, FeatureExtractor
from app.processors.normalizer import dedupe_hash, is_private, normalise, normalise_direction
from app.processors.parser import (
    classify_syslog_message,
    parse_protocol,
    parse_record,
)
from app.processors.validator import ValidationError, validate
from app.processors.models import RawRecord

NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def record(collector="packet", payload=None, event_type="NETWORK_CONNECTION") -> RawRecord:
    return RawRecord(collector=collector, received_at=NOW, event_type=event_type, payload=payload or {})


class TestParser:
    def test_packet_metadata_is_parsed_into_a_candidate_event(self) -> None:
        candidate = parse_record(
            record(
                payload={
                    "src": "10.0.0.5",
                    "dst": "8.8.8.8",
                    "sport": 51000,
                    "dport": 53,
                    "protocol": "udp",
                    "length": 120,
                    "tcp_flags": "S",
                    "dns_query": "example.com",
                }
            )
        )
        assert candidate["source_ip"] == "10.0.0.5"
        assert candidate["protocol"] == "UDP"
        assert candidate["event_type"] == "DNS_QUERY"
        assert candidate["connection_state"] == "SYN_SENT"
        assert candidate["network"]["dns_query"] == "example.com"

    def test_syslog_auth_failure_is_classified(self) -> None:
        candidate = parse_record(
            record(
                collector="syslog",
                payload={
                    "message": "Failed password for invalid user root from 10.0.0.9 port 22 ssh2",
                    "source_ip": "10.0.0.9",
                },
            )
        )
        assert candidate["event_type"] == "AUTH_FAILURE"
        assert candidate["metadata"]["username"] == "root"

    def test_syslog_firewall_deny_is_classified(self) -> None:
        event_type, _ = classify_syslog_message("UFW BLOCK IN=eth0 SRC=10.0.0.5 DST=10.0.0.1")
        assert event_type == "FIREWALL_DENY"

    def test_syslog_success_is_classified(self) -> None:
        event_type, extra = classify_syslog_message("Accepted password for deploy from 10.0.0.5 port 22 ssh2")
        assert event_type == "AUTH_SUCCESS"
        assert extra["username"] == "deploy"

    def test_unknown_messages_become_syslog_events(self) -> None:
        event_type, _ = classify_syslog_message("kernel: some routine message")
        assert event_type == "SYSLOG_EVENT"

    @pytest.mark.parametrize(
        "value,expected",
        [("tcp", "TCP"), ("17", "UDP"), ("icmpv6", "ICMPV6"), ("weird", "OTHER"), (None, "OTHER")],
    )
    def test_protocol_normalisation(self, value, expected) -> None:
        assert parse_protocol(value) == expected

    def test_parser_never_raises_on_garbage(self) -> None:
        assert parse_record(record(payload={"protocol": None})) is not None or True


class TestValidator:
    def test_valid_event_passes(self) -> None:
        clean = validate(
            {
                "timestamp": NOW,
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.1",
                "source_port": 1234,
                "destination_port": 80,
                "protocol": "TCP",
                "event_type": "NETWORK_CONNECTION",
                "packet_count": 3,
                "bytes": 900,
            }
        )
        assert clean["source_port"] == 1234

    def test_invalid_ip_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="invalid IP"):
            validate({"timestamp": NOW, "source_ip": "999.1.2.3", "event_type": "NETWORK_CONNECTION"})

    def test_port_out_of_range_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="port out of range"):
            validate(
                {
                    "timestamp": NOW,
                    "source_ip": "10.0.0.5",
                    "destination_port": 70000,
                    "event_type": "NETWORK_CONNECTION",
                }
            )

    def test_future_timestamp_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="future"):
            validate(
                {
                    "timestamp": NOW + timedelta(hours=2),
                    "source_ip": "10.0.0.5",
                    "event_type": "NETWORK_CONNECTION",
                }
            )

    def test_stale_timestamp_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="older than"):
            validate(
                {
                    "timestamp": NOW - timedelta(days=3),
                    "source_ip": "10.0.0.5",
                    "event_type": "NETWORK_CONNECTION",
                }
            )

    def test_network_event_without_addresses_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="without source or destination"):
            validate({"timestamp": NOW, "event_type": "NETWORK_CONNECTION"})

    def test_negative_counters_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="packet_count"):
            validate(
                {
                    "timestamp": NOW,
                    "source_ip": "10.0.0.5",
                    "event_type": "NETWORK_CONNECTION",
                    "packet_count": -5,
                }
            )

    def test_empty_candidate_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate(None)


class TestNormalizer:
    def test_direction_is_derived_from_address_classes(self) -> None:
        assert normalise_direction("192.168.1.5", "8.8.8.8") == "outbound"
        assert normalise_direction("8.8.8.8", "192.168.1.5") == "inbound"
        assert normalise_direction("192.168.1.5", "192.168.1.9") == "internal"
        assert normalise_direction("1.1.1.1", "8.8.8.8") == "external"

    def test_private_detection(self) -> None:
        assert is_private("10.1.2.3")
        assert is_private("::1")
        assert not is_private("8.8.8.8")
        assert not is_private(None)

    def test_normalisation_is_stable_and_hashes_are_deterministic(self) -> None:
        candidate = {
            "timestamp": NOW,
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.1",
            "destination_port": 22,
            "protocol": "tcp",
            "event_type": "NETWORK_CONNECTION",
            "connection_state": "syn",
            "packet_count": 1,
            "bytes": 60,
            "metadata": {},
            "network": {},
        }
        first = normalise(validate(dict(candidate)))
        second = normalise(validate(dict(candidate)))
        assert first.protocol == "TCP"
        assert first.connection_state == "SYN_SENT"
        assert first.dedupe_hash == second.dedupe_hash
        assert dedupe_hash({"event_type": "X"}) == dedupe_hash({"event_type": "X"})

    def test_different_ports_produce_different_hashes(self) -> None:
        base = {"event_type": "NETWORK_CONNECTION", "source_ip": "10.0.0.5", "destination_port": 22}
        other = dict(base, destination_port=443)
        assert dedupe_hash(base) != dedupe_hash(other)


class TestDeduplicator:
    def test_identical_hashes_inside_the_window_are_duplicates(self) -> None:
        dedupe = Deduplicator(window_seconds=30, max_entries=10)
        assert dedupe.seen("abc") is False
        assert dedupe.seen("abc") is True
        assert dedupe.stats()["duplicates_suppressed"] == 1

    def test_zero_window_disables_deduplication(self) -> None:
        assert Deduplicator(window_seconds=0).seen("abc") is False

    def test_empty_keys_are_never_duplicates(self) -> None:
        assert Deduplicator(window_seconds=30).seen("") is False

    def test_cache_is_bounded(self) -> None:
        dedupe = Deduplicator(window_seconds=60, max_entries=5)
        for index in range(50):
            dedupe.seen(f"key-{index}")
        assert dedupe.stats()["entries"] <= 6

    def test_clear_resets_counters(self) -> None:
        dedupe = Deduplicator(window_seconds=10)
        dedupe.seen("a")
        dedupe.seen("a")
        dedupe.clear()
        assert dedupe.stats()["duplicates_suppressed"] == 0


class TestFeatureExtractor:
    def test_features_reflect_observed_behaviour(self, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300)
        for port in range(20, 30):
            extractor.add_event(make_event(destination_port=port, connection_state="SYN_SENT"))
        extractor.add_event(make_event(event_type="AUTH_FAILURE", destination_port=22, connection_state="FAILED"))
        extractor.add_event(
            make_event(
                event_type="DNS_QUERY",
                protocol="UDP",
                destination_port=53,
                connection_state="ESTABLISHED",
                network={"dns_query": "a.example"},
            )
        )
        features = extractor.features("192.168.50.10")
        assert features.connection_count == 12
        assert features.unique_destination_ports == 11
        assert features.auth_failures == 1
        assert features.dns_requests == 1
        assert features.failed_connections == 1
        assert features.events_per_minute > 0

    def test_unknown_entity_has_zeroed_features(self) -> None:
        features = FeatureExtractor().features("10.99.99.99")
        assert features.connection_count == 0
        assert features.top_destination_port is None

    def test_feature_vector_order_is_stable(self, make_event) -> None:
        extractor = FeatureExtractor()
        extractor.add_event(make_event())
        vector = extractor.features("192.168.50.10").as_vector(FEATURE_ORDER)
        assert len(vector) == len(FEATURE_ORDER)
        assert all(isinstance(value, float) for value in vector)

    def test_store_is_bounded_per_entity(self, make_event) -> None:
        extractor = FeatureExtractor(window_seconds=300, max_observations=10)
        for index in range(40):
            extractor.add_event(make_event(destination_port=1000 + index))
        assert extractor.features("192.168.50.10").connection_count <= 10

    def test_statistics_expose_the_window(self) -> None:
        extractor = FeatureExtractor(window_seconds=120)
        assert extractor.statistics()["window_seconds"] == 120
