"""Collectors: synthetic lab generator, syslog transport and packet metadata."""

from __future__ import annotations

import socket
import threading
import time
from datetime import datetime, timezone

import pytest

from app.collectors.network.packet_collector import (
    PacketCollector,
    extract_http_metadata,
    extract_tls_sni,
    is_pcap_available,
)
from app.collectors.network.synthetic import SCENARIOS, SyntheticCollector
from app.collectors.syslog.udp_syslog import SyslogCollector, parse_priority, parse_syslog_line, parse_timestamp
from app.collectors.system.system_collector import SystemCollector


class TestSyntheticCollector:
    @pytest.mark.parametrize("scenario", SCENARIOS)
    def test_every_scenario_starts_and_emits_records(self, scenario) -> None:
        received = []
        collector = SyntheticCollector(received.append, eps=120, scenario=scenario, seed=11)
        assert collector.start() is True
        time.sleep(0.25)
        collector.stop()
        assert received, f"scenario {scenario} produced no events"
        assert all(record.collector == "synthetic" for record in received)

    def test_port_scan_events_target_one_source(self) -> None:
        received = []
        collector = SyntheticCollector(received.append, eps=200, scenario="port_scan", seed=3)
        collector.start()
        time.sleep(0.3)
        collector.stop()
        sources = {record.payload["source_ip"] for record in received}
        ports = {record.payload["destination_port"] for record in received}
        assert len(sources) == 1
        assert len(ports) > 5

    def test_brute_force_events_are_auth_failures(self) -> None:
        received = []
        collector = SyntheticCollector(received.append, eps=100, scenario="brute_force", seed=5)
        collector.start()
        time.sleep(0.3)
        collector.stop()
        assert all(record.event_type == "AUTH_FAILURE" for record in received)
        assert all("Failed password" in record.payload["message"] for record in received)

    def test_unknown_scenario_is_refused(self) -> None:
        collector = SyntheticCollector(lambda record: True, scenario="not-a-scenario")
        assert collector.start() is False
        assert "unknown scenario" in collector.status()["last_error"]

    def test_status_reports_scenario_and_rate(self) -> None:
        collector = SyntheticCollector(lambda record: True, scenario="dns_anomaly", eps=42)
        collector.start()
        time.sleep(0.1)
        status = collector.status()
        collector.stop()
        assert status["detail"]["scenario"] == "dns_anomaly"
        assert status["detail"]["eps"] == 42
        assert status["records"] >= 1


class TestSyslogParsing:
    def test_rfc3164_line(self) -> None:
        payload = parse_syslog_line("<34>Aug 18 22:30:12 host1 sshd[1234]: Failed password for root")
        assert payload["facility"] == "auth"
        assert payload["host"] == "host1"
        assert payload["app"] == "sshd"
        assert payload["process_id"] == "1234"
        assert "Failed password" in payload["message"]

    def test_rfc5424_line(self) -> None:
        payload = parse_syslog_line(
            "<165>1 2026-08-18T22:30:12Z host2 app 8710 ID47 - structured message body"
        )
        assert payload["version"] == 1
        assert payload["host"] == "host2"
        assert payload["process_id"] == "8710"
        assert payload["message"] == "structured message body"

    def test_json_datagram(self) -> None:
        payload = parse_syslog_line('{"source_ip": "10.0.0.5", "event_type": "FIREWALL_DENY", "message": "blocked"}')
        assert payload["source_ip"] == "10.0.0.5"
        assert payload["message"] == "blocked"

    def test_malformed_json_is_recorded_not_crashed(self) -> None:
        payload = parse_syslog_line('{"broken": ')
        assert payload["parse_error"] == "invalid json"

    def test_source_ip_is_extracted_from_the_message(self) -> None:
        payload = parse_syslog_line("kernel: IN=eth0 SRC=192.168.50.7 DST=10.0.0.1 denied")
        assert payload["source_ip"] == "192.168.50.7"

    def test_priority_mapping(self) -> None:
        assert parse_priority(34) == ("auth", "critical")
        assert parse_priority(None) == (None, None)

    def test_timestamp_parsing(self) -> None:
        assert parse_timestamp("2026-08-18T22:30:12Z") == datetime(2026, 8, 18, 22, 30, 12)
        assert parse_timestamp("Aug 18 22:30:12") is not None
        assert parse_timestamp("not a timestamp") is None
        assert parse_timestamp(None) is None


class TestSyslogCollectorTransport:
    def test_round_trip_over_udp(self) -> None:
        # Bind a free port first so the test never collides with a real service.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        received = []
        event = threading.Event()

        def sink(record):
            received.append(record)
            event.set()
            return True

        collector = SyslogCollector(sink, host="127.0.0.1", port=port)
        assert collector.start() is True
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.sendto(
                b"<34>Aug 18 22:30:12 fw1 sshd[42]: Failed password for invalid user admin from 10.0.0.77 port 51234",
                ("127.0.0.1", port),
            )
            client.close()
            assert event.wait(5), "collector did not receive the datagram"
        finally:
            collector.stop()

        payload = received[0].payload
        assert payload["source_ip"] == "10.0.0.77"
        assert "Failed password" in payload["message"]
        assert received[0].collector == "syslog"
        assert collector.status()["records"] >= 1

    def test_bind_failure_is_reported_not_raised(self) -> None:
        # Port 1 requires privileges on most systems; if it happens to bind, the
        # test still asserts the collector reports a usable status.
        collector = SyslogCollector(lambda record: True, host="127.0.0.1", port=1)
        started = collector.start()
        collector.stop()
        assert started in {True, False}
        assert collector.status()["running"] is False


class TestPacketMetadata:
    def test_http_metadata_extraction_keeps_only_method_and_host(self) -> None:
        payload = b"GET /admin HTTP/1.1\r\nHost: example.com\r\nCookie: session=secret\r\n\r\nbody"
        metadata = extract_http_metadata(payload)
        assert metadata["http_method"] == "GET"
        assert metadata["http_host"] == "example.com"
        assert "secret" not in str(metadata)

    def test_non_http_payload_is_ignored(self) -> None:
        assert extract_http_metadata(b"\x16\x03\x01\x00\xa5") == {}
        assert extract_http_metadata(b"") == {}

    def test_tls_sni_parser_is_safe_on_garbage(self) -> None:
        assert extract_tls_sni(b"") is None
        assert extract_tls_sni(b"\x16\x03\x01garbage") is None
        assert extract_tls_sni(b"not tls at all") is None

    def test_capture_availability_probe_returns_a_reason(self) -> None:
        available, reason = is_pcap_available()
        assert isinstance(available, bool)
        if not available:
            assert reason

    def test_collector_reports_status_even_when_capture_is_unavailable(self) -> None:
        collector = PacketCollector(lambda record: True, bpf_filter="ip")
        started = collector.start()
        status = collector.status()
        collector.stop()
        assert status["collector"] == "packet"
        assert status["detail"]["bpf"] == "ip"
        if started:
            assert status["running"] in {True, False}


class TestSystemCollector:
    def test_status_shape(self) -> None:
        collector = SystemCollector(lambda record: True, interval_seconds=30)
        status = collector.status()
        assert status["collector"] == "system"
        assert status["detail"]["interval_seconds"] == 30
        assert collector.name == "system"

    def test_missing_log_file_is_ignored(self, tmp_path) -> None:
        collector = SystemCollector(lambda record: True, interval_seconds=30, log_path=str(tmp_path / "nope.log"))
        assert collector.start() is True
        time.sleep(0.1)
        collector.stop()
        assert collector.status()["detail"]["log_path"] == ""
