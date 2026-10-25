"""Synthetic security event generator (authorized lab testing only — spec §32).

This is the "Security Event Generator" from the specification's test lab. It
emits realistic, *labelled* security scenarios so the detection pipeline can be
validated end to end without touching anybody else's network:

* ``port_scan``        - one source probing many ports on a target
* ``brute_force``      - repeated authentication failures against a host
* ``connection_flood`` - high-rate short-lived connections from one source
* ``dns_anomaly``      - high-rate DNS lookups using random subdomains
* ``volume_anomaly``   - a few very large transfers
* ``normal``           - baseline traffic that must NOT alert

Every record is tagged with ``metadata.synthetic = True`` and the scenario name
so tests and analysts can separate generated traffic from real traffic.
"""

from __future__ import annotations

import random
import threading
import time
from typing import Any

from ...config.logging_config import get_logger
from ...database.enums import EventType
from ..base import Collector

logger = get_logger(__name__)

SCENARIOS = (
    "normal",
    "port_scan",
    "brute_force",
    "connection_flood",
    "dns_anomaly",
    "volume_anomaly",
)


class SyntheticCollector(Collector):
    """Emit labelled synthetic security events at a controlled rate."""

    name = "synthetic"

    def source_label(self) -> str | None:
        """Lab provenance: every generated event says which scenario made it."""
        return f"lab:{self.scenario}"

    def __init__(self, sink, **options: Any) -> None:
        super().__init__(sink, **options)
        self.eps: float = float(options.get("eps") or 5.0)
        self.scenario: str = str(options.get("scenario") or "normal")
        self.seed: int = int(options.get("seed") or 1337)
        self.subnet: str = str(options.get("subnet") or "192.168.50")
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._random = random.Random(self.seed)
        self._scenario_events = 0
        # Attack scenarios are generated from a stable source so the resulting
        # behaviour is recognisable (a scan comes from one host, not forty).
        self._scanner = f"{self.subnet}.201"
        self._brute_source = f"{self.subnet}.101"
        self._flood_source = f"{self.subnet}.151"
        self._dns_source = f"{self.subnet}.61"
        self._volume_source = f"{self.subnet}.31"

    # ---------------------------------------------------------- lifecycle
    def _start(self) -> bool:
        if self.scenario not in SCENARIOS:
            self._last_error = f"unknown scenario {self.scenario!r}"
            return False
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name=f"synthetic-{self.scenario}", daemon=True
        )
        self._thread.start()
        self.set_detail(scenario=self.scenario, eps=self.eps)
        return True

    def _stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    # ----------------------------------------------------------- generator
    def _run(self) -> None:  # pragma: no cover - timing loop
        interval = 1.0 / max(self.eps, 0.01)
        next_run = time.monotonic()
        while not self._stop_event.is_set():
            try:
                if self.scenario == "port_scan":
                    self._emit_port_scan()
                elif self.scenario == "brute_force":
                    self._emit_brute_force()
                elif self.scenario == "connection_flood":
                    self._emit_connection_flood()
                elif self.scenario == "dns_anomaly":
                    self._emit_dns_anomaly()
                elif self.scenario == "volume_anomaly":
                    self._emit_volume_anomaly()
                else:
                    self._emit_normal()
            except Exception as exc:  # pragma: no cover - generator must not die
                self.record_error(exc)

            next_run += interval
            delay = next_run - time.monotonic()
            if delay > 0:
                self._stop_event.wait(delay)
            else:
                next_run = time.monotonic()

    # ------------------------------------------------------------ per-mode
    def _emit_normal(self) -> None:
        source = f"{self.subnet}.{self._random.randint(10, 60)}"
        destination = self._random.choice(
            [f"{self.subnet}.1", "8.8.8.8", "1.1.1.1", "142.250.190.46"]
        )
        port = self._random.choice([80, 443, 53, 123, 8080, 22])
        self.emit(
            {
                "source_ip": source,
                "destination_ip": destination,
                "source_port": self._random.randint(32768, 60999),
                "destination_port": port,
                "protocol": "UDP" if port in (53, 123) else "TCP",
                "bytes": self._random.randint(64, 1500),
                "packet_count": self._random.randint(1, 12),
                "connection_state": "ESTABLISHED",
            },
            event_type=EventType.DNS_QUERY.value if port == 53 else EventType.NETWORK_CONNECTION.value,
        )

    def _emit_port_scan(self) -> None:
        source = self._scanner
        target = f"{self.subnet}.1"
        self.emit(
            {
                "source_ip": source,
                "destination_ip": target,
                "source_port": self._random.randint(32768, 60999),
                "destination_port": self._random.randint(1, 9000),
                "protocol": "TCP",
                "tcp_flags": "S",
                "connection_state": "SYN_SENT",
                "bytes": 60,
                "packet_count": 1,
            },
            event_type=EventType.NETWORK_CONNECTION.value,
        )

    def _emit_brute_force(self) -> None:
        attacker = self._brute_source
        victim = f"{self.subnet}.10"
        user = self._random.choice(["root", "admin", "oracle", "postgres", "test"])
        self.emit(
            {
                "source_ip": attacker,
                "destination_ip": victim,
                "source_port": self._random.randint(32768, 60999),
                "destination_port": 22,
                "protocol": "TCP",
                "connection_state": "FAILED",
                "bytes": 220,
                "packet_count": 6,
                "message": f"Failed password for invalid user {user} from {attacker} port 51234 ssh2",
                "username": user,
            },
            event_type=EventType.AUTH_FAILURE.value,
        )

    def _emit_connection_flood(self) -> None:
        source = self._flood_source
        self.emit(
            {
                "source_ip": source,
                "destination_ip": f"{self.subnet}.1",
                "source_port": self._random.randint(1024, 65535),
                "destination_port": 443,
                "protocol": "TCP",
                "tcp_flags": "S",
                "connection_state": "SYN_SENT",
                "bytes": self._random.randint(40, 120),
                "packet_count": 1,
            },
            event_type=EventType.NETWORK_CONNECTION.value,
        )

    def _emit_dns_anomaly(self) -> None:
        source = self._dns_source
        token = "".join(self._random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
        self.emit(
            {
                "source_ip": source,
                "destination_ip": "8.8.8.8",
                "source_port": self._random.randint(32768, 60999),
                "destination_port": 53,
                "protocol": "UDP",
                "bytes": self._random.randint(60, 140),
                "packet_count": 1,
                "dns_query": f"{token}.tunnel-lab.example",
                "dns_qtype": "A",
            },
            event_type=EventType.DNS_QUERY.value,
        )

    def _emit_volume_anomaly(self) -> None:
        source = self._volume_source
        self.emit(
            {
                "source_ip": source,
                "destination_ip": "203.0.113.77",
                "source_port": self._random.randint(32768, 60999),
                "destination_port": 443,
                "protocol": "TCP",
                "connection_state": "ESTABLISHED",
                "bytes": self._random.randint(5_000_000, 40_000_000),
                "packet_count": self._random.randint(4000, 30000),
            },
            event_type=EventType.NETWORK_CONNECTION.value,
        )

    def status(self) -> dict:
        status = super().status()
        status["detail"].update({"scenario": self.scenario, "eps": self.eps})
        return status


__all__ = ["SCENARIOS", "SyntheticCollector"]
