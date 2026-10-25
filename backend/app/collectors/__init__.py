"""Collection layer: packet, syslog/firewall log, host and lab generator."""

from __future__ import annotations

from typing import Any

from .base import Collector, Sink
from .network.packet_collector import PacketCollector, is_pcap_available
from .network.synthetic import SCENARIOS, SyntheticCollector
from .syslog.udp_syslog import SyslogCollector, parse_syslog_line
from .system.system_collector import SystemCollector


def build_collectors(sink: Sink, settings) -> list[Collector]:
    """Instantiate the collectors enabled in the current settings."""
    collectors: list[Collector] = []

    if settings.collector_network_enabled:
        collectors.append(
            PacketCollector(
                sink,
                interface=settings.collector_interface or None,
                bpf_filter=settings.collector_bpf_filter,
                snaplen=settings.collector_snaplen,
                promiscuous=settings.collector_promiscuous,
            )
        )
    if settings.collector_syslog_enabled:
        collectors.append(
            SyslogCollector(
                sink,
                host=settings.collector_syslog_host,
                port=settings.collector_syslog_port,
            )
        )
    if settings.collector_system_enabled:
        collectors.append(
            SystemCollector(sink, interval_seconds=settings.collector_system_interval_seconds)
        )
    if settings.simulator_enabled:
        collectors.append(
            SyntheticCollector(
                sink,
                eps=settings.simulator_eps,
                scenario=settings.simulator_scenario,
                seed=settings.simulator_seed,
            )
        )
    return collectors


__all__ = [
    "SCENARIOS",
    "Collector",
    "PacketCollector",
    "Sink",
    "SyntheticCollector",
    "SyslogCollector",
    "SystemCollector",
    "build_collectors",
    "is_pcap_available",
    "parse_syslog_line",
]
