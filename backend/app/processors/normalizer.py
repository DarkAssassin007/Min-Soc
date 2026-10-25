"""Normalisation: turn validated records into the canonical event schema.

Normalisation guarantees that upstream collectors can be as messy as they like
without contaminating detection, storage or the dashboard: timestamps are UTC,
addresses are canonical, protocols/event types come from fixed vocabularies and
a stable deduplication hash is attached.
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any

from ..config.logging_config import get_logger
from ..database.enums import ConnectionState, EventType, Protocol
from .models import NormalizedEvent

logger = get_logger(__name__)

#: RFC1918 / loopback / link-local ranges used for direction classification.
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]

_PROTOCOL_ALIASES = {
    "TCP": Protocol.TCP.value,
    "UDP": Protocol.UDP.value,
    "ICMP": Protocol.ICMP.value,
    "ICMPV6": Protocol.ICMPV6.value,
    "ARP": Protocol.ARP.value,
    "OTHER": Protocol.OTHER.value,
}

_STATE_ALIASES = {
    "ESTABLISHED": ConnectionState.ESTABLISHED.value,
    "SYN_SENT": ConnectionState.SYN_SENT.value,
    "SYN": ConnectionState.SYN_SENT.value,
    "CLOSED": ConnectionState.CLOSED.value,
    "CLOSE_WAIT": ConnectionState.CLOSED.value,
    "RESET": ConnectionState.RESET.value,
    "RST": ConnectionState.RESET.value,
    "FAILED": ConnectionState.FAILED.value,
    "TIMEOUT": ConnectionState.FAILED.value,
    "REFUSED": ConnectionState.FAILED.value,
    "UNKNOWN": ConnectionState.UNKNOWN.value,
}


def is_private(address: str | None) -> bool:
    if not address:
        return False
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed in network for network in _PRIVATE_NETS)


def normalise_protocol(value: Any) -> str:
    return _PROTOCOL_ALIASES.get(str(value or "OTHER").upper(), Protocol.OTHER.value)


def normalise_state(value: Any) -> str:
    return _STATE_ALIASES.get(str(value or "UNKNOWN").upper(), ConnectionState.UNKNOWN.value)


def normalise_direction(source_ip: str | None, destination_ip: str | None, hint: Any = None) -> str | None:
    if hint in {"inbound", "outbound", "internal", "external"}:
        return str(hint)
    source_private = is_private(source_ip)
    destination_private = is_private(destination_ip)
    if source_private and destination_private:
        return "internal"
    if source_private and not destination_private:
        return "outbound"
    if not source_private and destination_private:
        return "inbound"
    return "external"


def dedupe_hash(event: dict[str, Any]) -> str:
    """Stable hash identifying "the same thing happening again"."""
    parts = [
        str(event.get("event_type", "")),
        str(event.get("source_ip") or ""),
        str(event.get("destination_ip") or ""),
        str(event.get("source_port") or ""),
        str(event.get("destination_port") or ""),
        str(event.get("protocol") or ""),
        str(event.get("connection_state") or ""),
        str((event.get("network") or {}).get("dns_query") or ""),
        str((event.get("metadata") or {}).get("message") or "")[:200],
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8", "ignore")).hexdigest()


def normalise(event: dict[str, Any]) -> NormalizedEvent:
    """Produce a :class:`NormalizedEvent` from a validated candidate."""
    metadata = dict(event.get("metadata") or {})
    network = dict(event.get("network") or {})

    protocol = normalise_protocol(event.get("protocol"))
    event_type = str(event.get("event_type") or EventType.UNKNOWN.value)
    if not EventType.has(event_type):
        event_type = EventType.UNKNOWN.value

    source_ip = event.get("source_ip")
    destination_ip = event.get("destination_ip")

    # DNS questions are extremely useful later in investigation.
    if not network.get("dns_query"):
        candidate_query = metadata.get("dns_query") or metadata.get("query")
        if candidate_query:
            network["dns_query"] = str(candidate_query)[:255]

    if event_type == EventType.DNS_QUERY.value and not network.get("dns_query"):
        question = metadata.get("question") or metadata.get("qname")
        if question:
            network["dns_query"] = str(question)[:255]

    normalised = NormalizedEvent(
        timestamp=event["timestamp"],
        source_ip=source_ip or None,
        destination_ip=destination_ip or None,
        source_port=event.get("source_port"),
        destination_port=event.get("destination_port"),
        protocol=protocol,
        packet_count=int(event.get("packet_count") or 1),
        bytes=int(event.get("bytes") or 0),
        connection_state=normalise_state(event.get("connection_state")),
        event_type=event_type,
        direction=normalise_direction(source_ip, destination_ip, event.get("direction")),
        interface=event.get("interface"),
        collector=event.get("collector"),
        metadata=metadata,
        network=network,
    )
    normalised.dedupe_hash = dedupe_hash(normalised.model_dump())
    return normalised


__all__ = [
    "dedupe_hash",
    "is_private",
    "normalise",
    "normalise_direction",
    "normalise_protocol",
    "normalise_state",
]
