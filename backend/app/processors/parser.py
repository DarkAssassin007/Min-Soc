"""Parsing: convert raw collector output into structured candidate events.

The parser is intentionally total: it never raises on malformed input, it
returns ``None`` and lets the validator explain why the record was rejected.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from ..database.enums import ConnectionState, EventType, Protocol
from ..config.logging_config import get_logger
from .models import RawRecord

logger = get_logger(__name__)

# --- syslog / OS security event recognition -------------------------------
_AUTH_FAILURE_PATTERNS = [
    re.compile(r"failed password for (?:invalid user )?(?P<user>[\w.\-@]+)", re.I),
    re.compile(r"authentication failure.*?user=(?P<user>[\w.\-@]+)", re.I),
    re.compile(r"invalid user (?P<user>[\w.\-@]+)", re.I),
    re.compile(r"failed login (?:attempt )?(?:for|user[= ])(?P<user>[\w.\-@]+)", re.I),
    re.compile(r"login incorrect", re.I),
    re.compile(r"account locked", re.I),
    re.compile(r"4625"),  # Windows Security: An account failed to log on
]
_AUTH_SUCCESS_PATTERNS = [
    re.compile(r"accepted (?:password|publickey) for (?P<user>[\w.\-@]+)", re.I),
    re.compile(r"session opened for user (?P<user>[\w.\-@]+)", re.I),
    re.compile(r"4624"),  # Windows Security: An account was successfully logged on
]
_FIREWALL_DENY_PATTERNS = [
    re.compile(r"\b(?:deny|denied|blocked|drop(?:ped)?|reject(?:ed)?)\b", re.I),
    re.compile(r"iptables.*(?:DROP|REJECT)", re.I),
    re.compile(r"UFW BLOCK", re.I),
]

_TCP_FLAG_STATE = {
    "S": ConnectionState.SYN_SENT.value,
    "SA": ConnectionState.SYN_SENT.value,
    "A": ConnectionState.ESTABLISHED.value,
    "PA": ConnectionState.ESTABLISHED.value,
    "FA": ConnectionState.CLOSED.value,
    "F": ConnectionState.CLOSED.value,
    "R": ConnectionState.RESET.value,
    "RA": ConnectionState.RESET.value,
}

_PROTOCOL_MAP = {
    "tcp": Protocol.TCP.value,
    "udp": Protocol.UDP.value,
    "icmp": Protocol.ICMP.value,
    "icmpv6": Protocol.ICMPV6.value,
    "icmp6": Protocol.ICMPV6.value,
    "arp": Protocol.ARP.value,
    "6": Protocol.TCP.value,
    "17": Protocol.UDP.value,
    "1": Protocol.ICMP.value,
}


def parse_protocol(value: Any) -> str:
    if value is None:
        return Protocol.OTHER.value
    token = str(value).strip().lower()
    return _PROTOCOL_MAP.get(token, Protocol.OTHER.value)


def classify_syslog_message(message: str) -> tuple[str, dict[str, Any]]:
    """Best-effort classification of a syslog/OS security message."""
    text = message or ""
    for pattern in _AUTH_FAILURE_PATTERNS:
        match = pattern.search(text)
        if match:
            user = match.groupdict().get("user") if match.groupdict() else None
            return EventType.AUTH_FAILURE.value, {"username": user}
    for pattern in _AUTH_SUCCESS_PATTERNS:
        match = pattern.search(text)
        if match:
            user = match.groupdict().get("user") if match.groupdict() else None
            return EventType.AUTH_SUCCESS.value, {"username": user}
    for pattern in _FIREWALL_DENY_PATTERNS:
        if pattern.search(text):
            return EventType.FIREWALL_DENY.value, {}
    return EventType.SYSLOG_EVENT.value, {}


def _coerce_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed
    return None


#: Structured network fields external producers may place at the top level of a
#: synthetic record; they are promoted into ``network`` so normalisation sees
#: the same shape the packet collector produces.
_NETWORK_PAYLOAD_KEYS = (
    "tcp_flags",
    "dns_query",
    "dns_qtype",
    "dns_rcode",
    "http_host",
    "http_method",
    "tls_sni",
    "icmp_type",
    "arp_op",
    "duration_ms",
    "interface",
    "capture_source",
)


def _infer_event_type(
    event_type: str | None,
    *,
    protocol: str,
    payload: dict[str, Any],
    default: str = EventType.NETWORK_CONNECTION.value,
) -> str:
    """Resolve a concrete event type when the producer was generic about it."""
    if event_type and event_type not in {EventType.UNKNOWN.value, EventType.NETWORK_CONNECTION.value}:
        return str(event_type)
    if payload.get("dns_query") or payload.get("dns_qname") or payload.get("dns_question"):
        return EventType.DNS_QUERY.value
    if protocol == Protocol.ARP.value:
        return EventType.ARP_ACTIVITY.value
    if protocol in (Protocol.ICMP.value, Protocol.ICMPV6.value):
        return EventType.ICMP_ACTIVITY.value
    return str(event_type) if event_type else default


def parse_packet(record: RawRecord) -> dict[str, Any]:
    """Parse metadata emitted by the packet collector (metadata only!)."""
    payload = record.payload or {}
    protocol = parse_protocol(payload.get("protocol") or payload.get("proto"))
    tcp_flags = payload.get("tcp_flags") or ""
    state = _TCP_FLAG_STATE.get(str(tcp_flags).upper(), ConnectionState.UNKNOWN.value)
    if payload.get("connection_state"):
        state = str(payload["connection_state"]).upper()

    event_type = _infer_event_type(record.event_type, protocol=protocol, payload=payload)

    return {
        "timestamp": _coerce_timestamp(payload.get("timestamp")) or record.received_at,
        "source_ip": payload.get("source_ip") or payload.get("src"),
        "destination_ip": payload.get("destination_ip") or payload.get("dst"),
        "source_port": payload.get("source_port") if "source_port" in payload else payload.get("sport"),
        "destination_port": payload.get("destination_port")
        if "destination_port" in payload
        else payload.get("dport"),
        "protocol": protocol,
        "packet_count": int(payload.get("packet_count") or payload.get("packets") or 1),
        "bytes": int(payload.get("bytes") or payload.get("length") or 0),
        "connection_state": state,
        "event_type": event_type,
        "interface": record.interface,
        "collector": record.collector,
        "network": {
            "tcp_flags": str(tcp_flags) or None,
            "dns_query": payload.get("dns_query"),
            "dns_qtype": payload.get("dns_qtype"),
            "dns_rcode": payload.get("dns_rcode"),
            "http_host": payload.get("http_host"),
            "http_method": payload.get("http_method"),
            "tls_sni": payload.get("tls_sni"),
            "icmp_type": payload.get("icmp_type"),
            "arp_op": payload.get("arp_op"),
            "interface": record.interface,
            "capture_source": payload.get("capture_source", record.collector),
            "meta": payload.get("meta") or {},
        },
    }


def parse_syslog(record: RawRecord) -> dict[str, Any]:
    payload = record.payload or {}
    message = str(payload.get("message") or payload.get("raw") or "")
    event_type, extra = classify_syslog_message(message)
    return {
        "timestamp": _coerce_timestamp(payload.get("timestamp")) or record.received_at,
        "source_ip": payload.get("source_ip") or record.source_host,
        "destination_ip": payload.get("destination_ip"),
        "source_port": payload.get("source_port"),
        "destination_port": payload.get("destination_port"),
        "protocol": parse_protocol(payload.get("protocol")),
        "packet_count": int(payload.get("packet_count") or 1),
        "bytes": int(payload.get("bytes") or 0),
        "connection_state": str(payload.get("connection_state") or ConnectionState.UNKNOWN.value),
        "event_type": event_type,
        "collector": record.collector,
        "metadata": {
            "message": message[:2000],
            "facility": payload.get("facility"),
            "app": payload.get("app") or payload.get("program"),
            "host": payload.get("host") or record.source_host,
            **extra,
        },
        "network": {},
    }


def parse_system(record: RawRecord) -> dict[str, Any]:
    payload = record.payload or {}
    message = str(payload.get("message") or "")
    event_type = payload.get("event_type")
    extra: dict[str, Any] = {}
    if not event_type:
        event_type, extra = classify_syslog_message(message)
    return {
        "timestamp": _coerce_timestamp(payload.get("timestamp")) or record.received_at,
        "source_ip": payload.get("source_ip") or payload.get("remote_address"),
        "destination_ip": payload.get("destination_ip") or payload.get("local_address"),
        "source_port": payload.get("source_port") or payload.get("remote_port"),
        "destination_port": payload.get("destination_port") or payload.get("local_port"),
        "protocol": parse_protocol(payload.get("protocol")),
        "packet_count": int(payload.get("packet_count") or 1),
        "bytes": int(payload.get("bytes") or 0),
        "connection_state": str(
            payload.get("connection_state")
            or (
                ConnectionState.ESTABLISHED.value
                if str(payload.get("status", "")).upper() == "ESTABLISHED"
                else ConnectionState.UNKNOWN.value
            )
        ),
        "event_type": event_type or EventType.SYSTEM_EVENT.value,
        "collector": record.collector,
        "metadata": {"message": message[:2000], "category": payload.get("category"), **extra},
        "network": {},
    }


def parse_record(record: RawRecord) -> dict[str, Any] | None:
    """Dispatch a raw record to the right parser."""
    try:
        if record.collector == "packet":
            return parse_packet(record)
        if record.collector in {"syslog", "firewall"}:
            return parse_syslog(record)
        if record.collector == "system":
            return parse_system(record)
        # Synthetic / externally supplied records are already structured.
        payload = dict(record.payload or {})
        payload.setdefault("timestamp", record.received_at)
        payload.setdefault("collector", record.collector)
        payload.setdefault("event_type", record.event_type)
        payload.setdefault("interface", record.interface)
        payload["protocol"] = parse_protocol(payload.get("protocol"))
        payload["event_type"] = _infer_event_type(
            payload.get("event_type"),
            protocol=payload["protocol"],
            payload=payload,
            default=EventType.UNKNOWN.value,
        )
        network = payload.get("network")
        if not isinstance(network, dict):
            network = {}
        for key in _NETWORK_PAYLOAD_KEYS:
            value = payload.get(key)
            if value is not None and key not in network:
                network[key] = value
        network.setdefault("interface", record.interface)
        network.setdefault("capture_source", record.collector)
        payload["network"] = network
        payload.setdefault("metadata", payload.pop("meta", {}) or {})
        return payload
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "record parsing failed",
            extra={"collector": record.collector, "error": str(exc)},
        )
        return None


__all__ = [
    "classify_syslog_message",
    "parse_packet",
    "parse_protocol",
    "parse_record",
    "parse_syslog",
    "parse_system",
]
