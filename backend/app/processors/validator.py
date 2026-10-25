"""Validation: reject malformed or incomplete events before they reach detection.

Validation is deliberately strict: a security platform that silently stores
garbage produces false conclusions later, so anything ambiguous is rejected
with a reason that is logged and counted.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from typing import Any

from ..config.logging_config import get_logger
from ..database.base import utcnow
from ..database.enums import EventType, Protocol

logger = get_logger(__name__)

MAX_AGE = timedelta(days=1)
MAX_FUTURE_SKEW = timedelta(minutes=5)
MAX_PACKETS = 10_000_000
MAX_BYTES = 1_000_000_000_000


class ValidationError(ValueError):
    """Raised internally when a record cannot be normalised."""


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "%" in text:  # IPv6 zone index, e.g. fe80::1%eth0
        text = text.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValidationError(f"invalid IP address: {value!r}") from None


def _valid_port(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"invalid port: {value!r}") from None
    if not 0 <= port <= 65535:
        raise ValidationError(f"port out of range: {port}")
    return port


def _valid_count(value: Any, *, limit: int, field: str) -> int:
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        raise ValidationError(f"invalid {field}: {value!r}") from None
    if number < 0 or number > limit:
        raise ValidationError(f"{field} out of range: {number}")
    return number


def _valid_timestamp(value: Any, *, now: datetime | None = None) -> datetime:
    if isinstance(value, datetime):
        stamp = value
    elif isinstance(value, str):
        try:
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValidationError(f"invalid timestamp: {value!r}") from None
    else:
        raise ValidationError(f"missing timestamp: {value!r}")

    if stamp.tzinfo is not None:
        stamp = stamp.astimezone(tz=None).replace(tzinfo=None)
    now = now or utcnow()
    if stamp > now + MAX_FUTURE_SKEW:
        raise ValidationError("timestamp is in the future")
    if stamp < now - MAX_AGE:
        raise ValidationError("timestamp is older than the retention window")
    return stamp


def validate(candidate: dict[str, Any] | None) -> dict[str, Any]:
    """Validate and coerce a parsed candidate into a clean dictionary.

    Raises :class:`ValidationError` with a human readable reason.
    """
    if not candidate:
        raise ValidationError("parser produced no event")

    event = dict(candidate)
    event["timestamp"] = _valid_timestamp(event.get("timestamp"))
    event["source_ip"] = _valid_ip(event.get("source_ip"))
    event["destination_ip"] = _valid_ip(event.get("destination_ip"))
    event["source_port"] = _valid_port(event.get("source_port"))
    event["destination_port"] = _valid_port(event.get("destination_port"))
    event["packet_count"] = max(_valid_count(event.get("packet_count"), limit=MAX_PACKETS, field="packet_count"), 1)
    event["bytes"] = _valid_count(event.get("bytes"), limit=MAX_BYTES, field="bytes")

    protocol = str(event.get("protocol") or Protocol.OTHER.value).strip().upper()
    if not Protocol.has(protocol):
        raise ValidationError(f"unsupported protocol: {protocol!r}")
    event["protocol"] = protocol

    event_type = str(event.get("event_type") or EventType.UNKNOWN.value)
    if not EventType.has(event_type):
        event_type = EventType.UNKNOWN.value
    event["event_type"] = event_type

    # A network event without endpoints carries no security value.
    if event_type in {
        EventType.NETWORK_CONNECTION.value,
        EventType.DNS_QUERY.value,
        EventType.DNS_RESPONSE.value,
        EventType.ICMP_ACTIVITY.value,
        EventType.ARP_ACTIVITY.value,
        EventType.FIREWALL_DENY.value,
    }:
        if not event["source_ip"] and not event["destination_ip"]:
            raise ValidationError("network event without source or destination address")
        if event["source_ip"] == event["destination_ip"] and event["source_ip"] is not None:
            if event_type != EventType.ARP_ACTIVITY.value:
                # Loopback-ish noise: keep it but mark it.
                event.setdefault("metadata", {})["self_addressed"] = True

    metadata = event.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        raise ValidationError("metadata must be an object")
    event["metadata"] = metadata or {}

    network = event.get("network")
    if network is not None and not isinstance(network, dict):
        raise ValidationError("network detail must be an object")
    event["network"] = network or {}

    return event


def is_valid(candidate: dict[str, Any] | None) -> tuple[bool, str | None]:
    """Non-raising variant used by the hot path."""
    try:
        validate(candidate)
        return True, None
    except ValidationError as exc:
        return False, str(exc)


__all__ = ["MAX_AGE", "ValidationError", "is_valid", "validate"]
