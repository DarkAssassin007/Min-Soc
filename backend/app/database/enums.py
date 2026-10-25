"""Domain enumerations.

These are stored as short strings in the database so the same schema works on
SQLite and PostgreSQL without native enum types.
"""

from __future__ import annotations

from enum import Enum


class StrEnumMixin:
    """Small helpers shared by the string enums."""

    @classmethod
    def values(cls) -> list[str]:
        return [member.value for member in cls]  # type: ignore[attr-defined]

    @classmethod
    def has(cls, value: str) -> bool:
        return value in cls.values()  # type: ignore[attr-defined]

    def __str__(self) -> str:  # pragma: no cover - convenience
        return str(self.value)  # type: ignore[attr-defined]


class UserRole(StrEnumMixin, str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class SeverityLevel(StrEnumMixin, str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(StrEnumMixin, str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


#: Legal lifecycle transitions (spec section 12).
ALERT_TRANSITIONS: dict[str, set[str]] = {
    AlertStatus.NEW.value: {
        AlertStatus.ACKNOWLEDGED.value,
        AlertStatus.INVESTIGATING.value,
        AlertStatus.RESOLVED.value,
        AlertStatus.FALSE_POSITIVE.value,
    },
    AlertStatus.ACKNOWLEDGED.value: {
        AlertStatus.INVESTIGATING.value,
        AlertStatus.RESOLVED.value,
        AlertStatus.FALSE_POSITIVE.value,
    },
    AlertStatus.INVESTIGATING.value: {
        AlertStatus.RESOLVED.value,
        AlertStatus.FALSE_POSITIVE.value,
    },
    AlertStatus.RESOLVED.value: set(),
    AlertStatus.FALSE_POSITIVE.value: set(),
}


class IncidentStatus(StrEnumMixin, str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


INCIDENT_TRANSITIONS: dict[str, set[str]] = {
    IncidentStatus.OPEN.value: {
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.INVESTIGATING.value: {
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
    },
    IncidentStatus.CONTAINED.value: {
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.RESOLVED.value,
    },
    IncidentStatus.RESOLVED.value: {IncidentStatus.CLOSED.value},
    IncidentStatus.CLOSED.value: set(),
}


class EventType(StrEnumMixin, str, Enum):
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    DNS_QUERY = "DNS_QUERY"
    DNS_RESPONSE = "DNS_RESPONSE"
    ARP_ACTIVITY = "ARP_ACTIVITY"
    ICMP_ACTIVITY = "ICMP_ACTIVITY"
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    FIREWALL_DENY = "FIREWALL_DENY"
    SYSTEM_EVENT = "SYSTEM_EVENT"
    SYSLOG_EVENT = "SYSLOG_EVENT"
    UNKNOWN = "UNKNOWN"


class Protocol(StrEnumMixin, str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    ICMPV6 = "ICMPV6"
    OTHER = "OTHER"


class ConnectionState(StrEnumMixin, str, Enum):
    ESTABLISHED = "ESTABLISHED"
    SYN_SENT = "SYN_SENT"
    CLOSED = "CLOSED"
    RESET = "RESET"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class LogCategory(StrEnumMixin, str, Enum):
    AUDIT = "AUDIT"
    AUTH = "AUTH"
    API = "API"
    COLLECTOR = "COLLECTOR"
    PIPELINE = "PIPELINE"
    DETECTION = "DETECTION"
    MODEL = "MODEL"
    DATABASE = "DATABASE"
    WEBSOCKET = "WEBSOCKET"
    SYSTEM = "SYSTEM"


class RuleType(StrEnumMixin, str, Enum):
    THRESHOLD = "THRESHOLD"
    PATTERN = "PATTERN"
    BEHAVIORAL = "BEHAVIORAL"


__all__ = [
    "ALERT_TRANSITIONS",
    "INCIDENT_TRANSITIONS",
    "AlertStatus",
    "ConnectionState",
    "EventType",
    "IncidentStatus",
    "LogCategory",
    "Protocol",
    "RuleType",
    "SeverityLevel",
    "UserRole",
]
