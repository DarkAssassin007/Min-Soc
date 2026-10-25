"""Detection rules shipped with Mini SOC."""

from __future__ import annotations

from .builtin import (
    BruteForceRule,
    ConnectionFloodRule,
    DnsAnomalyRule,
    FailedConnectionsRule,
    PortScanRule,
    SuspiciousProtocolRule,
    VolumeAnomalyRule,
)
from .registry import RULE_CLASSES, RuleRegistry, load_rule_packs

__all__ = [
    "RULE_CLASSES",
    "BruteForceRule",
    "ConnectionFloodRule",
    "DnsAnomalyRule",
    "FailedConnectionsRule",
    "PortScanRule",
    "RuleRegistry",
    "SuspiciousProtocolRule",
    "VolumeAnomalyRule",
    "load_rule_packs",
]
