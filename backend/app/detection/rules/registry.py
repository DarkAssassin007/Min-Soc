"""Rule registry: maps rule packs (YAML -> database) onto rule classes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ...config.logging_config import get_logger
from ...database.repository import Repository
from ..base import BaseRule, RuleContext, RuleResult
from .builtin import (
    BruteForceRule,
    ConnectionFloodRule,
    DnsAnomalyRule,
    FailedConnectionsRule,
    PortScanRule,
    SuspiciousProtocolRule,
    VolumeAnomalyRule,
)

logger = get_logger(__name__)

#: Every rule the platform ships with, keyed by ``rule_key``.
RULE_CLASSES: dict[str, type[BaseRule]] = {
    PortScanRule.rule_key: PortScanRule,
    BruteForceRule.rule_key: BruteForceRule,
    FailedConnectionsRule.rule_key: FailedConnectionsRule,
    ConnectionFloodRule.rule_key: ConnectionFloodRule,
    SuspiciousProtocolRule.rule_key: SuspiciousProtocolRule,
    DnsAnomalyRule.rule_key: DnsAnomalyRule,
    VolumeAnomalyRule.rule_key: VolumeAnomalyRule,
}


def load_rule_packs(rules_dir: str | Path) -> list[dict[str, Any]]:
    """Read every ``*.yaml`` rule pack in ``rules_dir`` (sorted, deterministic)."""
    directory = Path(rules_dir)
    if not directory.exists():
        logger.warning("rule directory missing", extra={"rules_dir": str(directory)})
        return []
    payloads: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.y*ml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            logger.error("rule pack parse failed", extra={"path": str(path), "error": str(exc)})
            continue
        for entry in data.get("rules", []):
            payloads.append(_normalise_entry(entry, source=path.name))
    return payloads


def _normalise_entry(entry: dict[str, Any], *, source: str) -> dict[str, Any]:
    rule_key = str(entry.get("rule_key") or "").strip()
    if not rule_key:
        raise ValueError(f"rule pack {source} contains an entry without rule_key")
    rule_class = RULE_CLASSES.get(rule_key)
    payload: dict[str, Any] = {
        "rule_key": rule_key,
        "name": str(entry.get("name") or rule_key.replace("_", " ").title()),
        "category": str(entry.get("category") or "GENERIC"),
        "rule_type": str(entry.get("rule_type") or "THRESHOLD"),
        "enabled": bool(entry.get("enabled", True)),
        "severity_hint": str(
            entry.get("severity_hint")
            or (rule_class.default_severity_hint if rule_class else "MEDIUM")
        ),
        "description": entry.get("description"),
        "recommended_action": entry.get("recommended_action"),
        "mitre_id": entry.get("mitre_id"),
        "threshold": float(entry.get("threshold") or 0.0),
        "window_seconds": int(entry.get("window_seconds") or 300),
        "params": dict(entry.get("params") or {}),
        "source": source,
    }
    if rule_class is not None:
        merged = dict(rule_class.default_params)
        merged.update(payload["params"])
        payload["params"] = merged
    return payload


class RuleRegistry:
    """Loads rules from disk into the database and instantiates rule objects."""

    def __init__(self, repository: Repository, rules_dir: str | Path) -> None:
        self.repository = repository
        self.rules_dir = Path(rules_dir)
        self._cache: list[tuple[BaseRule, Any]] = []

    def sync_from_disk(self) -> dict[str, int]:
        """Upsert every rule in the packs; returns created/updated counts."""
        created = updated = 0
        for payload in load_rule_packs(self.rules_dir):
            existing = self.repository.get_rule(payload["rule_key"])
            self.repository.upsert_rule(payload)
            if existing is None:
                created += 1
            else:
                updated += 1
        # Keep rule classes that ship without a pack available as well.
        for rule_key, rule_class in RULE_CLASSES.items():
            if self.repository.get_rule(rule_key) is None:
                self.repository.upsert_rule(
                    {
                        "rule_key": rule_key,
                        "name": rule_key.replace("_", " ").title(),
                        "category": "GENERIC",
                        "rule_type": "THRESHOLD",
                        "enabled": True,
                        "severity_hint": rule_class.default_severity_hint,
                        "description": (rule_class.__doc__ or "").strip().splitlines()[0]
                        if rule_class.__doc__
                        else None,
                        "recommended_action": rule_class.default_recommended_action,
                        "threshold": 0.0,
                        "window_seconds": 300,
                        "params": dict(rule_class.default_params),
                        "source": "builtin",
                    }
                )
                created += 1
        self.refresh()
        logger.info(
            "detection rules synchronised",
            extra={"created_rules": created, "updated_rules": updated, "rules": len(self._cache)},
        )
        return {"created": created, "updated": updated, "total": len(self._cache)}

    def refresh(self) -> None:
        """Reload enabled rules from the database (called periodically)."""
        cache: list[tuple[BaseRule, Any]] = []
        for row in self.repository.list_rules(enabled_only=True):
            rule_class = RULE_CLASSES.get(row.rule_key)
            if rule_class is None:
                logger.debug("rule row without implementation skipped", extra={"rule": row.rule_key})
                continue
            cache.append((rule_class(), row))
        self._cache = cache

    @property
    def rules(self) -> list[tuple[BaseRule, Any]]:
        return list(self._cache)

    def rule_keys(self) -> list[str]:
        return [rule.rule_key for rule, _row in self._cache]

    def evaluate(self, context_factory) -> list[RuleResult]:
        """Evaluate every enabled rule against an event/feature pair."""
        results: list[RuleResult] = []
        for rule, row in self._cache:
            context: RuleContext = context_factory(rule, row)
            try:
                result = rule.evaluate(context)
            except Exception as exc:  # a broken rule must not stop the pipeline
                logger.error(
                    "rule evaluation failed",
                    extra={"rule": rule.rule_key, "error": str(exc)},
                )
                continue
            if result is not None:
                results.append(result)
        return results


__all__ = ["RULE_CLASSES", "RuleRegistry", "load_rule_packs"]
