"""Detection engine: rule engine + ML anomaly engine behind one interface.

The engine is deliberately side-effect free with respect to the database: it
takes a normalised event plus its feature vector and returns a list of
:class:`DetectionResult`. Persisting detections, scoring them and deciding on
alerts is the job of the pipeline and the alert manager.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from ..config.logging_config import get_logger
from ..database.models import DetectionRule
from ..processors.models import FeatureVector, NormalizedEvent
from .anomaly.detector import AnomalyDetector, AnomalyResult
from .base import RuleContext, RuleResult
from .rules.registry import RuleRegistry

logger = get_logger(__name__)


@dataclass
class DetectionResult:
    """Everything detection produced for one event."""

    rule_hits: list[RuleResult] = field(default_factory=list)
    anomaly: AnomalyResult | None = None
    latency_ms: float = 0.0

    @property
    def triggered(self) -> bool:
        return bool(self.rule_hits) or bool(self.anomaly and self.anomaly.is_anomaly)

    def max_rule_score(self) -> float:
        return max((hit.score for hit in self.rule_hits), default=0.0)

    def max_confidence(self) -> float:
        values = [hit.confidence for hit in self.rule_hits]
        if self.anomaly is not None and self.anomaly.is_anomaly:
            values.append(self.anomaly.confidence)
        return max(values, default=0.0)

    def strongest_rule(self) -> RuleResult | None:
        if not self.rule_hits:
            return None
        return max(self.rule_hits, key=lambda hit: (hit.score, hit.confidence))

    def summary(self) -> dict[str, Any]:
        return {
            "rules": [hit.to_dict() for hit in self.rule_hits],
            "anomaly": self.anomaly.to_dict() if self.anomaly else None,
            "latency_ms": round(self.latency_ms, 3),
            "triggered": self.triggered,
        }


class DetectionEngine:
    """Runs the enabled rules and the ML model for each event."""

    def __init__(
        self,
        registry: RuleRegistry,
        anomaly_detector: AnomalyDetector | None,
        *,
        settings: Any,
    ) -> None:
        self.registry = registry
        self.anomaly_detector = anomaly_detector
        self.settings = settings
        self._lock = threading.RLock()
        self._evaluations = 0
        self._rule_hits = 0
        self._anomaly_hits = 0

    # ------------------------------------------------------------- runtime
    def refresh_rules(self) -> None:
        """Reload rule configuration (called by the scheduler)."""
        self.registry.refresh()

    def evaluate_rules(
        self,
        event: NormalizedEvent,
        features: FeatureVector,
        *,
        repository: Any | None = None,
    ) -> list[RuleResult]:
        """Evaluate every enabled rule for one event."""
        return self.registry.evaluate(
            lambda rule, row: RuleContext(
                event=event,
                features=features,
                rule=row if row is not None else _placeholder_rule(rule),
                settings=self.settings,
                repository=repository,
            )
        )

    def detect(
        self,
        event: NormalizedEvent,
        features: FeatureVector,
        *,
        repository: Any | None = None,
    ) -> DetectionResult:
        import time

        started = time.perf_counter()
        hits = self.evaluate_rules(event, features, repository=repository)
        anomaly = None
        if self.anomaly_detector is not None:
            anomaly = self.anomaly_detector.score(features)

        latency_ms = (time.perf_counter() - started) * 1000.0
        self._record(hits, anomaly)
        return DetectionResult(rule_hits=hits, anomaly=anomaly, latency_ms=latency_ms)

    def detect_many(
        self,
        items: list[tuple[NormalizedEvent, FeatureVector]],
        *,
        repository: Any | None = None,
    ) -> list[DetectionResult]:
        """Evaluate a batch; the ML model is invoked once for all events.

        scikit-learn spends several milliseconds dispatching each scoring call
        regardless of the batch size, so a single batched call keeps per-event
        inference cost bounded (the batch time is divided across the events).
        """
        import time

        batch = list(items)
        if not batch:
            return []
        anomalies: list[AnomalyResult | None] = [None] * len(batch)
        anomaly_ms = 0.0
        if self.anomaly_detector is not None:
            started = time.perf_counter()
            scored = self.anomaly_detector.score_many([features for _, features in batch])
            anomaly_ms = (time.perf_counter() - started) * 1000.0 / len(batch)
            anomalies = list(scored)
        results: list[DetectionResult] = []
        for (event, features), anomaly in zip(batch, anomalies):
            started = time.perf_counter()
            hits = self.evaluate_rules(event, features, repository=repository)
            latency_ms = (time.perf_counter() - started) * 1000.0 + anomaly_ms
            self._record(hits, anomaly)
            results.append(DetectionResult(rule_hits=hits, anomaly=anomaly, latency_ms=latency_ms))
        return results

    def _record(self, hits: list[RuleResult], anomaly: AnomalyResult | None) -> None:
        with self._lock:
            self._evaluations += 1
            self._rule_hits += len(hits)
            if anomaly is not None and anomaly.is_anomaly:
                self._anomaly_hits += 1

    # -------------------------------------------------------------- status
    def statistics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "evaluations": self._evaluations,
                "rule_hits": self._rule_hits,
                "anomaly_hits": self._anomaly_hits,
                "enabled_rules": self.registry.rule_keys(),
                "rules_loaded": len(self.registry.rules),
                "anomaly": self.anomaly_detector.statistics() if self.anomaly_detector else None,
            }


def _placeholder_rule(rule: Any) -> DetectionRule:
    """Build a transient rule row when a caller evaluates without a database row."""
    return DetectionRule(
        rule_key=rule.rule_key,
        name=rule.rule_key.replace("_", " ").title(),
        category="GENERIC",
        rule_type="THRESHOLD",
        enabled=True,
        severity_hint=rule.default_severity_hint,
        recommended_action=rule.default_recommended_action,
        threshold=0.0,
        window_seconds=300,
        params=dict(rule.default_params),
        source="builtin",
    )


__all__ = ["DetectionEngine", "DetectionResult"]
