"""Detection rule framework.

A rule is a small, testable object that looks at an event plus its behavioural
context and decides whether something suspicious happened. Rules are *never*
hard-coded with thresholds: every number comes from the rule's database row,
which is loaded from the versioned YAML packs in ``detection-rules/``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..database.enums import SeverityLevel
from ..database.models import DetectionRule
from ..processors.models import FeatureVector, NormalizedEvent


@dataclass
class RuleResult:
    """Outcome of a single rule evaluation."""

    rule_key: str
    detection_type: str
    score: float
    confidence: float
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_action: str = ""
    severity_hint: str = SeverityLevel.MEDIUM.value
    engine: str = "RULE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_key": self.rule_key,
            "detection_type": self.detection_type,
            "score": round(float(self.score), 2),
            "confidence": round(float(self.confidence), 3),
            "description": self.description,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
            "severity_hint": self.severity_hint,
            "engine": self.engine,
        }


@dataclass
class RuleContext:
    """Everything a rule is allowed to look at."""

    event: NormalizedEvent
    features: FeatureVector
    rule: DetectionRule
    settings: Any
    repository: Any | None = None

    @property
    def params(self) -> dict[str, Any]:
        return dict(self.rule.params or {})

    @property
    def window_seconds(self) -> int:
        return int(self.rule.window_seconds or self.settings.pipeline_feature_window_seconds)

    def param(self, name: str, default: Any) -> Any:
        value = self.params.get(name, default)
        return default if value is None else value

    def clamp_score(self, value: float) -> float:
        return max(0.0, min(100.0, round(float(value), 2)))


class BaseRule(ABC):
    """Base class for every detection rule."""

    #: Must match ``rule_key`` in the rule pack.
    rule_key: str = "BASE"
    detection_type: str = "GENERIC"
    #: Defaults merged under the database row's params.
    default_params: dict[str, Any] = {}
    default_severity_hint: str = SeverityLevel.MEDIUM.value
    default_recommended_action: str = "Review the related events in the Mini SOC dashboard."

    def params(self, context: RuleContext) -> dict[str, Any]:
        merged = dict(self.default_params)
        merged.update({k: v for k, v in context.params.items() if v is not None})
        return merged

    @abstractmethod
    def evaluate(self, context: RuleContext) -> RuleResult | None:
        """Return a :class:`RuleResult` when the rule fires, else ``None``."""

    # ------------------------------------------------------------- helpers
    def result(self, context: RuleContext, **overrides: Any) -> RuleResult:
        payload = {
            "rule_key": self.rule_key,
            "detection_type": self.detection_type,
            "score": 50.0,
            "confidence": 0.6,
            "description": f"{context.rule.name} matched",
            "evidence": {},
            "recommended_action": context.rule.recommended_action
            or self.default_recommended_action,
            "severity_hint": context.rule.severity_hint or self.default_severity_hint,
            "engine": "RULE",
        }
        payload.update(overrides)
        payload["score"] = context.clamp_score(payload["score"])
        payload["confidence"] = max(0.0, min(1.0, float(payload["confidence"])))
        return RuleResult(**payload)

    def scaled_score(self, value: float, threshold: float, ceiling: float) -> float:
        """Score in 40..100 based on how far past the threshold the value is."""
        if threshold <= 0:
            return 70.0
        ratio = float(value) / float(threshold)
        span = max(ceiling - threshold, 1.0)
        excess = max(0.0, float(value) - float(threshold))
        return min(100.0, 40.0 + 40.0 * ratio * 0.5 + 20.0 * min(excess / span, 1.0))


__all__ = ["BaseRule", "RuleContext", "RuleResult"]
