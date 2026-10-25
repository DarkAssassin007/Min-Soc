"""Detection layer: rule engine, ML anomaly engine and correlation."""

from __future__ import annotations

from .anomaly import AnomalyDetector, AnomalyResult, ModelRegistry
from .base import BaseRule, RuleContext, RuleResult
from .correlation import Correlator
from .engine import DetectionEngine, DetectionResult
from .rules import RULE_CLASSES, RuleRegistry, load_rule_packs

__all__ = [
    "RULE_CLASSES",
    "AnomalyDetector",
    "AnomalyResult",
    "BaseRule",
    "Correlator",
    "DetectionEngine",
    "DetectionResult",
    "ModelRegistry",
    "RuleContext",
    "RuleRegistry",
    "RuleResult",
    "load_rule_packs",
]
