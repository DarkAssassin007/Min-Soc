"""Risk engine (spec section 11).

Final risk score = weighted blend of

    rule score + ML anomaly score + event frequency + detection confidence
    + asset importance

with explicit, explainable boosts for multi-signal detections. Every weight and
band is configuration driven, and each assessment carries its components so an
analyst can see *why* a score is what it is (that transparency is what turns a
number into evidence).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from ..config.logging_config import get_logger
from ..database.enums import SeverityLevel
from ..detection.engine import DetectionResult
from ..processors.models import FeatureVector, NormalizedEvent

logger = get_logger(__name__)

#: Detection types grouped into analyst-facing threat classifications.
CLASSIFICATIONS: dict[str, str] = {
    "PORT_SCAN": "RECONNAISSANCE",
    "BRUTE_FORCE": "CREDENTIAL_ACCESS",
    "REPEATED_FAILED_CONNECTIONS": "RESOURCE_EXHAUSTION",
    "CONNECTION_FLOOD": "RESOURCE_EXHAUSTION",
    "SUSPICIOUS_PROTOCOL": "POLICY_VIOLATION",
    "DNS_ANOMALY": "C2_OR_TUNNELLING",
    "VOLUME_ANOMALY": "DATA_EXFILTRATION",
    "ML_ANOMALY": "ANOMALOUS_BEHAVIOUR",
}

#: Baseline used to normalise the frequency component (events per minute).
FREQUENCY_REFERENCE_PER_MINUTE = 60.0


@dataclass
class RiskAssessment:
    """Result of the risk engine for a single event."""

    score: float
    severity: str
    confidence: float
    classification: str
    components: dict[str, float] = field(default_factory=dict)
    boosts: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": round(self.score, 2),
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "classification": self.classification,
            "components": {k: round(v, 2) for k, v in self.components.items()},
            "boosts": {k: round(v, 2) for k, v in self.boosts.items()},
            "reasons": self.reasons,
        }


class RiskEngine:
    """Calculates risk scores, severity and confidence."""

    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self._lock = threading.RLock()
        self._assessments = 0
        self._severity_counts: dict[str, int] = {level.value: 0 for level in SeverityLevel}

    # -------------------------------------------------------------- scoring
    def weights(self) -> dict[str, float]:
        weights = dict(self.settings.risk_weights or {})
        total = sum(max(0.0, float(v)) for v in weights.values()) or 1.0
        return {key: max(0.0, float(value)) / total for key, value in weights.items()}

    def assess(
        self,
        event: NormalizedEvent,
        detection: DetectionResult,
        features: FeatureVector,
        *,
        asset_importance: int = 3,
    ) -> RiskAssessment:
        weights = self.weights()
        reasons: list[str] = []

        rule_score = detection.max_rule_score()
        if rule_score:
            strongest = detection.strongest_rule()
            if strongest is not None:
                reasons.append(f"{strongest.rule_key} matched (rule score {strongest.score:.0f})")

        ml_score = detection.anomaly.risk_contribution() if (
            detection.anomaly is not None and detection.anomaly.is_anomaly
        ) else 0.0
        if ml_score:
            reasons.append(
                f"ML anomaly score {detection.anomaly.anomaly_score:.3f} "
                f"(model {detection.anomaly.model_name}:{detection.anomaly.model_version})"
            )

        frequency_score = min(100.0, features.events_per_minute / FREQUENCY_REFERENCE_PER_MINUTE * 100.0)
        confidence_score = detection.max_confidence() * 100.0
        asset_score = min(100.0, max(0, int(asset_importance) - 1) * 25.0)

        components = {
            "rule": rule_score,
            "ml": ml_score,
            "frequency": frequency_score,
            "confidence": confidence_score,
            "asset": asset_score,
        }
        score = sum(components[key] * weights.get(key, 0.0) for key in components)

        # ----------------------------------------------------------- boosts
        boosts: dict[str, float] = {}
        rule_count = len(detection.rule_hits)
        if rule_count > 1:
            boosts["multiple_rules"] = min(15.0, 5.0 * (rule_count - 1))
            reasons.append(f"{rule_count} different rules matched the same behaviour")
        if detection.rule_hits and ml_score >= 60:
            boosts["rule_and_ml_agreement"] = 8.0
            reasons.append("rule engine and ML model agree this behaviour is anomalous")
        if features.off_hours:
            boosts["off_hours_activity"] = 3.0
            reasons.append("activity occurred outside business hours")
        if event.direction in {"outbound", "external"} and ml_score >= 50:
            boosts["outbound_anomaly"] = 5.0
            reasons.append("unusual outbound traffic")
        hint_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        severity_hint = max(
            (hit.severity_hint for hit in detection.rule_hits),
            default="LOW",
            key=lambda name: hint_rank.get(name, 0),
        )
        if severity_hint in {"HIGH", "CRITICAL"}:
            boosts["severity_hint"] = 5.0 if severity_hint == "HIGH" else 10.0
            reasons.append(f"rule severity hint {severity_hint}")

        final = min(100.0, score + sum(boosts.values()))
        confidence = detection.max_confidence()
        classification = self.classify(detection)

        assessment = RiskAssessment(
            score=round(final, 2),
            severity=self.settings.severity_for(final),
            confidence=round(min(max(confidence, 0.0), 1.0), 3),
            classification=classification,
            components=components,
            boosts=boosts,
            reasons=reasons,
        )
        with self._lock:
            self._assessments += 1
            self._severity_counts[assessment.severity] = (
                self._severity_counts.get(assessment.severity, 0) + 1
            )
        return assessment

    @staticmethod
    def classify(detection: DetectionResult) -> str:
        """Map detection types to a threat classification."""
        types = [hit.detection_type for hit in detection.rule_hits]
        if detection.anomaly is not None and detection.anomaly.is_anomaly:
            types.append("ML_ANOMALY")
        if not types:
            return "NORMAL"
        ordered = sorted(
            {CLASSIFICATIONS.get(name, "OTHER") for name in types},
            key=lambda name: 0 if name != "ANOMALOUS_BEHAVIOUR" else 1,
        )
        return ordered[0] if len(ordered) == 1 else "MULTI_STAGE"

    def severity_for(self, score: float) -> str:
        return self.settings.severity_for(score)

    # --------------------------------------------------------------- status
    def statistics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "assessments": self._assessments,
                "severity_counts": dict(self._severity_counts),
                "weights": {k: round(v, 4) for k, v in self.weights().items()},
                "bands": {
                    "low_max": self.settings.risk_low_max,
                    "medium_max": self.settings.risk_medium_max,
                    "high_max": self.settings.risk_high_max,
                },
                "frequency_reference_per_minute": FREQUENCY_REFERENCE_PER_MINUTE,
            }


__all__ = ["CLASSIFICATIONS", "FREQUENCY_REFERENCE_PER_MINUTE", "RiskAssessment", "RiskEngine"]
