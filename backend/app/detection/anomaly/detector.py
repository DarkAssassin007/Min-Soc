"""ML anomaly detection at inference time (spec section 9).

The deployed model is a scikit-learn ``IsolationForest`` trained by the
separate pipeline in ``ml/``. This module is responsible only for:

* loading the versioned artifact once and keeping it in memory,
* turning a :class:`FeatureVector` into a model input in a fixed feature order,
* producing an anomaly score and a confidence, with measured inference latency,
* degrading politely when no model is deployed (the platform keeps working with
  rules only, and reports the model as unavailable).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

import numpy as np

from ...config.logging_config import get_logger
from ...processors.feature_engineering import FEATURE_ORDER
from ...processors.models import FeatureVector
from .registry import ModelArtifact, ModelRegistry

logger = get_logger(__name__)


@dataclass
class AnomalyResult:
    """One anomaly evaluation."""

    model_name: str
    model_version: str
    anomaly_score: float
    is_anomaly: bool
    confidence: float
    threshold: float
    latency_ms: float
    features: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "anomaly_score": round(self.anomaly_score, 5),
            "is_anomaly": self.is_anomaly,
            "confidence": round(self.confidence, 3),
            "threshold": self.threshold,
            "latency_ms": round(self.latency_ms, 3),
        }

    def risk_contribution(self) -> float:
        """Map the anomaly score onto a 0-100 scale for the risk engine."""
        if self.anomaly_score >= 0:
            return 0.0
        magnitude = min(abs(self.anomaly_score) / 0.35, 1.0)
        return round(magnitude * 100.0, 2)


class AnomalyDetector:
    """Thread-safe Isolation Forest inference wrapper."""

    def __init__(
        self,
        registry: ModelRegistry,
        *,
        threshold: float = -0.05,
        enabled: bool = True,
        feature_order: list[str] | None = None,
    ) -> None:
        self.registry = registry
        self.enabled = enabled
        self.threshold = float(threshold)
        self.feature_order = list(feature_order or FEATURE_ORDER)
        self._lock = threading.RLock()
        self._model: Any = None
        self._artifact: ModelArtifact | None = None
        self._scaler: Any = None
        self._loaded_at: float | None = None
        self._inferences = 0
        self._anomalies = 0
        self._last_latency_ms = 0.0
        self._last_error: str | None = None

    # -------------------------------------------------------------- loading
    def load(self, *, ensure_baseline: bool = True) -> bool:
        """Load the active artifact (optionally bootstrapping a baseline)."""
        if not self.enabled:
            return False
        with self._lock:
            artifact = self.registry.active()
            if artifact is None and ensure_baseline:
                artifact = self.registry.ensure_baseline()
            if artifact is None:
                self._last_error = "no model artifact available"
                logger.warning("anomaly detector disabled: no model artifact")
                return False
            try:
                payload = self.registry.load(artifact)
            except Exception as exc:
                self._last_error = f"model load failed: {exc}"
                logger.error("model load failed", extra={"model": artifact.identifier, "error": str(exc)})
                return False

            if isinstance(payload, dict):
                self._model = payload.get("model")
                self._scaler = payload.get("scaler")
                self.feature_order = list(payload.get("feature_order") or self.feature_order)
                threshold = payload.get("threshold")
                if threshold is not None:
                    self.threshold = float(threshold)
            else:
                self._model = payload
                self._scaler = None
            self._artifact = artifact
            self._loaded_at = time.time()
            self._last_error = None
            logger.info(
                "anomaly model loaded",
                extra={
                    "model": artifact.identifier,
                    "algorithm": artifact.algorithm,
                    "threshold": self.threshold,
                },
            )
            return True

    def reload(self) -> bool:
        with self._lock:
            self._model = None
            self._artifact = None
        return self.load(ensure_baseline=False)

    @property
    def ready(self) -> bool:
        return self._model is not None

    @property
    def artifact(self) -> ModelArtifact | None:
        return self._artifact

    # ----------------------------------------------------------- inference
    def _vector(self, features: FeatureVector) -> np.ndarray:
        values = [float(getattr(features, name, 0.0) or 0.0) for name in self.feature_order]
        return np.asarray([values], dtype=float)

    def _build_result(
        self, features: FeatureVector, raw: float, prediction: int, latency_ms: float
    ) -> AnomalyResult:
        is_anomaly = bool(prediction == -1 or raw < self.threshold)
        # Distance from the threshold, normalised into a 0.5-0.99 confidence.
        margin = abs(raw - self.threshold)
        confidence = max(0.5, min(0.99, 0.5 + margin * 2.0)) if is_anomaly else max(
            0.4, min(0.95, 0.95 - margin)
        )
        artifact = self._artifact
        return AnomalyResult(
            model_name=artifact.name if artifact else "unknown",
            model_version=artifact.version if artifact else "0",
            anomaly_score=raw,
            is_anomaly=is_anomaly,
            confidence=confidence,
            threshold=self.threshold,
            latency_ms=latency_ms,
            features={name: float(getattr(features, name, 0.0) or 0.0) for name in self.feature_order},
        )

    def score(self, features: FeatureVector) -> AnomalyResult | None:
        """Score one feature vector. Returns ``None`` when unavailable."""
        results = self.score_many([features])
        return results[0] if results else None

    def score_many(self, features_list: list[FeatureVector]) -> list[AnomalyResult | None]:
        """Score a batch of feature vectors with a single model invocation.

        scikit-learn dispatches one parallel job per scoring call, which costs
        several milliseconds *per call* regardless of the number of samples, so
        the batch path in the pipeline is dramatically cheaper per event.
        Each result reports the batch time divided by the number of events.
        """
        batch = list(features_list)
        if not self.enabled or self._model is None or not batch:
            return [None] * len(batch)
        model = self._model
        started = time.perf_counter()
        try:
            matrix = np.asarray(
                [
                    [float(getattr(features, name, 0.0) or 0.0) for name in self.feature_order]
                    for features in batch
                ],
                dtype=float,
            )
            if self._scaler is not None:
                matrix = self._scaler.transform(matrix)
            if hasattr(model, "score_samples"):
                raw_scores = np.asarray(model.score_samples(matrix), dtype=float)
                offset = float(getattr(model, "offset_", 0.0))
                predictions = np.where(raw_scores < offset, -1, 1)
            else:  # one-class SVM and friends expose decision_function instead
                raw_scores = np.asarray(model.decision_function(matrix), dtype=float)
                predictions = np.where(raw_scores < 0.0, -1, 1)
        except Exception as exc:
            self._last_error = f"inference failed: {exc}"
            logger.error("anomaly inference failed", extra={"error": str(exc)})
            return [None] * len(batch)

        per_event_ms = (time.perf_counter() - started) * 1000.0 / len(batch)
        results = [
            self._build_result(features, float(raw), int(prediction), per_event_ms)
            for features, raw, prediction in zip(batch, raw_scores.tolist(), predictions.tolist())
        ]
        with self._lock:
            self._inferences += len(results)
            self._anomalies += sum(1 for result in results if result.is_anomaly)
            self._last_latency_ms = per_event_ms
        return results

    # ------------------------------------------------------------- status
    def statistics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "ready": self.ready,
                "model": self._artifact.identifier if self._artifact else None,
                "algorithm": self._artifact.algorithm if self._artifact else None,
                "threshold": self.threshold,
                "inferences": self._inferences,
                "anomalies": self._anomalies,
                "anomaly_rate": round(self._anomalies / self._inferences, 4) if self._inferences else 0.0,
                "last_latency_ms": round(self._last_latency_ms, 3),
                "loaded_at": (
                    time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self._loaded_at))
                    if self._loaded_at
                    else None
                ),
                "last_error": self._last_error,
                "feature_order": list(self.feature_order),
            }


__all__ = ["AnomalyDetector", "AnomalyResult"]
