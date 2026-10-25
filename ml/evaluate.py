"""Model evaluation: security-relevant metrics, not just accuracy.

Reported per model:

* confusion matrix (TP/FP/TN/FN)
* precision, recall, F1-score
* false-positive rate and false-negative rate (what an analyst actually feels)
* ROC-AUC when both classes are present
* inference latency (mean/p95 per sample, single-sample prediction)
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any

import numpy as np

from .features import FEATURE_ORDER


def confusion(predictions: np.ndarray, labels: np.ndarray) -> dict[str, int]:
    tp = int(np.sum((predictions == 1) & (labels == 1)))
    fp = int(np.sum((predictions == 1) & (labels == 0)))
    tn = int(np.sum((predictions == 0) & (labels == 0)))
    fn = int(np.sum((predictions == 0) & (labels == 1)))
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def metrics_from_confusion(counts: dict[str, int]) -> dict[str, float]:
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "specificity": round(1 - fpr, 4),
    }


def roc_auc(scores: np.ndarray, labels: np.ndarray) -> float | None:
    """ROC-AUC of the anomaly score (no dependency on sklearn's ranking)."""
    positive = scores[labels == 1]
    negative = scores[labels == 0]
    if len(positive) == 0 or len(negative) == 0:
        return None
    # Mann-Whitney U statistic with average ranks for ties.
    combined = np.concatenate([positive, negative])
    order = combined.argsort()
    ranks = np.empty(len(combined), dtype=float)
    ranks[order] = np.arange(1, len(combined) + 1)
    # average ranks for ties
    sorted_values = combined[order]
    index = 0
    while index < len(sorted_values):
        end = index
        while end + 1 < len(sorted_values) and sorted_values[end + 1] == sorted_values[index]:
            end += 1
        if end > index:
            average = (ranks[order[index : end + 1]]).mean()
            ranks[order[index : end + 1]] = average
        index = end + 1
    rank_sum = float(ranks[: len(positive)].sum())
    auc = (rank_sum - len(positive) * (len(positive) + 1) / 2) / (len(positive) * len(negative))
    return round(float(auc), 4)


def inference_latency(model, scaler, matrix: np.ndarray, *, sample: int = 200) -> dict[str, float]:
    """Measure single-row inference latency (what the pipeline experiences)."""
    latencies: list[float] = []
    rows = matrix[: min(sample, len(matrix))]
    for row in rows:
        vector = row.reshape(1, -1)
        started = time.perf_counter()
        if scaler is not None:
            vector = scaler.transform(vector)
        model.score_samples(vector)
        latencies.append((time.perf_counter() - started) * 1000.0)
    if not latencies:
        return {"mean_ms": 0.0, "p95_ms": 0.0, "samples": 0}
    latencies.sort()
    p95 = latencies[int(len(latencies) * 0.95) - 1] if len(latencies) > 1 else latencies[0]
    return {
        "mean_ms": round(statistics.fmean(latencies), 4),
        "p95_ms": round(p95, 4),
        "max_ms": round(max(latencies), 4),
        "samples": len(latencies),
    }


def evaluate_model(
    model,
    scaler,
    threshold: float,
    matrix: np.ndarray,
    labels: np.ndarray,
    *,
    scenarios: np.ndarray | None = None,
) -> dict[str, Any]:
    """Full evaluation report for a deployed model."""
    vectors = scaler.transform(matrix) if scaler is not None else matrix
    scores = np.asarray(model.score_samples(vectors), dtype=float)
    predictions = (scores < threshold).astype(int)
    counts = confusion(predictions, labels)
    report: dict[str, Any] = {
        "threshold": float(threshold),
        "samples": int(len(labels)),
        "confusion": counts,
        **metrics_from_confusion(counts),
        "roc_auc": roc_auc(-scores, labels),
        "score_mean_normal": round(float(scores[labels == 0].mean()), 5) if (labels == 0).any() else None,
        "score_mean_anomaly": round(float(scores[labels == 1].mean()), 5) if (labels == 1).any() else None,
        "latency": inference_latency(model, scaler, matrix),
        "feature_order": list(FEATURE_ORDER),
    }
    if scenarios is not None:
        per_scenario: dict[str, dict[str, float]] = {}
        for name in sorted(set(scenarios.tolist())):
            mask = scenarios == name
            scenario_labels = labels[mask]
            if not len(scenario_labels):
                continue
            if name == "normal":
                detected = float((predictions[mask] == 1).mean())
                per_scenario[name] = {
                    "samples": int(len(scenario_labels)),
                    "false_positive_rate": round(detected, 4),
                }
            else:
                detected = float((predictions[mask] == 1).mean())
                per_scenario[name] = {
                    "samples": int(len(scenario_labels)),
                    "detection_rate": round(detected, 4),
                }
        report["per_scenario"] = per_scenario
    return report


def load_artifact(path: str | Path) -> dict[str, Any]:
    import joblib

    payload = joblib.load(Path(path))
    if not isinstance(payload, dict):
        payload = {"model": payload, "scaler": None, "threshold": -0.05}
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a deployed Mini SOC anomaly model")
    parser.add_argument("--model", required=True, help="path to a .joblib artifact")
    parser.add_argument("--source", default="synthetic", choices=["synthetic", "database"])
    parser.add_argument("--output", default=None, help="write the report as JSON")
    args = parser.parse_args(argv)

    from .dataset import database_dataset, synthetic_dataset

    dataset = synthetic_dataset() if args.source == "synthetic" else database_dataset()
    matrix, labels, scenarios = dataset.matrix()
    payload = load_artifact(args.model)
    report = evaluate_model(
        payload["model"],
        payload.get("scaler"),
        float(payload.get("threshold", -0.05)),
        matrix,
        labels,
        scenarios=scenarios,
    )
    text = json.dumps(report, indent=2)
    print(text)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
