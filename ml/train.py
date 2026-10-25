"""Training pipeline: dataset -> clean -> split -> train -> evaluate -> deploy.

The model is trained **unsupervised on normal traffic only** (that is how
anomaly detection is supposed to work in a SOC: learn the baseline, flag the
deviations), then evaluated on a labelled hold-out set that contains both
normal traffic and every attack scenario from the lab.

Deployment is a two-step contract that keeps training and inference separate:
the artifact is written under ``ml/artifacts/`` and registered in the manifest;
the backend loads it from the registry and never trains anything itself.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from ._pathsetup import ensure_backend_importable, repo_root
from .dataset import Dataset, database_dataset, synthetic_dataset
from .evaluate import evaluate_model
from .features import FEATURE_ORDER

DEFAULT_ALGORITHMS = ("isolation_forest", "local_outlier_factor", "one_class_svm")


# ---------------------------------------------------------------------------
# model factory
# ---------------------------------------------------------------------------
def build_estimator(algorithm: str, *, contamination: float = 0.03, seed: int = 42):
    """Create an unfitted sklearn estimator for the requested algorithm."""
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.svm import OneClassSVM

    if algorithm == "isolation_forest":
        return IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination=contamination,
            random_state=seed,
            n_jobs=-1,
        )
    if algorithm == "local_outlier_factor":
        return LocalOutlierFactor(
            n_neighbors=20, novelty=True, contamination=contamination
        )
    if algorithm == "one_class_svm":
        return OneClassSVM(kernel="rbf", gamma="scale", nu=min(max(contamination, 0.01), 0.5))
    raise ValueError(f"unsupported algorithm {algorithm!r}; choose from {DEFAULT_ALGORITHMS}")


def next_version(artifacts_dir: Path, *, algorithm: str) -> str:
    """Monotonic, human readable version: ``v2-20261001``."""
    manifest_path = artifacts_dir / "manifest.json"
    existing: list[str] = []
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            existing = [
                str(entry.get("version"))
                for entry in manifest.get("models", [])
                if entry.get("algorithm") == algorithm
            ]
        except json.JSONDecodeError:
            existing = []
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    index = 1
    while f"v{index}-{stamp}" in existing:
        index += 1
    return f"v{index}-{stamp}"


# ---------------------------------------------------------------------------
# training
# ---------------------------------------------------------------------------
def train_model(
    *,
    algorithm: str = "isolation_forest",
    version: str | None = None,
    artifacts_dir: str | Path | None = None,
    baseline: bool = False,
    source: str | None = None,
    database_url: str | None = None,
    normal_samples: int = 1500,
    attack_per_scenario: int = 150,
    validation_fraction: float = 0.35,
    contamination: float = 0.03,
    threshold_percentile: float = 3.0,
    seed: int = 42,
    verbose: bool = True,
) -> dict[str, Any]:
    """Train, evaluate, persist and register one anomaly model."""
    ensure_backend_importable()

    from sklearn.preprocessing import StandardScaler

    from app.config.paths import default_paths
    from app.detection.anomaly.registry import ModelRegistry

    root = repo_root()
    artifacts = Path(artifacts_dir) if artifacts_dir else (root / "ml" / "artifacts")
    artifacts.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------- dataset
    if source is None:
        source = "synthetic" if baseline else "database"
    if source == "database":
        try:
            dataset = database_dataset(database_url=database_url)
        except Exception as exc:  # a fresh install has no events yet
            if verbose:
                print(f"[train] database dataset unavailable ({exc}); using synthetic lab data")
            dataset = synthetic_dataset(normal_samples=normal_samples, attack_per_scenario=attack_per_scenario, seed=seed)
    else:
        dataset = synthetic_dataset(normal_samples=normal_samples, attack_per_scenario=attack_per_scenario, seed=seed)

    if dataset.size < 50:
        if verbose:
            print("[train] not enough samples for training; falling back to synthetic lab data")
        dataset = synthetic_dataset(normal_samples=normal_samples, attack_per_scenario=attack_per_scenario, seed=seed)

    train_set, validation_set = dataset.split(validation_fraction=validation_fraction, seed=seed)
    train_matrix, train_labels, _ = train_set.matrix()
    validation_matrix, validation_labels, validation_scenarios = validation_set.matrix()

    normal_mask = train_labels == 0
    normal_training_matrix = train_matrix[normal_mask] if normal_mask.any() else train_matrix

    # ----------------------------------------------------------- training
    scaler = StandardScaler()
    scaled_normal = scaler.fit_transform(normal_training_matrix)
    estimator = build_estimator(algorithm, contamination=contamination, seed=seed)
    estimator.fit(scaled_normal)

    validation_scaled = scaler.transform(validation_matrix)
    validation_scores = np.asarray(estimator.score_samples(validation_scaled), dtype=float)
    threshold = float(np.percentile(validation_scores[validation_labels == 0], threshold_percentile))
    threshold = min(threshold, -1e-6)

    report = evaluate_model(
        estimator,
        scaler,
        threshold,
        validation_matrix,
        validation_labels,
        scenarios=validation_scenarios,
    )
    report.update(
        {
            "algorithm": algorithm,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "dataset": dataset.statistics,
            "training_samples": int(len(normal_training_matrix)),
            "validation_samples": int(len(validation_matrix)),
            "threshold_percentile": threshold_percentile,
            "contamination": contamination,
            "feature_order": list(FEATURE_ORDER),
            "scenario_detection_rates": report.get("per_scenario", {}),
        }
    )

    # ------------------------------------------------------------ persist
    version = version or next_version(artifacts, algorithm=algorithm)
    model_name = f"{'baseline' if baseline else 'anomaly'}_{algorithm}"
    artifact_path = artifacts / f"{model_name}_{version}.joblib"

    import joblib

    joblib.dump(
        {
            "model": estimator,
            "scaler": scaler,
            "threshold": threshold,
            "algorithm": algorithm,
            "feature_order": list(FEATURE_ORDER),
            "version": version,
            "trained_at": report["trained_at"],
        },
        artifact_path,
    )

    registry = ModelRegistry(default_paths(), artifacts_dir=artifacts)
    registry.artifacts_dir.mkdir(parents=True, exist_ok=True)
    registry.register(
        name=model_name,
        version=version,
        path=artifact_path,
        metrics=report,
        feature_order=list(FEATURE_ORDER),
        threshold=threshold,
        algorithm=algorithm,
        extra={"trained_at": report["trained_at"], "baseline": baseline, "dataset_source": dataset.source},
        activate=True,
    )

    if verbose:
        print(f"[train] model   : {model_name}:{version} ({algorithm})")
        print(f"[train] artifact: {artifact_path}")
        print(
            "[train] metrics : "
            f"precision={report['precision']:.3f} recall={report['recall']:.3f} "
            f"f1={report['f1_score']:.3f} fpr={report['false_positive_rate']:.4f} "
            f"fnr={report['false_negative_rate']:.4f} roc_auc={report['roc_auc']}"
        )
        print(
            f"[train] latency : mean={report['latency']['mean_ms']:.3f} ms "
            f"p95={report['latency']['p95_ms']:.3f} ms"
        )
        print(f"[train] threshold: {threshold:.5f}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the Mini SOC anomaly detection model")
    parser.add_argument("--algorithm", default="isolation_forest", choices=list(DEFAULT_ALGORITHMS))
    parser.add_argument("--version", default=None)
    parser.add_argument("--artifacts-dir", default=None)
    parser.add_argument("--baseline", action="store_true", help="train the bundled zero-config baseline")
    parser.add_argument("--source", default=None, choices=["synthetic", "database"])
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--normal-samples", type=int, default=1500)
    parser.add_argument("--attack-per-scenario", type=int, default=150)
    parser.add_argument("--contamination", type=float, default=0.03)
    parser.add_argument("--threshold-percentile", type=float, default=3.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--report", default=None, help="write the JSON report to this path")
    args = parser.parse_args(argv)

    report = train_model(
        algorithm=args.algorithm,
        version=args.version,
        artifacts_dir=args.artifacts_dir,
        baseline=args.baseline,
        source=args.source,
        database_url=args.database_url,
        normal_samples=args.normal_samples,
        attack_per_scenario=args.attack_per_scenario,
        contamination=args.contamination,
        threshold_percentile=args.threshold_percentile,
        seed=args.seed,
    )
    if args.report:
        target = Path(args.report)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[train] report  : {target}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
