"""Machine learning pipeline: dataset, training, evaluation, deployment, inference."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ML_ROOT = Path(__file__).resolve().parents[2]
if str(ML_ROOT) not in sys.path:
    sys.path.insert(0, str(ML_ROOT))

from ml.dataset import clean_samples, synthetic_dataset  # noqa: E402
from ml.evaluate import confusion, evaluate_model, metrics_from_confusion, roc_auc  # noqa: E402
from ml.features import ATTACK_SCENARIOS, FEATURE_ORDER, build_synthetic_dataset  # noqa: E402


class TestDataset:
    def test_baseline_dataset_is_imbalanced_like_real_traffic(self) -> None:
        dataset = synthetic_dataset(normal_samples=200, attack_per_scenario=20, seed=7)
        assert dataset.positives > 0
        assert dataset.negatives > dataset.positives
        assert dataset.statistics["source"] == "synthetic"

    def test_all_attack_scenarios_are_represented(self) -> None:
        samples = build_synthetic_dataset(normal_samples=50, attack_samples_per_scenario=10, seed=3)
        scenarios = {sample.scenario for sample in samples}
        assert set(ATTACK_SCENARIOS) <= scenarios

    def test_cleaning_drops_duplicates_and_repairs_values(self) -> None:
        samples = build_synthetic_dataset(normal_samples=5, attack_samples_per_scenario=1, seed=1)
        duplicated = samples + samples[:3]
        duplicated.append(type(samples[0])(features={**samples[0].features, "bytes_total": -10}, label=0))
        cleaned, statistics = clean_samples(duplicated)
        assert statistics["dropped_duplicates"] >= 3
        assert statistics["repaired_values"] >= 1
        assert all(value >= 0 for sample in cleaned for value in sample.as_row())

    def test_split_is_deterministic_and_stratified(self) -> None:
        dataset = synthetic_dataset(normal_samples=100, attack_per_scenario=20, seed=5)
        train, validation = dataset.split(validation_fraction=0.3, seed=5)
        assert train.size + validation.size == dataset.size
        assert validation.positives > 0
        again_train, _ = dataset.split(validation_fraction=0.3, seed=5)
        assert [s.label for s in train.samples] == [s.label for s in again_train.samples]

    def test_matrix_shapes_match_the_feature_contract(self) -> None:
        matrix, labels, scenarios = synthetic_dataset(normal_samples=20, attack_per_scenario=5).matrix()
        assert matrix.shape[1] == len(FEATURE_ORDER)
        assert matrix.shape[0] == labels.shape[0] == scenarios.shape[0]


class TestMetrics:
    def test_confusion_matrix_counts(self) -> None:
        import numpy as np

        counts = confusion(
            np.array([1, 1, 0, 0, 1]), np.array([1, 0, 0, 1, 1])
        )
        assert counts == {"tp": 2, "fp": 1, "tn": 1, "fn": 1}

    def test_derived_metrics_are_consistent(self) -> None:
        metrics = metrics_from_confusion({"tp": 8, "fp": 2, "tn": 90, "fn": 2})
        assert metrics["precision"] == pytest.approx(8 / 10)
        assert metrics["recall"] == pytest.approx(8 / 10)
        assert metrics["f1_score"] == pytest.approx(0.8)
        # ``evaluate_model`` rounds to 4 decimal places, so compare within 1e-4.
        assert metrics["false_positive_rate"] == pytest.approx(2 / 92, abs=1e-4)
        assert metrics["false_negative_rate"] == pytest.approx(0.2)

    def test_zero_division_is_handled(self) -> None:
        metrics = metrics_from_confusion({"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        assert metrics["precision"] == 0.0
        assert metrics["recall"] == 0.0

    def test_roc_auc_of_a_perfect_separator(self) -> None:
        import numpy as np

        scores = np.array([0.9, 0.8, 0.2, 0.1])
        labels = np.array([1, 1, 0, 0])
        assert roc_auc(scores, labels) == pytest.approx(1.0)

    def test_roc_auc_requires_both_classes(self) -> None:
        import numpy as np

        assert roc_auc(np.array([0.1, 0.2]), np.array([1, 1])) is None


class TestTrainingPipeline:
    @pytest.fixture(scope="class")
    @classmethod
    def trained(cls, tmp_path_factory) -> dict:
        from ml.train import train_model

        artifacts = tmp_path_factory.mktemp("artifacts")
        report = train_model(
            algorithm="isolation_forest",
            version="vtest-1",
            artifacts_dir=str(artifacts),
            baseline=True,
            normal_samples=300,
            attack_per_scenario=40,
            seed=13,
            threshold_percentile=5.0,
            verbose=False,
        )
        return {"report": report, "artifacts": artifacts}

    def test_training_produces_a_report_and_artifact(self, trained) -> None:
        report = trained["report"]
        assert report["algorithm"] == "isolation_forest"
        assert report["samples"] > 100
        assert report["feature_order"] == FEATURE_ORDER
        assert (trained["artifacts"] / "baseline_isolation_forest_vtest-1.joblib").exists()

    def test_evaluation_metrics_are_meaningful(self, trained) -> None:
        report = trained["report"]
        assert report["recall"] >= 0.8, "the lab scenarios must be detected"
        assert report["precision"] >= 0.6
        assert report["false_positive_rate"] <= 0.15
        assert report["roc_auc"] is None or report["roc_auc"] >= 0.8
        assert set(report["confusion"]) == {"tp", "fp", "tn", "fn"}

    def test_inference_latency_is_measured(self, trained) -> None:
        report = trained["report"]
        assert report["latency"]["samples"] > 0
        assert report["latency"]["mean_ms"] > 0
        assert report["latency"]["mean_ms"] < 100  # must be viable for real-time scoring

    def test_per_scenario_detection_rates_are_reported(self, trained) -> None:
        per_scenario = trained["report"]["per_scenario"]
        for scenario in ATTACK_SCENARIOS:
            assert scenario in per_scenario
            assert per_scenario[scenario]["detection_rate"] > 0.5

    def test_manifest_registers_the_model(self, trained) -> None:
        manifest = json.loads((trained["artifacts"] / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["active"] == "baseline_isolation_forest:vtest-1"
        assert manifest["models"][0]["metrics"]["f1_score"] >= 0

    def test_versioning_increments(self, trained) -> None:
        from ml.train import next_version

        assert next_version(trained["artifacts"], algorithm="isolation_forest") != "vtest-1"


class TestAnomalyDetector:
    @pytest.fixture()
    def detector(self, settings):
        from app.detection.anomaly.detector import AnomalyDetector
        from app.detection.anomaly.registry import ModelRegistry

        registry = ModelRegistry(settings.paths)
        detector = AnomalyDetector(registry, threshold=-0.05, enabled=True)
        loaded = detector.load(ensure_baseline=True)
        if not loaded:  # pragma: no cover - only if scikit-learn is unavailable
            pytest.skip("baseline model could not be trained")
        return detector

    def test_baseline_bootstrap_creates_a_usable_model(self, detector) -> None:
        assert detector.ready is True
        assert detector.artifact is not None
        assert (detector.registry.artifacts_dir / "manifest.json").exists()

    def test_obvious_anomaly_scores_as_anomalous(self, detector) -> None:
        from app.processors.models import FeatureVector

        features = FeatureVector(
            source_ip="10.0.0.5",
            window_seconds=300,
            connection_count=900,
            unique_destination_ports=700,
            unique_destination_ips=12,
            failed_connections=600,
            dns_requests=0,
            auth_failures=0,
            bytes_total=400_000,
            packets_total=3000,
            bytes_per_second=1333.0,
            packets_per_second=10.0,
            unique_protocols=1,
            events_per_minute=180.0,
        )
        result = detector.score(features)
        assert result is not None
        assert result.is_anomaly is True
        assert result.risk_contribution() > 0
        assert result.latency_ms >= 0

    def test_normal_traffic_is_not_flagged(self, detector) -> None:
        from app.processors.models import FeatureVector

        features = FeatureVector(
            source_ip="10.0.0.6",
            window_seconds=300,
            connection_count=10,
            unique_destination_ports=4,
            unique_destination_ips=3,
            failed_connections=0,
            dns_requests=12,
            unique_dns_queries=9,
            auth_failures=0,
            bytes_total=200_000,
            packets_total=280,
            bytes_per_second=666.0,
            packets_per_second=0.9,
            avg_connection_duration_ms=120.0,
            unique_protocols=2,
            events_per_minute=2.0,
        )
        result = detector.score(features)
        assert result is not None
        assert result.is_anomaly is False

    def test_statistics_describe_the_deployed_model(self, detector) -> None:
        stats = detector.statistics()
        assert stats["ready"] is True
        assert stats["algorithm"] == "isolation_forest"
        assert stats["feature_order"] == FEATURE_ORDER

    def test_disabled_detector_returns_none(self, settings) -> None:
        from app.detection.anomaly.detector import AnomalyDetector
        from app.detection.anomaly.registry import ModelRegistry
        from app.processors.models import FeatureVector

        detector = AnomalyDetector(ModelRegistry(settings.paths), enabled=False)
        assert detector.score(FeatureVector(source_ip="x", window_seconds=60)) is None

    def test_reload_after_activation(self, detector) -> None:
        assert detector.reload() is True
