"""Model registry for deployed inference artifacts.

Training lives in ``ml/`` and is deliberately separate from this runtime
component (spec section 10): the backend only ever *loads* a versioned artifact
that the training pipeline produced. Artifacts are stored under
``ml/artifacts/`` with a JSON sidecar holding the evaluation metrics, feature
order and training metadata, so a deployed model is always identifiable.

If no artifact exists, :meth:`ModelRegistry.ensure_baseline` trains one from the
bundled baseline dataset so a fresh install still has working ML detection.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...config.logging_config import get_logger
from ...config.paths import AppPaths

logger = get_logger(__name__)

MANIFEST_NAME = "manifest.json"
BASELINE_NAME = "baseline_isolation_forest"


@dataclass
class ModelArtifact:
    """A versioned model on disk."""

    name: str
    version: str
    path: Path
    metrics: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    feature_order: list[str] = field(default_factory=list)
    threshold: float = -0.05
    algorithm: str = "isolation_forest"

    @property
    def identifier(self) -> str:
        return f"{self.name}:{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "algorithm": self.algorithm,
            "threshold": self.threshold,
            "feature_order": self.feature_order,
            "metrics": self.metrics,
            "metadata": self.metadata,
            "path": str(self.path),
            "trained_at": self.metadata.get("trained_at"),
            "loaded_at": self.metadata.get("loaded_at"),
        }


class ModelRegistry:
    """Discovers and loads model artifacts from the artifacts directory."""

    def __init__(self, paths: AppPaths, artifacts_dir: Path | str | None = None) -> None:
        self.paths = paths
        #: Artifacts usually live under the app home, but the training pipeline
        #: can point the registry at an explicit directory (tests, ad-hoc runs).
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else paths.artifacts
        self._lock = threading.RLock()
        self._manifest_cache: dict[str, Any] | None = None

    # ------------------------------------------------------------ discovery
    def manifest(self) -> dict[str, Any]:
        manifest_path = self.artifacts_dir / MANIFEST_NAME
        if not manifest_path.exists():
            return {}
        try:
            with self._lock:
                self._manifest_cache = json.loads(manifest_path.read_text(encoding="utf-8"))
                return self._manifest_cache or {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("model manifest unreadable", extra={"error": str(exc)})
            return {}

    def list_models(self) -> list[ModelArtifact]:
        manifest = self.manifest()
        artifacts: list[ModelArtifact] = []
        entries = manifest.get("models", [])
        for entry in entries:
            path = Path(entry.get("path") or "")
            if not path.is_absolute():
                path = self.artifacts_dir / path
            if not path.exists():
                continue
            artifacts.append(
                ModelArtifact(
                    name=entry.get("name", "unknown"),
                    version=str(entry.get("version", "0")),
                    path=path,
                    metrics=entry.get("metrics", {}) or {},
                    metadata={k: v for k, v in entry.items() if k not in {"metrics"}},
                    feature_order=entry.get("feature_order", []) or [],
                    threshold=float(entry.get("threshold", -0.05)),
                    algorithm=entry.get("algorithm", "isolation_forest"),
                )
            )
        return artifacts

    def latest(self, *, algorithm: str | None = None) -> ModelArtifact | None:
        artifacts = [a for a in self.list_models() if not algorithm or a.algorithm == algorithm]
        if not artifacts:
            return None
        return sorted(artifacts, key=lambda a: a.version)[-1]

    def active(self) -> ModelArtifact | None:
        """The model marked active in the manifest, else the newest one."""
        manifest = self.manifest()
        active_id = manifest.get("active")
        if active_id:
            for artifact in self.list_models():
                if artifact.identifier == active_id:
                    return artifact
        return self.latest()

    # -------------------------------------------------------------- loading
    def load(self, artifact: ModelArtifact) -> Any:
        """Load a joblib artifact from disk."""
        import joblib  # imported lazily so API-only deployments stay light

        return joblib.load(artifact.path)

    # ------------------------------------------------------------- baseline
    def ensure_baseline(self, *, force: bool = False) -> ModelArtifact | None:
        """Train and register a baseline model when none is deployed yet."""
        if not force:
            active = self.active()
            if active is not None:
                return active
        try:
            # The training pipeline lives beside the backend package (spec section 30),
            # so make the repository root importable before calling into it.
            import sys

            root = str(self.paths.home)
            if root not in sys.path:
                sys.path.insert(0, root)
            from ml.train import train_model  # type: ignore

            logger.info("no deployed model found - training bundled baseline model")
            result = train_model(
                algorithm="isolation_forest",
                version=None,
                artifacts_dir=str(self.artifacts_dir),
                baseline=True,
            )
            artifact = self.active()
            if artifact is not None:
                logger.info("baseline model ready", extra={"model": artifact.identifier})
            return artifact or (result if isinstance(result, ModelArtifact) else None)
        except Exception as exc:
            logger.error("baseline model training failed", extra={"error": str(exc)})
            return None

    # -------------------------------------------------------------- writing
    def register(
        self,
        *,
        name: str,
        version: str,
        path: Path,
        metrics: dict[str, Any],
        feature_order: list[str],
        threshold: float,
        algorithm: str,
        extra: dict[str, Any] | None = None,
        activate: bool = True,
    ) -> ModelArtifact:
        """Add an artifact to the manifest (used by the training pipeline)."""
        manifest = self.manifest() or {"models": []}
        entry: dict[str, Any] = {
            "name": name,
            "version": version,
            "algorithm": algorithm,
            "threshold": threshold,
            "feature_order": feature_order,
            "metrics": metrics,
            "path": str(path.relative_to(self.artifacts_dir))
            if path.is_relative_to(self.artifacts_dir)
            else str(path),
            "trained_at": datetime.now(timezone.utc).isoformat(),
            **(extra or {}),
        }
        models = [m for m in manifest.get("models", []) if not (m.get("name") == name and str(m.get("version")) == str(version))]
        models.append(entry)
        manifest["models"] = models
        if activate:
            manifest["active"] = f"{name}:{version}"
        manifest["updated_at"] = datetime.now(timezone.utc).isoformat()
        manifest_path = self.artifacts_dir / MANIFEST_NAME
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with self._lock:
            self._manifest_cache = manifest
        return ModelArtifact(
            name=name,
            version=version,
            path=path,
            metrics=metrics,
            feature_order=feature_order,
            threshold=threshold,
            algorithm=algorithm,
            metadata=entry,
        )


__all__ = ["BASELINE_NAME", "MANIFEST_NAME", "ModelArtifact", "ModelRegistry"]
