"""Runtime assembly: wire configuration, storage, detection and collection.

One function builds the whole platform so the API, the tests and the CLI all
exercise exactly the same object graph. This is the only place where the layers
are allowed to know about each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..alerts.incident import IncidentManager
from ..alerts.manager import AlertManager
from ..collectors import build_collectors
from ..config.logging_config import get_logger, setup_logging
from ..config.paths import AppPaths
from ..config.settings import Settings, get_settings
from ..database.connection import init_db, session_scope
from ..database.context import RepositoryProxy
from ..database.repository import Repository
from ..detection.anomaly.detector import AnomalyDetector
from ..detection.anomaly.registry import ModelRegistry
from ..detection.correlation.correlator import Correlator
from ..detection.engine import DetectionEngine
from ..detection.rules.registry import RuleRegistry
from ..risk.scoring import RiskEngine
from .pipeline import Broadcaster, ProcessingPipeline

logger = get_logger(__name__)

BroadcastFn = Callable[[str, dict], None]


@dataclass
class Runtime:
    """Everything the application needs while it is running."""

    settings: Settings
    paths: AppPaths
    pipeline: ProcessingPipeline
    rule_registry: RuleRegistry
    model_registry: ModelRegistry
    detector: AnomalyDetector
    engine: DetectionEngine
    risk: RiskEngine
    alerts: AlertManager
    incidents: IncidentManager
    correlator: Correlator
    repository: RepositoryProxy
    broadcaster: BroadcastFn | None = None
    websocket_manager: Any | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def components(self) -> dict[str, Any]:
        return {
            "settings": self.settings,
            "paths": self.paths,
            "pipeline": self.pipeline,
            "rules": self.rule_registry,
            "models": self.model_registry,
            "detector": self.detector,
            "engine": self.engine,
            "risk": self.risk,
            "alerts": self.alerts,
            "incidents": self.incidents,
            "correlator": self.correlator,
        }

    def start_collection(self) -> None:
        self.pipeline.start()

    def shutdown(self) -> None:
        self.pipeline.stop()


def sync_detection_rules(settings: Settings, repository: Repository) -> dict[str, int]:
    """Load the YAML rule packs into the database (idempotent)."""
    registry = RuleRegistry(repository, settings.rules_path)
    result = registry.sync_from_disk()
    return result


def build_runtime(
    settings: Settings | None = None,
    *,
    broadcaster: BroadcastFn | None = None,
    start_collection: bool = False,
    initialize_schema: bool = True,
    load_model: bool = True,
) -> Runtime:
    """Assemble the application runtime."""
    settings = settings or get_settings()
    setup_logging(settings)
    paths = settings.ensure_directories()
    warnings: list[str] = []

    if initialize_schema:
        init_db(settings=settings)

    # -------------------------------------------------------- persistence
    repository_proxy = RepositoryProxy()
    with session_scope() as session:
        repository = Repository(session)
        rules_synced = sync_detection_rules(settings, repository)
        repository.log_system(
            message="runtime bootstrap complete",
            category="SYSTEM",
            details={
                "rules": rules_synced,
                "environment": settings.env,
                "database": settings.database_url.split("///")[-1],
            },
        )
    logger.info("detection rules synchronised", extra=rules_synced)

    # ---------------------------------------------------------- detection
    model_registry = ModelRegistry(paths)
    detector = AnomalyDetector(
        model_registry,
        threshold=settings.anomaly_threshold,
        enabled=settings.anomaly_enabled,
    )
    if load_model:
        if not detector.load(ensure_baseline=True):
            warnings.append(
                "anomaly detector unavailable: no model artifact and baseline training failed"
            )
    else:
        warnings.append("anomaly detector not loaded (load_model=False)")

    with session_scope() as session:
        repository_proxy.bind(repository := Repository(session))
        rule_registry = RuleRegistry(repository, settings.rules_path)
        rule_registry.refresh()
        repository_proxy.unbind()

    risk = RiskEngine(settings)
    incidents = IncidentManager(repository_proxy, settings)
    correlator = Correlator(repository_proxy, incidents, settings)
    alerts = AlertManager(repository_proxy, settings, correlator=correlator)
    engine = DetectionEngine(rule_registry, detector, settings=settings)

    if broadcaster is not None:
        def _alert_listener(action: str, payload: dict) -> None:
            broadcaster("alerts", {"type": action, "data": payload})

        alerts.add_listener(_alert_listener)

    # ------------------------------------------------------------ pipeline
    pipeline = ProcessingPipeline(settings, broadcaster=broadcaster, repository=repository_proxy)
    pipeline.attach(
        rules=rule_registry,
        detector=detector,
        engine=engine,
        risk=risk,
        alerts=alerts,
    )

    for collector in build_collectors(pipeline.submit, settings):
        pipeline.attach_collector(collector)

    if settings.simulator_enabled:
        warnings.append(
            "authorized-lab simulator enabled: synthetic events are mixed with real "
            "traffic (MINI_SOC_SIMULATOR_ENABLED=true)"
        )

    if start_collection:
        pipeline.start()

    logger.info(
        "runtime assembled",
        extra={
            "collectors": [getattr(c, "name", "?") for c in pipeline.collectors],
            "rules": len(rule_registry.rules),
            "model": detector.artifact.identifier if detector.artifact else None,
            "warnings": warnings,
        },
    )
    return Runtime(
        settings=settings,
        paths=paths,
        pipeline=pipeline,
        rule_registry=rule_registry,
        model_registry=model_registry,
        detector=detector,
        engine=engine,
        risk=risk,
        alerts=alerts,
        incidents=incidents,
        correlator=correlator,
        repository=repository_proxy,
        broadcaster=broadcaster,
        warnings=warnings,
    )


__all__ = ["Runtime", "build_runtime", "sync_detection_rules"]
