"""Dataset construction for training.

Two sources are supported:

* **real events** - export feature vectors recomputed from stored events
  (``--source database``); unlabelled, so training treats them as normal
  traffic unless a rule/alert already marked them as attacks;
* **synthetic lab** - the labelled generator used for baseline models and for
  measuring detection quality (``--source synthetic``).

Cleaning is explicit and logged: duplicates are dropped, non-finite values and
impossible ranges are repaired, and the class balance is reported so nobody
trains on a silently degenerate dataset.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .features import (
    ATTACK_SCENARIOS,
    FEATURE_ORDER,
    LabelledSample,
    build_synthetic_dataset,
    samples_to_matrix,
)


@dataclass
class Dataset:
    """A cleaned dataset ready for training."""

    samples: list[LabelledSample]
    feature_order: list[str]
    source: str
    statistics: dict[str, Any]

    @property
    def size(self) -> int:
        return len(self.samples)

    @property
    def positives(self) -> int:
        return sum(1 for sample in self.samples if sample.label == 1)

    @property
    def negatives(self) -> int:
        return self.size - self.positives

    def matrix(self):
        return samples_to_matrix(self.samples)

    def split(self, *, validation_fraction: float = 0.3, seed: int = 7) -> tuple["Dataset", "Dataset"]:
        """Deterministic train/validation split (stratified by label+scenario)."""
        rng = random.Random(seed)
        buckets: dict[tuple[int, str], list[LabelledSample]] = {}
        for sample in self.samples:
            buckets.setdefault((sample.label, sample.scenario), []).append(sample)
        train: list[LabelledSample] = []
        validation: list[LabelledSample] = []
        for bucket in buckets.values():
            rng.shuffle(bucket)
            cut = max(1, int(len(bucket) * (1 - validation_fraction)))
            train.extend(bucket[:cut])
            validation.extend(bucket[cut:] or bucket[:1])
        rng.shuffle(train)
        rng.shuffle(validation)
        return (
            Dataset(train, self.feature_order, self.source, {"split": "train"}),
            Dataset(validation, self.feature_order, self.source, {"split": "validation"}),
        )

    def to_csv(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow([*FEATURE_ORDER, "label", "scenario"])
            for sample in self.samples:
                writer.writerow([*sample.as_row(), sample.label, sample.scenario])
        return target


# --------------------------------------------------------------------------
# cleaning
# --------------------------------------------------------------------------
def clean_samples(samples: list[LabelledSample], *, max_ratio: float = 60.0) -> tuple[list[LabelledSample], dict[str, Any]]:
    """Drop duplicates and repair impossible values."""
    import math

    seen: set[tuple] = set()
    cleaned: list[LabelledSample] = []
    dropped_duplicates = 0
    repaired = 0

    for sample in samples:
        key = (tuple(round(v, 6) for v in sample.as_row()), sample.label)
        if key in seen:
            dropped_duplicates += 1
            continue
        seen.add(key)
        values = dict(sample.features)
        for name in FEATURE_ORDER:
            value = values.get(name, 0.0)
            try:
                number = float(value)
            except (TypeError, ValueError):
                number = 0.0
            if not math.isfinite(number) or number < 0:
                number = 0.0
                repaired += 1
            values[name] = number
        # cheap sanity bounds: a 5 minute window cannot exceed max_ratio x rate
        for total, rate in (("bytes_total", "bytes_per_second"), ("packets_total", "packets_per_second")):
            window_estimate = values[total] / max(values[rate], 1e-9)
            if window_estimate < 1 or window_estimate > 10_000:
                values[rate] = round(values[total] / 300.0, 3)
                repaired += 1
        cleaned.append(LabelledSample(values, sample.label, sample.scenario, sample.meta))

    statistics = {
        "input": len(samples),
        "output": len(cleaned),
        "dropped_duplicates": dropped_duplicates,
        "repaired_values": repaired,
        "positive": sum(1 for s in cleaned if s.label == 1),
        "negative": sum(1 for s in cleaned if s.label == 0),
    }
    return cleaned, statistics


# --------------------------------------------------------------------------
# sources
# --------------------------------------------------------------------------
def synthetic_dataset(
    *, normal_samples: int = 1200, attack_per_scenario: int = 120, seed: int = 20260818
) -> Dataset:
    samples = build_synthetic_dataset(
        normal_samples=normal_samples, attack_samples_per_scenario=attack_per_scenario, seed=seed
    )
    cleaned, statistics = clean_samples(samples)
    statistics.update({"source": "synthetic", "scenarios": list(ATTACK_SCENARIOS)})
    return Dataset(cleaned, FEATURE_ORDER, "synthetic", statistics)


def database_dataset(
    *,
    database_url: str | None = None,
    minutes: int = 1440,
    limit: int = 20000,
) -> Dataset:
    """Recompute feature vectors from stored events (unlabelled -> normal)."""
    from datetime import timedelta

    from app.database.base import utcnow
    from app.database.connection import configure_engine, session_scope
    from app.database.repository import Repository
    from app.processors.feature_engineering import FeatureExtractor

    if database_url:
        configure_engine(database_url)

    extractor = FeatureExtractor(window_seconds=300)
    since = utcnow() - timedelta(minutes=minutes)
    labels_by_entity: dict[str, int] = {}

    with session_scope() as session:
        repository = Repository(session)
        events = repository.list_events(limit=limit, start=since, order="asc")
        for event in events:
            from app.processors.models import NormalizedEvent

            extractor.add_event(
                NormalizedEvent(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    source_port=event.source_port,
                    destination_port=event.destination_port,
                    protocol=event.protocol,
                    packet_count=event.packet_count,
                    bytes=event.bytes,
                    connection_state=event.connection_state,
                    event_type=event.event_type,
                    direction=event.direction,
                    interface=event.interface,
                    collector=event.collector,
                    metadata=event.meta or {},
                    network={},
                )
            )
            if float(event.risk_score or 0.0) >= 61:
                labels_by_entity[event.source_ip or ""] = 1
        alerts = repository.list_alerts(limit=5000)
        for alert in alerts:
            if alert.source_ip:
                labels_by_entity[alert.source_ip] = 1

    samples: list[LabelledSample] = []
    for features in extractor.features_for_all(limit=limit):
        samples.append(
            LabelledSample(
                features={
                    name: float(getattr(features, name, 0.0) or 0.0) for name in FEATURE_ORDER
                },
                label=labels_by_entity.get(features.source_ip, 0),
                scenario="observed",
            )
        )
    cleaned, statistics = clean_samples(samples)
    statistics.update({"source": "database", "minutes": minutes})
    return Dataset(cleaned, FEATURE_ORDER, "database", statistics)


__all__ = ["Dataset", "clean_samples", "database_dataset", "synthetic_dataset"]
