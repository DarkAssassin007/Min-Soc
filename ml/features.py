"""Feature contract shared by training and inference.

The backend imports :data:`FEATURE_ORDER` from ``app.processors.feature_engineering``;
this module re-exports exactly the same list so a model artifact always records
the feature order it was trained with. A mismatch is the classic cause of
silently wrong ML in production, so it is checked explicitly.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, time
from typing import Iterable

# --- keep in sync with backend/app/processors/feature_engineering.py --------
FEATURE_ORDER: list[str] = [
    "connection_count",
    "unique_destination_ports",
    "unique_destination_ips",
    "failed_connections",
    "dns_requests",
    "unique_dns_queries",
    "auth_failures",
    "bytes_total",
    "packets_total",
    "bytes_per_second",
    "packets_per_second",
    "avg_connection_duration_ms",
    "unique_protocols",
    "events_per_minute",
]

#: Human readable labels used in evaluation reports.
LABELS = {0: "normal", 1: "anomaly"}


@dataclass
class LabelledSample:
    features: dict[str, float]
    label: int
    scenario: str = "normal"
    meta: dict = field(default_factory=dict)

    def as_row(self) -> list[float]:
        return [float(self.features.get(name, 0.0)) for name in FEATURE_ORDER]


def synthetic_sample(scenario: str, rng: random.Random) -> LabelledSample:
    """Generate one labelled feature vector for a lab scenario."""
    if scenario == "port_scan":
        ports = rng.randint(20, 400)
        connections = ports + rng.randint(0, 40)
        values = {
            "connection_count": connections,
            "unique_destination_ports": ports,
            "unique_destination_ips": rng.choice([1, 1, 1, 2, 5]),
            "failed_connections": int(connections * rng.uniform(0.2, 0.8)),
            "dns_requests": rng.randint(0, 5),
            "unique_dns_queries": rng.randint(0, 4),
            "auth_failures": 0,
            "bytes_total": connections * rng.randint(54, 120),
            "packets_total": connections * rng.randint(1, 3),
        }
        label = 1
    elif scenario == "brute_force":
        failures = rng.randint(5, 120)
        values = {
            "connection_count": failures + rng.randint(0, 10),
            "unique_destination_ports": rng.randint(1, 3),
            "unique_destination_ips": 1,
            "failed_connections": failures,
            "dns_requests": rng.randint(0, 3),
            "unique_dns_queries": rng.randint(0, 2),
            "auth_failures": failures,
            "bytes_total": failures * rng.randint(180, 320),
            "packets_total": failures * rng.randint(4, 8),
        }
        label = 1
    elif scenario == "connection_flood":
        connections = rng.randint(80, 1200)
        values = {
            "connection_count": connections,
            "unique_destination_ports": rng.randint(1, 4),
            "unique_destination_ips": rng.randint(1, 3),
            "failed_connections": int(connections * rng.uniform(0.0, 0.3)),
            "dns_requests": rng.randint(0, 10),
            "unique_dns_queries": rng.randint(0, 8),
            "auth_failures": 0,
            "bytes_total": connections * rng.randint(40, 90),
            "packets_total": connections,
        }
        label = 1
    elif scenario == "dns_anomaly":
        queries = rng.randint(120, 2000)
        values = {
            "connection_count": queries + rng.randint(0, 20),
            "unique_destination_ports": 1,
            "unique_destination_ips": rng.randint(1, 4),
            "failed_connections": 0,
            "dns_requests": queries,
            "unique_dns_queries": int(queries * rng.uniform(0.85, 1.0)),
            "auth_failures": 0,
            "bytes_total": queries * rng.randint(60, 140),
            "packets_total": queries,
        }
        label = 1
    elif scenario == "volume_anomaly":
        megabytes = rng.uniform(40, 400)
        values = {
            "connection_count": rng.randint(1, 20),
            "unique_destination_ports": rng.randint(1, 3),
            "unique_destination_ips": rng.randint(1, 2),
            "failed_connections": 0,
            "dns_requests": rng.randint(0, 5),
            "unique_dns_queries": rng.randint(0, 4),
            "auth_failures": 0,
            "bytes_total": int(megabytes * 1_000_000),
            "packets_total": int(megabytes * rng.randint(200, 900)),
        }
        label = 1
    else:  # normal traffic
        if rng.random() < 0.4:
            # New or idle hosts produce sparse windows; the model must learn
            # that this is normal, otherwise every entity's first events are
            # flagged anomalous until its window fills up (cold-start noise).
            connections = max(1, int(rng.gauss(4, 2)))
            values = {
                "connection_count": connections,
                "unique_destination_ports": max(1, int(rng.gauss(2, 1))),
                "unique_destination_ips": max(1, int(rng.gauss(2, 1))),
                "failed_connections": 0,
                "dns_requests": max(0, int(rng.gauss(3, 3))),
                "unique_dns_queries": max(0, int(rng.gauss(2, 2))),
                "auth_failures": 0,
                "bytes_total": max(500, int(rng.gauss(60_000, 40_000))),
                "packets_total": max(5, int(rng.gauss(80, 40))),
            }
        else:
            connections = max(1, int(rng.gauss(12, 6)))
            values = {
                "connection_count": connections,
                "unique_destination_ports": max(1, int(rng.gauss(4, 2))),
                "unique_destination_ips": max(1, int(rng.gauss(3, 2))),
                "failed_connections": max(0, int(rng.gauss(0.6, 0.8))),
                "dns_requests": max(0, int(rng.gauss(15, 8))),
                "unique_dns_queries": max(0, int(rng.gauss(10, 5))),
                "auth_failures": 0,
                "bytes_total": max(500, int(rng.gauss(250_000, 120_000))),
                "packets_total": max(5, int(rng.gauss(300, 120))),
            }
        label = 0

    window = 300.0
    values.setdefault("bytes_per_second", round(values["bytes_total"] / window, 3))
    values.setdefault("packets_per_second", round(values["packets_total"] / window, 3))
    values.setdefault(
        "avg_connection_duration_ms",
        round(rng.uniform(20, 900), 3) if scenario == "normal" else round(rng.uniform(0, 60), 3),
    )
    values.setdefault("unique_protocols", rng.randint(1, 3) if scenario == "normal" else 1)
    values.setdefault("events_per_minute", round(values["connection_count"] * 60.0 / window, 3))
    return LabelledSample(features=values, label=label, scenario=scenario)


#: Attack scenarios used to build the labelled evaluation set.
ATTACK_SCENARIOS = ("port_scan", "brute_force", "connection_flood", "dns_anomaly", "volume_anomaly")


def build_synthetic_dataset(
    *,
    normal_samples: int = 1200,
    attack_samples_per_scenario: int = 120,
    seed: int = 20260818,
) -> list[LabelledSample]:
    """Build a labelled dataset with realistic class imbalance (mostly normal)."""
    rng = random.Random(seed)
    samples = [synthetic_sample("normal", rng) for _ in range(normal_samples)]
    for scenario in ATTACK_SCENARIOS:
        samples.extend(synthetic_sample(scenario, rng) for _ in range(attack_samples_per_scenario))
    rng.shuffle(samples)
    return samples


def samples_to_matrix(samples: Iterable[LabelledSample]):
    """Split samples into an (X, y, scenarios) tuple of plain Python objects."""
    import numpy as np

    rows: list[list[float]] = []
    labels: list[int] = []
    scenarios: list[str] = []
    for sample in samples:
        rows.append(sample.as_row())
        labels.append(int(sample.label))
        scenarios.append(sample.scenario)
    return (
        np.asarray(rows, dtype=float),
        np.asarray(labels, dtype=int),
        np.asarray(scenarios, dtype=object),
    )


def checking_window_bounds() -> tuple[time, time]:
    """Business-hours window used by the backend feature extractor."""
    return (time(8, 0), time(19, 0))


__all__ = [
    "ATTACK_SCENARIOS",
    "FEATURE_ORDER",
    "LABELS",
    "LabelledSample",
    "build_synthetic_dataset",
    "checking_window_bounds",
    "samples_to_matrix",
    "synthetic_sample",
]
