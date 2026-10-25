"""Provenance: where a record actually came from.

Every event and alert carries the collector that produced it and, when the
source has one, the interface or endpoint it arrived on. Collectors listed in
:data:`LAB_COLLECTORS` are the authorized-lab generator, so anything they
produce is marked ``LAB`` and can never be mistaken for observed traffic.

This module intentionally has no imports from the rest of the application: both
the persistence models and the API use it to describe the same field set.
"""

from __future__ import annotations

from typing import Any, Iterable

#: Origin values surfaced to the dashboard.
ORIGIN_LIVE = "LIVE"
ORIGIN_LAB = "LAB"
ORIGIN_UNKNOWN = "UNKNOWN"

#: Collectors that fabricate traffic instead of observing it.
LAB_COLLECTORS = frozenset({"synthetic"})

#: Human readable description of each collector.
COLLECTOR_LABELS = {
    "packet": "live packet capture",
    "syslog": "syslog / firewall feed",
    "system": "host telemetry",
    "api": "API ingestion",
    "synthetic": "lab generator",
}


def normalize_collector(collector: str | None) -> str | None:
    """Lower-case a collector name, treating blanks as unknown."""
    value = str(collector or "").strip().lower()
    return value or None


def origin_for(collector: str | None) -> str:
    """``LAB`` for generated test traffic, ``LIVE`` for everything observed."""
    name = normalize_collector(collector)
    if name is None:
        return ORIGIN_UNKNOWN
    return ORIGIN_LAB if name in LAB_COLLECTORS else ORIGIN_LIVE


def is_lab(collector: str | None) -> bool:
    """Whether this collector fabricates data."""
    return normalize_collector(collector) in LAB_COLLECTORS


def label_for(collector: str | None) -> str:
    """Readable name of the collector, used in tooltips."""
    name = normalize_collector(collector)
    if name is None:
        return "unknown source"
    return COLLECTOR_LABELS.get(name, name)


def _unique_collectors(values: Iterable[str | None]) -> list[str]:
    cleaned = [normalize_collector(value) for value in values]
    return [value for value in dict.fromkeys(cleaned) if value]


def _unique_interfaces(values: Iterable[str | None]) -> list[str]:
    cleaned = [("" if value is None else str(value).strip()) or None for value in values]
    return [value for value in dict.fromkeys(cleaned) if value]


def provenance(
    collector: str | None,
    interface: str | None = None,
    *,
    collectors: Iterable[str | None] | None = None,
    interfaces: Iterable[str | None] | None = None,
) -> dict[str, Any]:
    """Describe the source of one record or one aggregated alert.

    Aggregated records (an alert that keeps absorbing matching events) report the
    first collector/interface as the primary source and every feed they have
    seen so far in ``collectors``/``interfaces``.
    """
    primary = normalize_collector(collector)
    feeds = _unique_collectors(collectors if collectors is not None else [primary])
    hops = _unique_interfaces(interfaces if interfaces is not None else [interface])
    lab = any(name in LAB_COLLECTORS for name in feeds) or primary in LAB_COLLECTORS
    if primary is None and feeds:
        primary = feeds[0]
    return {
        "collector": primary,
        "collectors": feeds,
        "interface": hops[0] if hops else None,
        "interfaces": hops,
        "origin": ORIGIN_LAB if lab else origin_for(primary),
        "label": label_for(primary),
        "lab": lab,
    }


__all__ = [
    "COLLECTOR_LABELS",
    "LAB_COLLECTORS",
    "ORIGIN_LAB",
    "ORIGIN_LIVE",
    "ORIGIN_UNKNOWN",
    "is_lab",
    "label_for",
    "normalize_collector",
    "origin_for",
    "provenance",
]
