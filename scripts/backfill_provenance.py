#!/usr/bin/env python
"""Backfill alert provenance from the event that raised each alert.

Alerts store the collector and interface that produced them in their evidence
blob. Alerts raised before that was recorded (or restored from an older
database) can still be traced: every alert keeps ``evidence.first_event_id``,
and the event row carries ``collector`` and ``interface``.

The script is idempotent - alerts that already know their source are skipped.

Usage (from the repository root):

    .venv\\Scripts\\python.exe scripts\\backfill_provenance.py
    .venv\\Scripts\\python.exe scripts\\backfill_provenance.py --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.database.connection import session_scope  # noqa: E402
from app.database.models import Alert, Event  # noqa: E402
from app.provenance import normalize_collector  # noqa: E402


def backfill(dry_run: bool = False) -> dict[str, int]:
    """Copy collector/interface from each alert's first event into its evidence."""
    stats = {"alerts": 0, "already": 0, "updated": 0, "unresolved": 0}
    with session_scope() as session:
        alerts = session.query(Alert).all()
        stats["alerts"] = len(alerts)
        caches: dict[str, tuple[str | None, str | None] | None] = {}
        for alert in alerts:
            evidence = dict(alert.evidence or {})
            if evidence.get("collector"):
                stats["already"] += 1
                continue
            event_id = evidence.get("first_event_id")
            if not event_id:
                stats["unresolved"] += 1
                continue
            if event_id not in caches:
                event = session.query(Event).filter(Event.event_id == event_id).one_or_none()
                caches[event_id] = (
                    (event.collector, event.interface) if event is not None else None
                )
            resolved = caches[event_id]
            if resolved is None:
                stats["unresolved"] += 1
                continue
            collector, interface = resolved
            name = normalize_collector(collector)
            evidence["collector"] = name
            evidence["interface"] = interface
            evidence["collectors"] = [name] if name else []
            evidence["interfaces"] = [interface] if interface else []
            if not dry_run:
                alert.evidence = evidence
            stats["updated"] += 1
        if dry_run:
            session.rollback()
        else:
            session.commit()
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    args = parser.parse_args()

    stats = backfill(dry_run=args.dry_run)
    prefix = "would update" if args.dry_run else "updated"
    print(
        f"alerts={stats['alerts']} {prefix}={stats['updated']} "
        f"already_tagged={stats['already']} unresolved={stats['unresolved']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
