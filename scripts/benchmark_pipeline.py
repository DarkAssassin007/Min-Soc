#!/usr/bin/env python
"""Synthetic throughput benchmark for the Mini SOC processing pipeline.

This is the phase 9 evidence generator: it feeds a deterministic, realistic mix
of synthetic records through the *real* runtime (collectors -> processors ->
detection -> risk -> alerts -> SQLite) and measures what actually happened:

* offered / accepted events per second,
* processing, detection, alert and database latencies (mean / p50 / p95 / max),
* CPU seconds spent and resident memory before/after,
* rejection, duplicate and back-pressure (drop) counts,
* alerts, incidents and persisted rows.

The benchmark uses an isolated temporary home directory, so it never touches the
operator's real database, logs or artifacts.  A copy of the deployed ML artifact
(``ml/artifacts``) is placed in that temporary home so anomaly detection is
exercised exactly as in production; if no artifact exists the benchmark runs
with ML disabled and reports that.

Usage (from the repository root):

    .venv\\Scripts\\python.exe scripts\\benchmark_pipeline.py --events 4000
    .venv\\Scripts\\python.exe scripts\\benchmark_pipeline.py --events 20000 --workers 4
    python scripts/benchmark_pipeline.py --events 10000 --json logs/benchmark-report.json
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config.settings import Settings  # noqa: E402
from app.processors.models import RawRecord  # noqa: E402

#: Scenario weights (must sum to 100) - see :func:`build_records`.
_WEIGHTS = {
    "browsing": 55,
    "failed_connections": 10,
    "port_scan": 10,
    "auth_failures": 10,
    "dns": 10,
    "bulk_transfer": 5,
}

_NORMAL_PORTS = (80, 443, 443, 443, 8080, 8443, 123, 993, 587)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _scenario_for(index: int, rng: random.Random) -> str:
    """Stable weighted scenario selection."""
    roll = rng.randrange(100)
    cumulative = 0
    for name, weight in _WEIGHTS.items():
        cumulative += weight
        if roll < cumulative:
            return name
    return "browsing"


def build_records(count: int, *, seed: int = 1337) -> list[RawRecord]:
    """Build ``count`` synthetic records covering normal and attack traffic."""
    rng = random.Random(seed)
    records: list[RawRecord] = []
    for index in range(count):
        scenario = _scenario_for(index, rng)
        timestamp = _utcnow()
        source_port = 1024 + rng.randrange(64500)
        if scenario == "browsing":
            payload = {
                "source_ip": f"192.168.{1 + rng.randrange(0, 60)}.{1 + rng.randrange(0, 250)}",
                "destination_ip": f"{rng.choice((93, 151, 104, 172))}.{rng.randrange(0, 250)}.{rng.randrange(0, 250)}.{rng.randrange(1, 250)}",
                "source_port": source_port,
                "destination_port": rng.choice(_NORMAL_PORTS),
                "protocol": "TCP",
                "bytes": rng.randrange(300, 40_000),
                "packet_count": rng.randrange(3, 60),
                "connection_state": "ESTABLISHED",
                "timestamp": timestamp,
            }
            event_type = "NETWORK_CONNECTION"
        elif scenario == "failed_connections":
            payload = {
                "source_ip": f"10.90.{rng.randrange(1, 4)}.{rng.randrange(1, 40)}",
                "destination_ip": "10.90.0.10",
                "source_port": source_port,
                "destination_port": rng.choice((22, 445, 3389, 21)),
                "protocol": "TCP",
                "bytes": rng.randrange(40, 400),
                "packet_count": rng.randrange(1, 5),
                "connection_state": "FAILED",
                "timestamp": timestamp,
            }
            event_type = "NETWORK_CONNECTION"
        elif scenario == "port_scan":
            payload = {
                "source_ip": f"10.70.{rng.randrange(1, 4)}.{rng.randrange(1, 40)}",
                "destination_ip": "10.70.0.10",
                "source_port": source_port,
                "destination_port": 1 + rng.randrange(65534),
                "protocol": "TCP",
                "bytes": rng.randrange(40, 80),
                "packet_count": 1,
                "connection_state": "SYN_SENT",
                "timestamp": timestamp,
            }
            event_type = "NETWORK_CONNECTION"
        elif scenario == "auth_failures":
            host = f"10.60.{rng.randrange(1, 3)}.50"
            payload = {
                "source_ip": host,
                "destination_ip": "10.60.0.20",
                "source_port": source_port,
                "destination_port": 22,
                "protocol": "TCP",
                "bytes": rng.randrange(100, 300),
                "packet_count": rng.randrange(4, 12),
                "connection_state": "FAILED",
                "timestamp": timestamp,
                # Unique per record so the deduplicator does not fold the burst.
                "message": f"Failed password for invalid user admin from {host} port {source_port} ssh2",
            }
            event_type = "AUTH_FAILURE"
        elif scenario == "dns":
            label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(70))
            payload = {
                "source_ip": f"10.50.{rng.randrange(1, 4)}.{rng.randrange(1, 60)}",
                "destination_ip": "10.50.0.53",
                "source_port": source_port,
                "destination_port": 53,
                "protocol": "UDP",
                "bytes": rng.randrange(60, 300),
                "packet_count": rng.randrange(1, 3),
                "connection_state": "ESTABLISHED",
                "timestamp": timestamp,
                "dns_query": f"{label}.tunnel.example.com",
            }
            event_type = "DNS_QUERY"
        else:  # bulk_transfer
            payload = {
                "source_ip": f"10.40.{rng.randrange(1, 3)}.{rng.randrange(1, 30)}",
                "destination_ip": "203.0.113.10",
                "source_port": source_port,
                "destination_port": 443,
                "protocol": "TCP",
                "bytes": rng.randrange(4_000_000, 12_000_000),
                "packet_count": rng.randrange(3_000, 9_000),
                "connection_state": "ESTABLISHED",
                "timestamp": timestamp,
            }
            event_type = "NETWORK_CONNECTION"
        records.append(
            RawRecord(
                collector="synthetic",
                received_at=_utcnow(),
                event_type=event_type,
                payload=payload,
            )
        )
    return records


def build_settings(home: Path, *, workers: int, queue_size: int) -> Settings:
    """Isolated settings with the deployed ML artifact copied in when present."""
    artifacts_src = REPO_ROOT / "ml" / "artifacts"
    artifacts_dst = home / "ml" / "artifacts"
    artifacts_dst.mkdir(parents=True, exist_ok=True)
    if artifacts_src.is_dir():
        for item in artifacts_src.iterdir():
            if item.is_file():
                shutil.copy2(item, artifacts_dst / item.name)
    has_artifact = (artifacts_dst / "manifest.json").exists()
    return Settings(
        home=str(home),
        database_url=f"sqlite+pysqlite:///{home / 'data' / 'bench.db'}",
        env="development",
        log_level="ERROR",
        log_json=False,
        collector_network_enabled=False,
        collector_syslog_enabled=False,
        collector_system_enabled=False,
        simulator_enabled=False,
        anomaly_enabled=has_artifact,
        pipeline_workers=workers,
        pipeline_queue_size=queue_size,
    )


def drain_deadline(runtime, *, timeout: float) -> tuple[float, dict]:
    """Wait until every submitted record has been handled or the timeout hits."""
    started = time.perf_counter()
    while time.perf_counter() - started < timeout:
        stats = runtime.pipeline.stats.as_dict()
        handled = stats["processed"] + stats["rejected"] + stats["duplicates"]
        if handled >= stats["received"] and runtime.pipeline.queue.qsize() == 0:
            return time.perf_counter() - started, stats
        time.sleep(0.05)
    return time.perf_counter() - started, runtime.pipeline.stats.as_dict()


def database_counts() -> dict[str, int]:
    from sqlalchemy import func, select

    from app.database.connection import session_scope
    from app.database.models import Alert, Detection, Event, Incident, ModelPrediction

    counts: dict[str, int] = {}
    with session_scope() as session:
        for name, model in (
            ("events", Event),
            ("detections", Detection),
            ("alerts", Alert),
            ("incidents", Incident),
            ("model_predictions", ModelPrediction),
        ):
            counts[name] = int(session.scalar(select(func.count()).select_from(model)) or 0)
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--events", type=int, default=4000, help="records to offer (default 4000)")
    parser.add_argument("--workers", type=int, default=None, help="pipeline worker threads (default: settings)")
    parser.add_argument("--queue-size", type=int, default=None, help="pipeline queue capacity (default: settings)")
    parser.add_argument("--timeout", type=float, default=180.0, help="drain timeout seconds (default 180)")
    parser.add_argument(
        "--json",
        type=Path,
        default=REPO_ROOT / "logs" / "benchmark-report.json",
        help="where to write the JSON report",
    )
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    if args.events < 1:
        parser.error("--events must be >= 1")

    defaults = Settings()
    workers = args.workers if args.workers is not None else defaults.pipeline_workers
    queue_size = args.queue_size if args.queue_size is not None else defaults.pipeline_queue_size

    from app.database.connection import dispose_engine
    from app.services.bootstrap import build_runtime

    # NOTE: mkdtemp + best-effort cleanup instead of TemporaryDirectory: on Windows
    # SQLite keeps the database handle until the very last connection is garbage
    # collected, which makes strict cleanup spuriously fail.
    home = Path(tempfile.mkdtemp(prefix="mini-soc-bench-"))
    lingering: list[str] = []
    try:
        settings = build_settings(home, workers=workers, queue_size=queue_size)
        runtime = build_runtime(settings, start_collection=False)
        records = build_records(args.events, seed=args.seed)

        import psutil

        process = psutil.Process()
        process.cpu_percent(interval=None)
        rss_start_mb = process.memory_info().rss / (1024 * 1024)
        cpu_start = sum(process.cpu_times()[:2])

        try:
            runtime.pipeline.start()
            feed_started = time.perf_counter()
            for record in records:
                runtime.pipeline.submit(record)
            feed_finished = time.perf_counter()
            drain_seconds, stats = drain_deadline(runtime, timeout=args.timeout)
            finished = time.perf_counter()

            cpu_seconds = sum(process.cpu_times()[:2]) - cpu_start
            rss_end_mb = process.memory_info().rss / (1024 * 1024)
            snapshot = runtime.pipeline.metrics.snapshot(queue_depth=runtime.pipeline.queue.qsize())
            accepted = int(stats["processed"])
            offered_seconds = max(feed_finished - feed_started, 1e-6)
            active_seconds = max(finished - feed_started, 1e-6)
            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "config": {
                    "events_offered": args.events,
                    "workers": workers,
                    "queue_size": queue_size,
                    "ml_enabled": bool(settings.anomaly_enabled),
                    "seed": args.seed,
                },
                "throughput": {
                    "offered_per_second": round(args.events / offered_seconds, 1),
                    "handled_per_second": round((accepted + stats["rejected"] + stats["duplicates"]) / active_seconds, 1),
                    "accepted_per_second": round(accepted / active_seconds, 1),
                    "feed_seconds": round(offered_seconds, 3),
                    "active_seconds": round(active_seconds, 3),
                    "drain_seconds": round(drain_seconds, 3),
                },
                "pipeline": {
                    "received": stats["received"],
                    "processed": accepted,
                    "rejected": stats["rejected"],
                    "duplicates": stats["duplicates"],
                    "dropped": stats["dropped"],
                    "batches": stats["batches"],
                    "errors": stats["errors"],
                    "last_error": stats["last_error"],
                },
                "alerts": {
                    "alerts_created": snapshot.get("alerts_created", 0),
                    "alerts_updated": snapshot.get("alerts_updated", 0),
                    "alerts_correlated": snapshot.get("alerts_correlated", 0),
                    "broadcasts": snapshot.get("broadcasts", 0),
                },
                "latency_ms": snapshot.get("latency", {}),
                "resources": {
                    "cpu_seconds_total": round(cpu_seconds, 3),
                    "cpu_seconds_per_event": round(cpu_seconds / max(accepted, 1), 6),
                    "cpu_percent_observed": snapshot.get("cpu_percent"),
                    "rss_start_mb": round(rss_start_mb, 2),
                    "rss_end_mb": round(rss_end_mb, 2),
                    "rss_delta_mb": round(rss_end_mb - rss_start_mb, 2),
                },
                "database_rows": database_counts(),
            }
        finally:
            runtime.shutdown()
            # Release the SQLite file handle before the temp directory is removed.
            dispose_engine()
            lingering = [t.name for t in threading.enumerate() if t is not threading.main_thread()]
    finally:
        shutil.rmtree(home, ignore_errors=True)

    report["resources"]["lingering_threads"] = lingering

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    print("Mini SOC pipeline benchmark")
    print("=" * 52)
    print(f"  offered events        : {report['config']['events_offered']}")
    print(f"  workers / queue       : {report['config']['workers']} / {report['config']['queue_size']}")
    print(f"  ML detection          : {'enabled' if report['config']['ml_enabled'] else 'disabled (no artifact)'}")
    print(f"  accepted throughput   : {report['throughput']['accepted_per_second']:,.1f} events/s")
    print(f"  handled throughput    : {report['throughput']['handled_per_second']:,.1f} events/s")
    print(f"  rejected / duplicates : {report['pipeline']['rejected']} / {report['pipeline']['duplicates']}")
    print(f"  dropped (backpressure): {report['pipeline']['dropped']}")
    latency = report["latency_ms"]
    for stage in ("processing", "detection", "alert", "database"):
        summary = latency.get(stage, {})
        print(
            f"  {stage:<10} latency   : mean {summary.get('mean_ms', 0):.2f} ms | "
            f"p95 {summary.get('p95_ms', 0):.2f} ms | max {summary.get('max_ms', 0):.2f} ms"
        )
    print(
        f"  CPU / memory          : {report['resources']['cpu_seconds_total']:.2f} CPU-s "
        f"({report['resources']['cpu_seconds_per_event'] * 1000:.3f} ms/event), "
        f"RSS {report['resources']['rss_start_mb']:.1f} -> {report['resources']['rss_end_mb']:.1f} MB"
    )
    print(
        f"  alerts                : {report['alerts']['alerts_created']} created, "
        f"{report['alerts']['alerts_updated']} updated, "
        f"{report['alerts']['alerts_correlated']} correlated into incidents"
    )
    print(f"  database rows         : {report['database_rows']}")
    print(f"\nReport written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
