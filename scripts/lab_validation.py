#!/usr/bin/env python
"""End-to-end lab validation for Mini SOC (spec phase 10, section 32).

Runs a controlled security-event simulation through the *real* runtime - the
same object graph the API uses - and validates that the full chain works:

    collect -> normalize -> detect -> score -> alert -> persist

Scenarios (all synthetic, no real network traffic):

* port scan from one source across 120 destination ports,
* credential attack: repeated authentication failures,
* DNS tunnelling-style queries (long, randomised names),
* bulk transfer from one source (volume anomaly),
* benign web/mail/DNS traffic that must NOT raise alerts (false-positive check).

The script writes an evidence report to ``logs/validation-report.json`` and
exits non-zero if any expectation fails, so CI or an operator can run it as a
gate before deployment.

Usage (from the repository root):

    .venv\\Scripts\\python.exe scripts\\lab_validation.py
    python scripts/lab_validation.py --json logs/validation-report.json
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config.settings import Settings  # noqa: E402
from app.processors.models import RawRecord  # noqa: E402


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class Scenario:
    """One controlled attack/benign simulation."""

    key: str
    description: str
    sources: list[str]
    expected_detections: set[str] = field(default_factory=set)
    benign: bool = False
    records: list[RawRecord] = field(default_factory=list)


def _record(*, event_type: str, source_ip: str, payload: dict) -> RawRecord:
    payload = {"source_ip": source_ip, "timestamp": _utcnow(), **payload}
    return RawRecord(
        collector="synthetic",
        received_at=_utcnow(),
        event_type=event_type,
        payload=payload,
    )


def build_scenarios(seed: int = 2026) -> list[Scenario]:
    rng = random.Random(seed)

    port_scan = Scenario(
        key="port_scan",
        description="120 TCP SYNs across unique ports from one source",
        sources=["10.77.1.10"],
        expected_detections={"PORT_SCAN"},
    )
    for port in range(1, 121):
        port_scan.records.append(
            _record(
                event_type="NETWORK_CONNECTION",
                source_ip="10.77.1.10",
                payload={
                    "destination_ip": "10.77.1.1",
                    "source_port": 40000 + port,
                    "destination_port": port,
                    "protocol": "TCP",
                    "bytes": 54,
                    "packet_count": 1,
                    "connection_state": "SYN_SENT",
                },
            )
        )

    brute_force = Scenario(
        key="brute_force",
        description="25 failed SSH authentications from one source",
        sources=["10.77.2.10"],
        expected_detections={"BRUTE_FORCE"},
    )
    for index in range(25):
        brute_force.records.append(
            _record(
                event_type="AUTH_FAILURE",
                source_ip="10.77.2.10",
                payload={
                    "destination_ip": "10.77.2.20",
                    "source_port": 41000 + index,
                    "destination_port": 22,
                    "protocol": "TCP",
                    "bytes": 180,
                    "packet_count": 8,
                    "connection_state": "FAILED",
                    "message": f"Failed password for invalid user admin from 10.77.2.10 port {41000 + index} ssh2",
                },
            )
        )

    dns = Scenario(
        key="dns_tunnelling",
        description="5 DNS queries with 70-character random labels",
        sources=["10.77.3.10"],
        expected_detections={"DNS_ANOMALY"},
    )
    for index in range(5):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(70))
        dns.records.append(
            _record(
                event_type="DNS_QUERY",
                source_ip="10.77.3.10",
                payload={
                    "destination_ip": "10.77.3.53",
                    "source_port": 42000 + index,
                    "destination_port": 53,
                    "protocol": "UDP",
                    "bytes": 120,
                    "packet_count": 1,
                    "connection_state": "ESTABLISHED",
                    "dns_query": f"{label}.exfil.example.com",
                },
            )
        )

    volume = Scenario(
        key="volume_anomaly",
        description="8 x 8 MB transfers from one source (64 MB total)",
        sources=["10.77.4.10"],
        expected_detections={"VOLUME_ANOMALY"},
    )
    for index in range(8):
        volume.records.append(
            _record(
                event_type="NETWORK_CONNECTION",
                source_ip="10.77.4.10",
                payload={
                    "destination_ip": "203.0.113.77",
                    "source_port": 43000 + index,
                    "destination_port": 443,
                    "protocol": "TCP",
                    "bytes": 8 * 1024 * 1024,
                    "packet_count": 5600,
                    "connection_state": "ESTABLISHED",
                },
            )
        )

    # 30 hosts x 8 connections ~= the baseline dataset's normal profile
    # (about 12 connections and a few hundred KB per host per 5-minute window),
    # so the model can be checked for false positives instead of being fed a
    # synthetic flood and (correctly) flagging it.
    benign = Scenario(
        key="benign_traffic",
        description="240 normal records across 30 hosts (false-positive check)",
        sources=[f"10.77.9.{index}" for index in range(1, 31)],
        benign=True,
    )
    for index in range(240):
        source = benign.sources[index % len(benign.sources)]
        benign.records.append(
            _record(
                event_type="NETWORK_CONNECTION",
                source_ip=source,
                payload={
                    "destination_ip": f"93.184.{rng.randrange(0, 50)}.{rng.randrange(1, 250)}",
                    "source_port": 44000 + (index % 20000),
                    "destination_port": rng.choice((80, 443, 443, 443, 587, 993)),
                    "protocol": "TCP",
                    "bytes": rng.randrange(5_000, 45_000),
                    "packet_count": rng.randrange(10, 60),
                    "connection_state": "ESTABLISHED",
                },
            )
        )

    return [port_scan, brute_force, dns, volume, benign]


def build_settings(home: Path) -> Settings:
    artifacts_src = REPO_ROOT / "ml" / "artifacts"
    artifacts_dst = home / "ml" / "artifacts"
    artifacts_dst.mkdir(parents=True, exist_ok=True)
    if artifacts_src.is_dir():
        for item in artifacts_src.iterdir():
            if item.is_file():
                shutil.copy2(item, artifacts_dst / item.name)
    return Settings(
        home=str(home),
        database_url=f"sqlite+pysqlite:///{home / 'data' / 'validation.db'}",
        env="development",
        log_level="ERROR",
        log_json=False,
        collector_network_enabled=False,
        collector_syslog_enabled=False,
        collector_system_enabled=False,
        simulator_enabled=False,
        anomaly_enabled=(artifacts_dst / "manifest.json").exists(),
    )


def drain(runtime, *, timeout: float = 60.0) -> None:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        stats = runtime.pipeline.stats.as_dict()
        handled = stats["processed"] + stats["rejected"] + stats["duplicates"]
        if handled >= stats["received"] and runtime.pipeline.queue.qsize() == 0:
            return
        time.sleep(0.05)
    raise TimeoutError("pipeline did not drain within the validation timeout")


def detection_types_by_source() -> dict[str, set[str]]:
    from sqlalchemy import select

    from app.database.connection import session_scope
    from app.database.models import Detection, Event

    result: dict[str, set[str]] = {}
    with session_scope() as session:
        rows = session.execute(
            select(Event.source_ip, Detection.detection_type).join(
                Detection, Detection.event_id == Event.event_id
            )
        ).all()
        for source_ip, detection_type in rows:
            result.setdefault(source_ip or "", set()).add(detection_type)
    return result


def alert_summary() -> list[dict]:
    from app.database.connection import session_scope
    from app.database.repository import Repository

    with session_scope() as session:
        alerts = Repository(session).list_alerts(limit=500)
        return [
            {
                "alert_id": alert.alert_id,
                "detection_type": alert.detection_type,
                "severity": alert.severity,
                "risk_score": float(alert.risk_score or 0.0),
                "source_ip": alert.source_ip,
                "engine": alert.engine,
                "status": alert.status,
                "incident_id": alert.incident_id,
            }
            for alert in alerts
        ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--json",
        type=Path,
        default=REPO_ROOT / "logs" / "validation-report.json",
        help="where to write the JSON evidence report",
    )
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()

    from app.database.connection import dispose_engine
    from app.services.bootstrap import build_runtime

    scenarios = build_scenarios(seed=args.seed)
    records = [record for scenario in scenarios for record in scenario.records]

    # NOTE: mkdtemp + best-effort cleanup instead of TemporaryDirectory: on Windows
    # SQLite keeps the database handle until the very last connection is garbage
    # collected, which makes strict cleanup spuriously fail.
    home = Path(tempfile.mkdtemp(prefix="mini-soc-validation-"))
    try:
        settings = build_settings(home)
        runtime = build_runtime(settings, start_collection=False)
        try:
            runtime.pipeline.start()
            started = time.perf_counter()
            for record in records:
                runtime.pipeline.submit(record)
            drain(runtime)
            elapsed = time.perf_counter() - started
            time.sleep(0.5)  # let the final batch commit become visible

            detections = detection_types_by_source()
            alerts = alert_summary()
            snapshot = runtime.pipeline.metrics.snapshot(queue_depth=runtime.pipeline.queue.qsize())
        finally:
            runtime.shutdown()
            # Release the SQLite file handle before the temp directory is removed.
            dispose_engine()
    finally:
        shutil.rmtree(home, ignore_errors=True)

    alerts_by_source: dict[str, list[dict]] = {}
    for alert in alerts:
        alerts_by_source.setdefault(alert["source_ip"] or "", []).append(alert)

    results = []
    for scenario in scenarios:
        observed: set[str] = set()
        scenario_alerts: list[dict] = []
        for source in scenario.sources:
            observed |= detections.get(source, set())
            scenario_alerts.extend(alerts_by_source.get(source, []))
        if scenario.benign:
            # Rule detections must be exactly zero; the ML model is allowed its
            # measured false-positive budget (training reported ~3%).
            rule_detections = observed - {"ML_ANOMALY"}
            rule_alerts = [a for a in scenario_alerts if (a.get("engine") or "RULE") != "ML"]
            ml_alerts = [a for a in scenario_alerts if (a.get("engine") or "RULE") == "ML"]
            ml_rate = len(ml_alerts) / max(len(scenario.records), 1)
            passed = not rule_detections and not rule_alerts and ml_rate <= 0.15
            results.append(
                {
                    "key": scenario.key,
                    "description": scenario.description,
                    "benign": True,
                    "rule_detections": sorted(rule_detections),
                    "ml_anomaly_alerts": len(ml_alerts),
                    "ml_false_positive_rate": round(ml_rate, 4),
                    "rule_alerts": rule_alerts,
                    "passed": passed,
                }
            )
        else:
            missing = sorted(scenario.expected_detections - observed)
            results.append(
                {
                    "key": scenario.key,
                    "description": scenario.description,
                    "expected_detections": sorted(scenario.expected_detections),
                    "observed_detections": sorted(observed),
                    "missing_detections": missing,
                    "alerts": scenario_alerts,
                    "passed": not missing,
                }
            )

    benign_events = sum(len(s.records) for s in scenarios if s.benign)
    benign_alerts = sum(
        len(r.get("rule_alerts", [])) + int(r.get("ml_anomaly_alerts", 0))
        for r in results
        if r.get("benign")
    )
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_records": len(records),
        "elapsed_seconds": round(elapsed, 3),
        "pipeline": runtime.pipeline.stats.as_dict(),
        "latency_ms": snapshot.get("latency", {}),
        "scenarios": results,
        "summary": {
            "scenarios_passed": sum(1 for r in results if r["passed"]),
            "scenarios_total": len(results),
            "attack_detections_observed": sorted(
                {d for r in results if not r.get("benign") for d in r.get("observed_detections", [])}
            ),
            "benign_events": benign_events,
            "benign_alerts": benign_alerts,
            "benign_rule_alerts": sum(
                len(r.get("rule_alerts", [])) for r in results if r.get("benign")
            ),
            "benign_ml_alerts": sum(
                int(r.get("ml_anomaly_alerts", 0)) for r in results if r.get("benign")
            ),
            "false_positive_rate": round(benign_alerts / max(benign_events, 1), 6),
        },
        "passed": all(r["passed"] for r in results),
    }

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    print("Mini SOC end-to-end lab validation")
    print("=" * 62)
    print(f"  records submitted : {report['total_records']} in {report['elapsed_seconds']:.2f}s")
    print(f"  pipeline          : {report['pipeline']}")
    for result in results:
        status = "PASS" if result["passed"] else "FAIL"
        if result.get("benign"):
            detail = (
                f"rule_detections={result['rule_detections'] or 'none'}, "
                f"rule_alerts={len(result['rule_alerts'])}, "
                f"ml_alerts={result['ml_anomaly_alerts']} "
                f"({result['ml_false_positive_rate']:.1%})"
            )
        else:
            detail = f"expected={result['expected_detections']}, observed={result['observed_detections']}"
        print(f"  [{status}] {result['key']:<18} {detail}")
    summary = report["summary"]
    print(
        f"\n  scenarios: {summary['scenarios_passed']}/{summary['scenarios_total']} passed | "
        f"benign alerts: {summary['benign_alerts']}/{summary['benign_events']} "
        f"(FPR {summary['false_positive_rate']:.2%})"
    )
    processing = report["latency_ms"].get("processing", {})
    if processing:
        print(f"  processing latency: mean {processing.get('mean_ms', 0)} ms | p95 {processing.get('p95_ms', 0)} ms")
    print(f"\nReport written to {args.json}")
    if not report["passed"]:
        print("VALIDATION FAILED")
        return 1
    print("VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
