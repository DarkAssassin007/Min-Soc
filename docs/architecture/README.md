# Mini SOC — Architecture

Mini SOC is a real-time network security monitoring platform. Events flow from
collection to the dashboard through one deterministic pipeline; every stage is
observable through metrics and covered by tests.

## 1. Component map

```text
mini-soc/
├── backend/
│   └── app/
│       ├── api/             FastAPI app: REST routes, WebSocket routes, deps
│       ├── alerts/          alert manager + incident manager
│       ├── collectors/      packet (scapy), syslog (UDP), system (psutil)
│       ├── config/          settings, paths, logging
│       ├── database/        engine, models, repository, id sequences
│       ├── detection/
│       │   ├── rules/       YAML rule packs -> registry -> built-in rules
│       │   ├── anomaly/     model registry, detector, baseline bootstrap
│       │   └── correlation/ correlator (alerts -> incidents)
│       ├── processors/      parser, validator, normalizer, dedupe, features
│       ├── risk/            risk scoring + classification
│       ├── security/        JWT, passwords, RBAC, rate limiting, audit
│       └── services/        runtime bootstrap, pipeline, metrics, simulator, audit
├── frontend/                React 18 + Vite SOC dashboard (9 pages)
├── ml/                      training pipeline (dataset, features, evaluate, train)
├── detection-rules/         editable YAML rule packs
├── scripts/                 setup/run/test/benchmark/validation helpers
├── collectors/ database/ tests/   layout anchors (see their READMEs)
└── docs/                    this documentation set
```

## 2. Data flow

```text
collectors (packet | syslog | system | simulator)
        │ RawRecord
        ▼
bounded queue (back-pressure: counted drops, never a stalled collector)
        ▼
pipeline workers ── one transaction per batch ──────────────────────────────┐
   parse ─► validate ─► normalise ─► dedupe ─► Event + NetworkEvent rows    │
        │                                                                   │
        ├─ batched ML scoring (one model call per batch)                    │
        ├─ rule evaluation (7 built-in rules + YAML packs)                  │
        ├─ risk scoring (components, boosts, severity bands, classification)│
        └─ alerts (+ dedupe) ─► incident correlation ───────────────────────┘
        │ commit
        ▼
WebSocket broadcast (/ws/live, /ws/alerts, /ws/network) + metrics
        ▼
React dashboard (live feed, alerts, incidents, network, threats, analytics,
                investigation, reports)
```

## 3. Runtime composition

`app.services.bootstrap.build_runtime()` is the only place that wires the
object graph: settings → paths → database init → rule sync → model registry →
detector → detection engine → risk engine → alert/incident managers →
correlator → pipeline. The API, the tests, the benchmark and the validation
script all exercise the exact same runtime.

## 4. Threading and the single-writer design

* Collector threads only push into a **bounded `queue.Queue`**. When the queue
  is full the record is dropped and counted (`stats.dropped`) — a burst degrades
  by dropping, not by freezing the collector.
* **Worker threads** gather batches (up to `db_write_batch_size`, bounded by a
  50 ms window) and commit once per batch. Each record gets its own savepoint,
  so one malformed record rolls back only its own work.
* SQLite is a single-writer engine. `write_lock` serialises our batches (and the
  maintenance writer) on SQLite so parallel workers can never deadlock on a
  read-to-write upgrade. On PostgreSQL the lock is skipped and workers run fully
  in parallel.
* Long-lived services (alert manager, incident manager, correlator, rule
  registry) receive a `RepositoryProxy` whose session is bound per batch — no
  service ever holds a stale session.

### Batch ML scoring

scikit-learn dispatches one parallel job per scoring call, costing several
milliseconds **per call regardless of batch size**. Scoring each event
individually capped the pipeline at ~27 events/s with ML enabled. The pipeline
now preprocesses a whole batch, scores every feature vector with a single
`score_samples` call, and only then evaluates rules/risk/alerts per record.
Measured effect (2 workers, 4 000 events, ML enabled): detection stage mean
latency 26.8 ms → **0.21 ms** per event, end-to-end throughput 26.8 → **~210
events/s**, CPU cost 4.4 ms per event.

## 5. Detection

* **Rules** are declared in `detection-rules/*.yaml`, loaded into the database
  by the rule registry (so thresholds are editable through the API) and
  re-synced at startup and on a schedule. Seven built-in rule types:
  port scan, brute force, connection flood, repeated failed connections, DNS
  anomaly, volume anomaly, suspicious protocol.
* **ML** is an Isolation Forest trained by the separate `ml/` pipeline. The
  backend only loads versioned artifacts from the model registry and never
  trains at request time (a bundled baseline is bootstrapped if no artifact
  exists). Inference returns a score, threshold decision, confidence and
  measured latency; results are stored in `model_predictions`.
* **Risk** combines rule scores, anomaly contribution, asset importance,
  event severity and behaviour boosts into a 0–100 score with configurable
  severity bands and an impact classification.

## 6. Alerts, incidents and correlation

The alert manager creates an alert for a triggered detection above the minimum
risk score and deduplicates repeats of the same detection type + entities
inside the dedupe window (updating `last_seen`, `event_count`, evidence samples
and score instead of flooding the analyst). The correlator attaches an alert to
an open incident for the same entity, or opens a new incident when the alert is
HIGH/CRITICAL or when one source produced `min_alerts` alerts with
`min_detection_types` distinct types inside the correlation window.

## 7. API and security

* JWT access tokens (HS256) + rotating refresh tokens; password hashing with
  bcrypt; role model ADMIN / ANALYST / VIEWER enforced per route.
* Login and API rate limiting, request-id correlation, secure response
  headers, CORS and trusted-host allow-lists, audit log for privileged actions.
* WebSocket channels authenticate the token on connect and are capped by
  `ws_max_connections`.

## 8. Observability

`/api/v1/system/metrics` exposes live per-stage latency (processing, detection,
alert, database, WebSocket), events/s, queue depth, drop/reject/duplicate
counts, CPU and RSS; a snapshot is persisted every 15 s for trend charts.
`/api/v1/system/health` and `/ready` are used by the container health check.

## 9. Extension points

| I want to… | do this |
|------------|---------|
| add a detection rule | add YAML to `detection-rules/` (see its README) — it is synced on startup |
| add a collector | implement the collector protocol under `backend/app/collectors/` and register it in `build_collectors()` |
| change the database | set `MINI_SOC_DATABASE_URL` to PostgreSQL; no code changes (write lock is skipped automatically) |
| retrain the ML model | run `python -m ml.train --baseline --report logs/training-report.json` (see docs/ml) |
| tune buffers | `MINI_SOC_PIPELINE_QUEUE_SIZE`, `MINI_SOC_DB_WRITE_BATCH_SIZE`, `MINI_SOC_PIPELINE_WORKERS` |
