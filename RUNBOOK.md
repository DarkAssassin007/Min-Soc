# Mini SOC — Runbook

Everything needed to install, run, operate and deploy Mini SOC on a single
Windows machine or as a container stack. For architecture, API, database and ML
details see the [docs](docs/).

---

## 0. One-click start

Double-click **[run_mini_soc.bat](run_mini_soc.bat)** in the project root (or run
`run_mini_soc.bat` from a terminal).

It does, in order:

1. checks that `python` and `npm` are on `PATH`;
2. runs `scripts\setup.bat` **only** on the first run (creates `.venv`, installs
   Python + ML + dashboard dependencies, copies `.env.example` → `.env`);
3. warns if ports 8000/5173 are already in use;
4. opens the **backend** and **dashboard** in two separate windows and prints
   the URLs.

| service | URL |
|---------|-----|
| SOC dashboard | http://127.0.0.1:5173 |
| REST API docs (Swagger) | http://127.0.0.1:8000/docs |
| Liveness probe | http://127.0.0.1:8000/api/v1/system/health |

Closing the two windows (or `Ctrl+C` inside them) stops the platform. Nothing
else is left running: no service, no scheduled task, no background daemon.

---

## 1. Total working procedure

### Step 1 — Install prerequisites (once)

| requirement | why | check |
|-------------|-----|-------|
| Python 3.11+ (3.14 verified) | backend + ML | `python --version` |
| Node.js 18+ | dashboard build/dev server | `node --version` |
| Npcap (Windows) | **only** for live packet capture | installs into `C:\Windows\System32\Npcap` |

Live capture is optional: without Npcap the platform still collects syslog,
host telemetry and API-ingested events.

Mini SOC is **real-time only**: the dashboard renders exactly what the live
collectors produced. The lab generator is off unless you deliberately set
`MINI_SOC_SIMULATOR_ENABLED=true` on an isolated host, and even then the
`POST /system/simulator` endpoint refuses to start it while the flag is false.

### Step 2 — First-run setup

`run_mini_soc.bat` handles it, or run it explicitly:

```bat
scripts\setup.bat
```

Creates `.venv`, installs `backend/requirements.txt`,
`backend/requirements-dev.txt`, `ml/requirements.txt`, copies `.env.example`
to `.env`, and runs `npm install` in `frontend/`.

### Step 3 — Configure `.env`

Open `.env` in the project root. The defaults run a local development SOC as-is.
Set at minimum, before any real use:

```ini
MINI_SOC_ADMIN_PASSWORD=ChangeMe-Str0ng-Passphrase     # first-run bootstrap
MINI_SOC_JWT_SECRET=<64+ random chars>                 # required when ENV=production
MINI_SOC_CORS_ORIGINS=http://127.0.0.1:5173            # lock down for production
MINI_SOC_TRUSTED_HOSTS=localhost,127.0.0.1
```

Capture-related keys worth knowing:

```ini
MINI_SOC_COLLECTOR_NETWORK_ENABLED=true    # live packet capture (needs Npcap)
MINI_SOC_COLLECTOR_INTERFACE=              # empty = first adapter with a routable IPv4
MINI_SOC_COLLECTOR_BPF_FILTER=tcp or udp or icmp or arp
MINI_SOC_COLLECTOR_SYSLOG_ENABLED=true     # UDP listener on :5514
MINI_SOC_COLLECTOR_SYSTEM_ENABLED=false    # psutil host telemetry
MINI_SOC_SIMULATOR_ENABLED=false           # real-time only; true = lab generator (isolated host)
```

If `MINI_SOC_JWT_SECRET` is empty in development, one is generated once and
persisted to `data/secrets/jwt.key`, so logins survive restarts.

### Step 4 — Start the platform

```bat
run_mini_soc.bat
```

or the individual pieces:

```bat
scripts\start_all.bat        :: backend + dashboard in separate windows
scripts\start_backend.bat    :: API only, http://127.0.0.1:8000
scripts\start_frontend.bat   :: dashboard only, http://127.0.0.1:5173
```

### Step 5 — Sign in (or create the first administrator)

**This machine already has an account** — the database at `data\mini_soc.db`
contains one user:

| field | value |
|-------|-------|
| username | `admin` |
| password | `MiniSOC-Core-2026!` |
| role | `ADMIN` |

Log in at http://127.0.0.1:5173 with those credentials. Change the password
before using the platform on a real network (`POST /api/v1/users/{id}/password`).

To start completely fresh, stop the backend, delete `data\mini_soc.db`, restart,
and use the bootstrap flow below.

The very first account is created through the one-shot bootstrap endpoint. It
works **only while no user exists** and returns `409` forever after.

- **From the dashboard (easiest):** open http://127.0.0.1:5173. Because no user
  exists yet, the login page automatically switches to *Create administrator*.
  Enter a username and a strong password — you are logged in immediately.
- **From the API:**

  ```bat
  curl -X POST http://127.0.0.1:8000/api/v1/auth/bootstrap ^
       -H "Content-Type: application/json" ^
       -d "{\"username\":\"admin\",\"password\":\"ChangeMe-Str0ng-Passphrase\"}"
  ```

  Password policy is enforced (length + variety, username not contained).

The `MINI_SOC_ADMIN_*` variables in `.env` are consumed by
`python -m app.database.seed --create-admin` for headless installs.

### Step 6 — Confirm data is flowing

1. **Dashboard → Overview** shows totals, severity mix and recent alerts.
2. **Live Monitor** streams events over the WebSocket (`/ws/live`) as the
   collectors push them.
3. **API check:**

   ```bat
   curl http://127.0.0.1:8000/api/v1/system/health
   curl http://127.0.0.1:8000/api/v1/system/collectors
   curl http://127.0.0.1:8000/api/v1/system/metrics
   ```

   `/metrics` reports events/s, queue depth, per-stage latencies (collection,
   processing, detection, alert, database, websocket), CPU and RSS.

If nothing arrives: this is expected on an idle network — Mini SOC never invents
events. Check which adapter was chosen (`GET /api/v1/system/collectors` reports
`detail.interface`) and the BPF filter, then confirm the syslog listener is
reachable on UDP 5514. To prove the pipeline end-to-end without touching real
traffic, use the offline harnesses instead: `scripts\validate_lab.bat` and
`scripts\benchmark.bat` (they write to their own throw-away databases). Only on
an isolated lab host should you set `MINI_SOC_SIMULATOR_ENABLED=true` and call
`POST /api/v1/system/simulator?scenario=port_scan` — the dashboard then shows a
red `LAB DATA` badge until you stop it.

### Step 7 — Daily analyst workflow

| stage | where | what happens |
|-------|-------|--------------|
| observe | Live Monitor | raw normalised events as they arrive |
| triage | Alerts | alerts sorted by severity/risk; open one to see the triggering event, detection types, risk breakdown and the ML prediction |
| respond | Alert detail | change status `NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED`, assign an analyst, add notes |
| correlate | Incidents | related alerts on the same entity collapse into one incident; add notes and assign an owner |
| hunt | Threats / Analytics / Network / Investigation | rule-hit timelines, historical aggregates, per-entity network stats, ad-hoc investigation views |
| report | Reports | exportable summaries for a time range |

Alert de-duplication is built in: repeats of the same detection type on the same
source/destination inside the dedupe window update the existing alert instead of
creating a new one, and the update counter is visible in the metrics.

### Step 8 — Tune detection

- **Rules** live in [`detection-rules/`](detection-rules/) as YAML packs
  (port scan, brute force, connection flood, repeated failures, DNS anomaly,
  volume anomaly, suspicious protocol). Edit thresholds, save, and the registry
  re-syncs (hot reload every `MINI_SOC_RULES_RELOAD_SECONDS`, default 60 s) —
  or restart the backend.
- **ML model** is a versioned Isolation Forest artifact in `ml/artifacts/`.
  Retrain and publish a new version:

  ```bat
  .venv\Scripts\python.exe -m ml.train --baseline --version v3 --report logs\training-report.json
  ```

  Activate/roll back through `GET /api/v1/models` and
  `POST /api/v1/models/activate`. See [docs/ml](docs/ml/README.md).

### Step 9 — Verify the installation

```bat
scripts\run_tests.bat         :: backend suite (236 tests) + dashboard suite (14 tests)
scripts\validate_lab.bat      :: end-to-end attack + benign validation (phase 10)
scripts\benchmark.bat 4000    :: throughput / latency / CPU / memory benchmark (phase 9)
```

Reports land in `logs\`: `validation-report.json`, `benchmark-report.json`,
`training-report.json`. Expected results are listed in the
[root README](README.md#verification-evidence).

### Step 10 — Maintenance

| task | how |
|------|-----|
| retention purge | automatic every 6 h; force with `POST /api/v1/system/maintenance/purge` |
| log rotation | the app rotates `logs/mini_soc.log` itself (`MINI_SOC_LOG_MAX_BYTES`, 5 backups) |
| database backup | copy `data/mini_soc.db` (+ `-wal`/`-shm`) while stopped, or `pg_dump` on PostgreSQL |
| secret backup | back up `data/secrets/` together with the database |
| audit review | `GET /api/v1/system/audit` (ADMIN) |
| revoke a session | `POST /api/v1/users/{id}/revoke-tokens` |

---

## 2. Deployment structure

### A. Development / single-machine SOC (default)

```text
                    Windows host
 ┌─────────────────────────────────────────────────────────────┐
 │  cmd window 1                    cmd window 2               │
 │  uvicorn app.main:app            vite dev server            │
 │  :8000                           :5173                      │
 │      ▲  /api, /ws proxy ────────────┘                       │
 │      │                                                      │
 │  collectors: Npcap capture · UDP syslog :5514 · psutil      │
 │      │                                                      │
 │  pipeline → detection → risk → alerts → incidents           │
 │      │                                                      │
 │  data/mini_soc.db (SQLite WAL)   logs/   ml/artifacts/      │
 └─────────────────────────────────────────────────────────────┘
```

One machine, two processes, zero external services. This is what
`run_mini_soc.bat` starts.

### B. Single-process deployment (API + dashboard together)

```bat
cd frontend
npm run build:api                              :: emits frontend\dist rooted at /app/
cd ..\backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

When `frontend/dist` exists the backend serves the dashboard at `/app` (and the
assets it references). Always build with `npm run build:api` for this mode: it
roots the bundle and the SPA router at `/app`, so deep links such as
`/app/alerts` survive a refresh. The REST API stays on `/api/v1` and the OpenAPI
docs on `/api/docs`, so **one process** serves both the API and the dashboard —
no CORS, no separate Node server. Suitable for a small always-on SOC box (wrap it
in a Windows service or Task Scheduler entry, or run it in the background).

### C. Docker Compose

```bash
cp .env.example .env          # set MINI_SOC_JWT_SECRET and MINI_SOC_ADMIN_PASSWORD
docker compose up --build     # dashboard :8080, API :8000
docker compose --profile postgres up --build   # SQLite → PostgreSQL
```

```text
 browser :8080
      │
 ┌────▼──────────────┐        ┌────────────────────┐
 │ dashboard (nginx) │──/api/─▶│ backend (uvicorn)  │
 │  frontend image   │──/ws/──▶│  backend image     │
 └───────────────────┘        └─────────┬──────────┘
                                        │
                        volume mini-soc-data (SQLite, logs, ml artifacts)
                        volume postgres-data  (only with --profile postgres)
```

Notes:

- Containers cannot see host network interfaces by default, so the backend image
  ships with `MINI_SOC_COLLECTOR_NETWORK_ENABLED=false`. It still ingests via
  the syslog receiver and the REST API. **For real packet capture run the backend
  directly on the host** (option A or B) with Npcap installed. The lab simulator
  stays off in containers unless you deliberately enable it.
- `frontend/nginx.conf` proxies `/api/` and `/ws/` (with WebSocket upgrade
  headers) to `backend:8000` and falls back to `index.html` for SPA routes.
- The backend healthcheck hits `/api/v1/system/health`.

### D. Production hardening (any of the above)

- [ ] `MINI_SOC_ENV=production`, `MINI_SOC_DEBUG=false`
- [ ] `MINI_SOC_JWT_SECRET` = long random value (≥ 32 bytes)
- [ ] `MINI_SOC_ADMIN_PASSWORD` set for bootstrap, rotated afterwards
- [ ] `MINI_SOC_CORS_ORIGINS` / `MINI_SOC_TRUSTED_HOSTS` limited to real hosts
- [ ] TLS terminated by a reverse proxy (nginx / Caddy / IIS) in front of the API
- [ ] capture interface authorized and the BPF filter scoped
- [ ] scheduled backup of the database **and** `data/secrets/`
- [ ] monitoring on `/api/v1/system/health` and `/api/v1/system/metrics`
- [ ] capacity headroom: measured ~4.4 ms CPU per event and ~200 MB RSS with ML

---

## 3. Where everything lives on disk

```text
mini-soc\
├── run_mini_soc.bat        ← one-click launcher (this runbook's entry point)
├── .env                    ← your configuration (created from .env.example)
├── backend\                ← FastAPI app, pipeline, detection, storage
├── frontend\               ← React dashboard (src\, dist\ after a build)
├── ml\                     ← training pipeline; ml\artifacts\ holds model versions
├── detection-rules\        ← YAML rule packs (hot-reloaded)
├── scripts\                ← setup / start / test / validate / benchmark helpers
├── docs\                   ← architecture · api · database · ml · deployment
├── data\                   ← mini_soc.db (SQLite WAL) + secrets\
└── logs\                   ← mini_soc.log + benchmark/validation/training reports
```

`MINI_SOC_HOME` relocates `data\`, `logs\`, `ml\artifacts\` and
`detection-rules\` to any directory (e.g. `C:\ProgramData\MiniSOC`) without
touching the code — useful for a service install.

---

## 4. Command reference

| command | purpose |
|---------|---------|
| `run_mini_soc.bat` | first-run setup if needed, then start backend + dashboard |
| `scripts\setup.bat` | install/reinstall all dependencies, create `.env` |
| `scripts\start_all.bat` | start backend + dashboard (deps already installed) |
| `scripts\start_backend.bat` | backend only, :8000 |
| `scripts\start_frontend.bat` | dashboard only, :5173 |
| `scripts\run_tests.bat` | backend + dashboard test suites |
| `scripts\validate_lab.bat` | attack/benign end-to-end validation |
| `scripts\benchmark.bat [events]` | pipeline benchmark (default 4000 events) |

---

## 5. Troubleshooting

| symptom | cause / fix |
|---------|-------------|
| `Python was not found on PATH` | install Python 3.11+ and tick *Add python.exe to PATH* |
| `npm was not found on PATH` | install Node.js 18+ |
| backend window closes instantly | check `logs\mini_soc.error.log`; usually a bad `.env` value or port 8000 taken |
| `Port 8000 is already in use` | another Mini SOC (or app) is running — close it or change `MINI_SOC_PORT` and `VITE_BACKEND` |
| dashboard loads but no live data | WebSocket blocked — proxy `/ws/` with upgrade headers, or use option B (single process) |
| `401` on every request | access token expired (30 min default) — refresh or log in again |
| `429` responses | rate limit hit (`MINI_SOC_RATE_LIMIT_PER_MINUTE`, default 240/min) |
| no packet events | Npcap missing, wrong interface, or BPF filter too narrow; check `/api/v1/system/collectors` |
| `database is locked` in logs | SQLite writer contention — set `MINI_SOC_PIPELINE_WORKERS=1` or move to PostgreSQL |
| ML alerts never fire | `GET /api/v1/models` — if no artifact is active, retrain with `python -m ml.train --baseline` |
| `already_initialised` on bootstrap | an account already exists — log in as `admin` / `MiniSOC-Core-2026!`, or delete `data\mini_soc.db` (backend stopped) to start over |
| forgot the admin password | stop the backend, delete `data\mini_soc.db`, restart, and use *Create administrator* on the login page |

Always monitor only systems you are authorized to observe.
