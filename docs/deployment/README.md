# Mini SOC — Deployment

Three supported ways to run the platform:

1. **Windows desktop / workstation** (development and single-machine SOC) —
   helper scripts, one process per component.
2. **Windows service-style manual start** — backend + built dashboard served by
   the backend itself (single process deployment).
3. **Docker Compose** — backend container + nginx dashboard (+ optional
   PostgreSQL).

Live packet capture additionally needs **Npcap** (Windows) or libpcap (Linux)
and an interface you are authorized to monitor.

## 1. Windows quick start

```bat
scripts\setup.bat          :: venv + dependencies + .env + npm install
:: edit .env: set MINI_SOC_ADMIN_PASSWORD (and MINI_SOC_JWT_SECRET for production)
scripts\start_all.bat      :: backend :8000 + dashboard :5173 in separate windows
```

Then open http://127.0.0.1:5173, create the first administrator with the
`/api/v1/auth/bootstrap` endpoint (or the dashboard's first-run screen), and log in.

Other helpers:

```bat
scripts\run_tests.bat      :: backend suite + dashboard suite
scripts\validate_lab.bat   :: controlled attack/benign validation (phase 10)
scripts\benchmark.bat 4000 :: throughput/latency/CPU benchmark (phase 9)
```

Manual equivalent:

```bat
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
cd frontend && npm run dev
```

## 2. Single-process deployment (API + dashboard)

```bat
cd frontend
npm run build:api          :: emits frontend\dist rooted at /app/
cd ..\backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

When `frontend/dist` exists the backend serves the dashboard at `/app` with an
SPA fallback, so one process serves both API and dashboard (strict
CSP-friendly, no CORS). `npm run build:api` roots the bundle and router at
`/app`; a plain `npm run build` only renders the first page under `/app`.

## 3. Docker Compose

```bash
cp .env.example .env       # set MINI_SOC_JWT_SECRET and MINI_SOC_ADMIN_PASSWORD
docker compose up --build  # dashboard on :8080, API on :8000
docker compose --profile postgres up --build   # SQLite -> PostgreSQL (see docs/database)
```

Containers cannot see host interfaces by default; the backend image runs with
`MINI_SOC_COLLECTOR_NETWORK_ENABLED=false` and collects via the syslog
receiver, the API or the simulator. For host capture, run the backend directly
on the host (option 1/2) with Npcap installed.

## 4. Configuration reference

All settings use the `MINI_SOC_` prefix (see [.env.example](../../.env.example)
for the full list).

| variable | default | notes |
|----------|---------|-------|
| `MINI_SOC_HOME` | repository root | relocates `data/`, `logs/`, `ml/artifacts`, `detection-rules` |
| `MINI_SOC_DATABASE_URL` | `sqlite+pysqlite:///./data/mini_soc.db` | PostgreSQL supported |
| `MINI_SOC_JWT_SECRET` | auto-generated in `data/secrets/` | **set explicitly in production** |
| `MINI_SOC_ADMIN_USERNAME` / `_PASSWORD` | `admin` / empty | used by the first-run bootstrap |
| `MINI_SOC_COLLECTOR_*` | network/syslog on, system off | enable only authorized sources |
| `MINI_SOC_SIMULATOR_ENABLED` | `false` | lab-only synthetic traffic; while false the platform is real-time only and `POST /system/simulator` is refused |
| `MINI_SOC_PIPELINE_QUEUE_SIZE` / `_WORKERS` / `DB_WRITE_BATCH_SIZE` | 20000 / 2 / 100 | back-pressure and batch tuning |
| `MINI_SOC_RATE_LIMIT_PER_MINUTE` / `_LOGIN_...` | 240 / 10 | API abuse protection |
| `MINI_SOC_CORS_ORIGINS` / `_TRUSTED_HOSTS` | localhost | lock these down in production |

## 5. Production checklist

- [ ] `MINI_SOC_ENV=production`, `MINI_SOC_DEBUG=false`
- [ ] `MINI_SOC_JWT_SECRET` set to a long random value (≥ 32 bytes)
- [ ] `MINI_SOC_ADMIN_PASSWORD` set for the first-run bootstrap; rotate after
- [ ] `MINI_SOC_CORS_ORIGINS` and `MINI_SOC_TRUSTED_HOSTS` limited to real hosts
- [ ] TLS terminated by a reverse proxy (nginx/Caddy/IIS) in front of the API
- [ ] capture interface authorized and BPF filter scoped (`MINI_SOC_COLLECTOR_BPF_FILTER`)
- [ ] backup job for the database and `data/secrets/` (see docs/database)
- [ ] log rotation for `logs/` (the app appends; OS tooling should rotate)
- [ ] monitoring on `/api/v1/system/health` and `/api/v1/system/metrics`
- [ ] CPU/memory headroom: measured ~11 ms CPU per event, ~200 MB RSS with ML

## 6. Operations

| task | how |
|------|-----|
| health check | `GET /api/v1/system/health` (liveness) and `/ready` (DB + runtime) |
| live metrics | `GET /api/v1/system/metrics` (events/s, latencies, CPU, RSS, queue depth) |
| retention purge | `POST /api/v1/system/maintenance/purge` or the 6-hourly automatic purge |
| rule changes | edit `detection-rules/*.yaml`; the registry re-syncs on schedule or restart |
| model rollback | `POST /api/v1/models/activate` with the previous version |
| force re-login | `POST /api/v1/users/{id}/revoke-tokens` |
| audit trail | `GET /api/v1/system/audit` (ADMIN) |

## 7. Troubleshooting

| symptom | check |
|---------|-------|
| no events arriving | `/api/v1/system/collectors`; capture requires Npcap/libpcap and a free interface; syslog listens on UDP 5514 by default |
| `database is locked` in logs | SQLite writer contention — lower `MINI_SOC_PIPELINE_WORKERS` to 1 or move to PostgreSQL |
| 401 on every request | access token expired (30 min default); refresh or log in again |
| 429 responses | rate limit hit; raise `MINI_SOC_RATE_LIMIT_PER_MINUTE` deliberately |
| dashboard shows no live data | WebSocket blocked by a proxy — proxy `/ws/` with upgrade headers (see `frontend/nginx.conf`) |
| ML alerts missing | `GET /api/v1/models`; if no artifact is active, retrain with `python -m ml.train --baseline` |
