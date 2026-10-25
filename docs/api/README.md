# Mini SOC — API reference

Base URL: `http://127.0.0.1:8000` (development). Interactive OpenAPI docs are
served at `/docs` (Swagger UI) and `/redoc`; the machine-readable schema at
`/openapi.json`.

All REST endpoints live under `/api/v1`. Requests and responses are JSON.

## Authentication

| step | endpoint | notes |
|------|----------|-------|
| first administrator | `POST /api/v1/auth/bootstrap` | succeeds only while no user exists; uses `MINI_SOC_ADMIN_*` settings |
| login | `POST /api/v1/auth/login` | returns access token (30 min default) + refresh token (7 days) |
| refresh | `POST /api/v1/auth/refresh` | rotates the refresh token |
| logout | `POST /api/v1/auth/logout` | revokes the presented refresh token |
| current user | `GET /api/v1/auth/me` | identity, role, permissions |

Send `Authorization: Bearer <access-token>` on every protected request.
Roles: **ADMIN** (everything), **ANALYST** (investigate, acknowledge, resolve,
notes), **VIEWER** (read-only). Failures return `401` (missing/invalid token)
or `403` (insufficient role).

## Endpoints

| method | path | role | purpose |
|--------|------|------|---------|
| GET | `/events` | VIEWER | paginated event feed (`source_ip`, `event_type`, `severity`, time filters) |
| GET | `/events/{event_id}` | VIEWER | event detail |
| GET | `/events/{event_id}/detections` | VIEWER | detections produced by an event |
| GET | `/events/{event_id}/related` | VIEWER | related events for the same entity |
| GET | `/alerts` | VIEWER | alert list (`severity`, `status`, `search`, pagination) |
| GET | `/alerts/statistics` | VIEWER | totals by severity/status/detection type |
| GET | `/alerts/{alert_id}` | VIEWER | alert detail + evidence + linked detections |
| PATCH | `/alerts/{alert_id}` | ANALYST | status transition (`NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED`), assignment, resolution |
| POST | `/alerts/{alert_id}/assign` | ANALYST | assign to a user |
| GET/POST | `/alerts/{alert_id}/notes` | VIEWER/ANALYST | investigation notes |
| GET | `/incidents` | VIEWER | incident list + filters |
| GET | `/incidents/statistics` | VIEWER | incident totals |
| GET | `/incidents/{incident_id}` | VIEWER | incident detail, timeline, linked alerts |
| POST | `/incidents` | ANALYST | manual incident creation |
| PATCH | `/incidents/{incident_id}` | ANALYST | status/severity/ownership changes |
| POST | `/incidents/{incident_id}/notes` | ANALYST | incident notes |
| GET | `/network/traffic` | VIEWER | protocol/traffic time series for charts |
| GET | `/network/statistics` | VIEWER | top talkers, ports, DNS activity |
| GET/PUT | `/network/assets` · `/network/assets/{ip}` | VIEWER/ANALYST | asset inventory + importance (feeds the risk engine) |
| GET | `/analytics` | VIEWER | historical analytics (detections, severity mix, trends) |
| GET | `/threats` | VIEWER | threat analytics (detection types, sources, MITRE-style classification) |
| GET | `/dashboard/summary` | VIEWER | KPI summary used by the overview page |
| GET | `/rules` · `/rules/{rule_key}` | VIEWER | rule catalogue; PATCH (ADMIN) tunes enabled state/thresholds |
| GET | `/models` | VIEWER | deployed model artefacts + metrics |
| POST | `/models/activate` | ADMIN | activate a registered model version |
| GET | `/system/health` · `/ready` | public | liveness / readiness probes |
| GET | `/system/metrics` | VIEWER | live pipeline metrics (events/s, latencies, CPU, memory) |
| GET | `/system/collectors` | VIEWER | collector status |
| GET | `/system/logs` · `/system/audit` | ADMIN | system log + audit trail |
| POST | `/system/maintenance/purge` | ADMIN | retention purge |
| POST | `/system/simulator` | ADMIN | start/stop/configure the authorized-lab event simulator (403 `simulator_disabled` unless `MINI_SOC_SIMULATOR_ENABLED=true`) |
| GET/POST | `/users` | ADMIN | user administration |
| PATCH | `/users/{user_id}` | ADMIN | role/active changes (self-demotion blocked) |
| POST | `/users/{user_id}/revoke-tokens` | ADMIN | force re-login |
| GET | `/users/me/permissions` | any | effective permissions |

## Pagination and errors

List endpoints return a page envelope:

```json
{ "items": [ ... ], "total": 42, "limit": 50, "offset": 0, "has_more": false }
```

Errors use a stable, non-leaking shape (validation failures never echo the
submitted value and include per-field `problems`):

```json
{ "error": "invalid_credentials", "message": "Invalid username or password", "request_id": "..." }
```

`422` marks validation failures; `429` marks rate limiting (see
`MINI_SOC_RATE_LIMIT_PER_MINUTE`, `MINI_SOC_LOGIN_RATE_LIMIT_PER_MINUTE`).

## WebSocket channels

Connect to `ws://<host>/ws/{channel}?token=<access-token>` (the `Authorization`
header is also accepted). Channels:

| channel | messages |
|---------|----------|
| `/ws/live` | `{"type": "events", "data": [event, ...]}` as batches are committed |
| `/ws/alerts` | `{"type": "alert.created" \| "alert.updated", "data": alert}` |
| `/ws/network` | network telemetry frames |

```js
const ws = new WebSocket(`ws://127.0.0.1:8000/ws/alerts?token=${token}`)
ws.onmessage = (e) => console.log(JSON.parse(e.data))
```

Unauthenticated sockets are closed with code `4401`; over-limit connections
with `4503`. The dashboard's WebSocket client (`frontend/src/services/websocket.js`)
reconnects with backoff and shares one socket per channel.
