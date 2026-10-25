# Mini SOC — Database

Default deployment is a single SQLite file (`data/mini_soc.db`) in WAL mode —
zero configuration, no server to run. Larger deployments set
`MINI_SOC_DATABASE_URL` to PostgreSQL and get multi-writer concurrency for free
(`docker-compose.yml` ships an optional `postgres` profile).

## Engine and tuning

`backend/app/database/connection.py` builds the engine and applies SQLite
pragmas on every connection:

| pragma | value | why |
|--------|-------|-----|
| `journal_mode` | WAL | concurrent readers while the pipeline writes |
| `synchronous` | NORMAL | durability without fsync-per-commit cost |
| `foreign_keys` | ON | referential integrity |
| `busy_timeout` | 30 s | tolerate brief writer contention |
| `temp_store` | MEMORY | faster sorts/joins for analytics queries |
| `cache_size` | ~40 MB | fewer page reads on hot tables |

The pipeline is the only writer for telemetry tables. On SQLite its batches are
serialised with `write_lock` (single-writer engine); PostgreSQL skips the lock.
Session scope commits per batch; per-record savepoints isolate malformed
records. ID sequences are allocated with an atomic upsert
(`id_sequences` + `INSERT .. ON CONFLICT .. RETURNING`), so parallel workers
never collide.

## Schema

| table | purpose | key fields |
|-------|---------|------------|
| `id_sequences` | human-readable ID allocation (`EVT-`, `ALT-`, `INC-`, `DET-`) | `name`, `value` |
| `users` | accounts + RBAC | `username`, `password_hash`, `role`, `is_active` |
| `refresh_tokens` | refresh-token rotation/revocation | `token_hash`, `expires_at`, `revoked_at` |
| `assets` | entity inventory feeding risk scoring | `ip_address`, `importance`, `tags` |
| `events` | normalised security events | `event_id`, `timestamp`, `source_ip`, `destination_ip`, `event_type`, `protocol`, `severity`, `risk_score`, `anomaly_score`, `dedupe_hash` |
| `network_events` | protocol detail (1:1 with events) | `dns_query`, `tcp_flags`, `http_host`, `tls_sni`, `duration_ms` |
| `detection_rules` | rule catalogue synced from YAML | `rule_key`, `category`, `enabled`, `threshold`, `params`, `source` |
| `detections` | rule/ML detections per event | `detection_id`, `event_id`, `rule_key`, `detection_type`, `engine`, `rule_score`, `anomaly_score`, `confidence`, `alert_id` |
| `alerts` | analyst-facing alerts | `alert_id`, `dedupe_key`, `detection_type`, `severity`, `risk_score`, `status`, `event_count`, `incident_id`, `first_seen`, `last_seen` |
| `incidents` | correlated alert groups | `incident_id`, `title`, `severity`, `status`, `source_entities`, `detection_types`, `alert_count`, `timeline` |
| `investigation_notes` | notes on alerts/incidents | `subject_type`, `subject_id`, `note`, `author_id` |
| `model_predictions` | every ML inference (audit + drift) | `event_id`, `model_name`, `model_version`, `anomaly_score`, `is_anomaly`, `threshold`, `features`, `latency_ms` |
| `system_logs` | operational log of the platform | `message`, `category`, `level`, `details` |
| `metrics_snapshots` | periodic performance snapshots (15 s) | `events_per_second`, `*_latency_ms`, `cpu_percent`, `memory_mb` |
| `config_overrides` | runtime setting overrides | `key`, `value`, `updated_by` |

## Retention

`POST /api/v1/system/maintenance/purge` (ADMIN) deletes telemetry older than
`MINI_SOC_PIPELINE_RETENTION_DAYS` (default 30). The pipeline also runs the
purge on its maintenance schedule (every 6 h). Rules, users, assets and model
metadata are never purged.

## PostgreSQL

```env
MINI_SOC_DATABASE_URL=postgresql+psycopg://mini_soc:CHANGE_ME@localhost:5432/mini_soc
```

The schema is created on first startup. `psycopg` is already installed with the
backend requirements, so no extra dependency is needed; the in-process write
lock is skipped automatically for non-SQLite URLs.

## Backup and restore

* SQLite: stop the service (or use `sqlite3 data/mini_soc.db ".backup backup.db"`)
  and copy `data/mini_soc.db`. WAL files are checkpointed on clean shutdown.
* PostgreSQL: `pg_dump -U mini_soc mini_soc > backup.sql`.
* Secrets: `data/secrets/` holds the generated JWT key — back it up separately
  so tokens survive a restore, or rotate it to force re-login of everyone.
