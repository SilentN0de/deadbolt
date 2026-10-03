# Data Model (V0.4)

Normalized finding/evidence model. Python dataclasses live in
`storage/models.py`; the SQLite schema in `storage/schema.sql`.

## findings

One row per distinct `(target, title)`. Re-running discovery against the same
target **updates** the row instead of duplicating it.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | TEXT PK | uuid4 hex, stable across re-runs |
| `target` | TEXT | e.g. `127.0.0.1` |
| `title` | TEXT | e.g. `Open port 22/tcp (SSH) — banner: 'SSH-2.0-...'` |
| `severity` | TEXT | `info` \| `low` \| `medium` \| `high` \| `critical` |
| `status` | TEXT | `suspected` \| `confirmed` \| `accepted-risk` \| `fixed` \| `false-positive` |
| `first_seen` | TEXT | ISO-8601 UTC of first observation |
| `last_seen` | TEXT | ISO-8601 UTC of most recent observation |
| `remediation` | TEXT | Human-readable guidance |
| `retest_history` | TEXT | JSON array of retest/lifecycle events, e.g. `[{"timestamp": "...", "event": "re-observed", "detail": "..."}, {"timestamp": "...", "event": "remediated", "detail": "..."}]` |

**Status lifecycle (V0.4):** discovery alone can only produce `suspected`.
Validation moves `suspected` → `confirmed` / `false-positive`. Retest moves
open findings → `fixed` when the service is gone, or `fixed` → `confirmed`
on regression. Operators move findings through the explicit state machine
in `lifecycle.py` (`POST /findings/{id}/status`). Every transition and every
retest is recorded in the append-only `finding_events` table below.
See `docs/lifecycle.md`.

## evidence

Immutable supporting observations, one row per probe that contributed to a
finding.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | INTEGER PK | autoincrement |
| `finding_id` | TEXT FK | → `findings(id)`, cascade delete |
| `timestamp` | TEXT | ISO-8601 UTC |
| `collector` | TEXT | e.g. `discovery.tcp` |
| `excerpt` | TEXT | raw output truncated to ≤512 chars |
| `excerpt_hash` | TEXT | sha256 hex of the **full** raw output |
| `detail` | TEXT | JSON: structured probe metadata (host, port, timeout flags, …) |

## runs

One row per discovery execution.

| Column | Notes |
| --- | --- |
| `started_at` / `finished_at` | ISO-8601 UTC |
| `scope_file` / `scope_hash` | absolute path + sha256 of the scope file used |
| `scope_targets` | JSON array of resolved target IPs |
| `authorization_acknowledged` | 0/1 — the flag state for this run |
| `target_count` | number of resolved hosts |
| `status` | `running` \| `completed` \| `failed` \| `denied` |
| `summary` | JSON: probe counts, open ports, findings created |

## audit_log

**Append-only.** One row per discovery *attempt*, allowed or denied:
timestamp, event, scope file + hash (NULL when the file was missing),
authorization flags, target count, `decision` (`allow`/`deny`), reason.
`BEFORE UPDATE` / `BEFORE DELETE` triggers abort any mutation.

## finding_events (V0.4)

**Append-only** lifecycle timeline, one row per status transition or retest
attempt (triggers abort UPDATE/DELETE like `audit_log`).

| Column | Notes |
| --- | --- |
| `finding_id` | → `findings(id)`, cascade delete |
| `timestamp` | ISO-8601 UTC |
| `event` | `status_changed` \| `retest` \| `note` |
| `old_status` / `new_status` | statuses before/after |
| `actor` | `operator` \| `retest` \| `system` (validation-driven) |
| `detail` | JSON: operator note, retest summary, validation outcome |

## finding_snapshots (V0.4)

Point-in-time counts for trend tracking: one row per `(status, severity)`
per snapshot batch (`timestamp`, `run_id` NULL for retest batches, `status`,
`severity`, `count`). Written automatically when a discovery run completes
and after every retest batch. `GET /trends` buckets them per day (latest
batch wins); `GET /trends/summary` derives current totals and
mean-time-to-fix from `finding_events`.
