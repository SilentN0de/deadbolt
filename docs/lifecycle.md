# Finding Lifecycle (V0.4)

Every finding moves through an explicit, closed state machine defined in
`lifecycle.py` (`TRANSITIONS`). No status is ever written outside the
machine — operator actions, retests, and validation all go through
`transition_finding()`, and every transition is recorded in the
append-only `finding_events` table.

## State diagram

```
                    ┌─────────────┐
                    │  suspected  │  discovery alone can only produce this
                    └──────┬──────┘
                           │ validate / operator
              ┌────────────┼──────────────┐
              ▼            ▼              ▼
     ┌─────────────┐ ┌──────────┐ ┌───────────────┐
     │  confirmed  │ │  fixed   │ │ false-positive│
     └──────┬──────┘ └────┬─────┘ └───────┬───────┘
            │             │ regression    │ reopen
            │             ▼ (re-observed) ▼
            │        ┌──────────┐ ┌─────────────┐
            │        │confirmed │ │  suspected  │
            │        └──────────┘ └─────────────┘
            │ accepted-risk
            ▼
     ┌──────────────┐   reopen
     │accepted-risk │ ──────────► confirmed
     └──────────────┘
```

Allowed edges:

| From | To |
| --- | --- |
| `suspected` | `confirmed`, `fixed`, `false-positive` |
| `confirmed` | `fixed`, `accepted-risk`, `false-positive` |
| `fixed` | `confirmed` (regression) |
| `accepted-risk` | `confirmed` (reopened) |
| `false-positive` | `suspected` (reopened) |

`suspicious → fixed` exists so retest can mark a never-validated finding
fixed when its service is gone; operators may also use it directly
(e.g. "I removed that service").

## Retest flow (`retest/`)

`retest_finding(finding_id)` re-runs the applicable read-only probes
(`tcp_reprobe` + `banner_intel`, plus `tls_certificate` on TLS ports —
the same pipeline validation uses) against the target's **current** state:

| Probe result | Retest event | Status effect |
| --- | --- | --- |
| still present | `re-observed` | unchanged; `last_seen` refreshed — or `fixed` → `confirmed` regression |
| gone | `remediated` | `confirmed`/`suspected` → `fixed` (actor=`retest`) |
| gone, already terminal | `still-fixed` / `not-present` | unchanged |
| probe error / no port | `inconclusive` | unchanged |

Every retest appends `{timestamp, event, detail}` to the finding's
`retest_history` JSON, stores per-check evidence rows (`retest.<check>`),
writes one `finding_events` row (`event=retest`, actor=`retest`), and is
audit-logged. `retest_all(status_filter)` retests every open finding
(`suspected` + `confirmed` by default, or one explicit status) and records
a trend snapshot when the batch completes. Per-finding failures are
captured in the results, not fatal to the batch.

Scope is enforced exactly like validation: a target outside the authorized
scope refuses the retest (audit-deny + 400).

## API reference

| Method & path | Body / query | Notes |
| --- | --- | --- |
| `POST /findings/{id}/retest` | — | Re-probe one finding. 201. 404 unknown finding, 400 scope refused, 429 cooldown (10s). |
| `POST /retest` | `{"status": "open"}` (default) or one status | Batch retest + snapshot. 201, per-finding results. 400 on bad filter. |
| `POST /findings/{id}/status` | `{"status": "<status>", "note": "…"}` | Operator transition. 200. 400 on unknown status or illegal edge — the response includes the `allowed` next statuses. 404 unknown finding. |
| `GET /findings/{id}/events` | `?limit=` | Append-only lifecycle timeline. |
| `GET /trends` | `?days=30` | Per-day series: `{date, open, by_status, by_severity}` (latest snapshot batch per day wins). |
| `GET /trends/summary` | `?days=30` | `open`, `fixed_total`, `false_positive_total`, `new_in_period`, `mean_time_to_fix_seconds` (null when nothing was ever fixed). |

Mean time to fix = mean(`first fixed-transition timestamp` − `first_seen`)
across findings that have at least one `→ fixed` transition, read from
`finding_events` (null-safe).

## Dashboard

The dashboard (`/`) shows trend stat cards (open / fixed / false
positives / new in 30d / mean time to fix) fetched from
`GET /trends/summary`, refreshed on page load.
