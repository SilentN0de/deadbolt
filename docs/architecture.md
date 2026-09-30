# Architecture (V0.1)

## Components

```
┌──────────────┐      scope file       ┌──────────────────┐
│  agent/      │  ─────────────────▶   │  config/         │
│  scope.py    │  allow / deny         │  authorized_     │
│  discovery.py│                       │  targets.yaml    │
└──────┬───────┘                       └──────────────────┘
       │ TCP connect + banner grab (read-only, rate-limited)
       ▼
┌──────────────┐   findings/evidence   ┌──────────────────┐
│  storage/    │  ─────────────────▶   │  SQLite (WAL)    │
│  db.py       │                       │  data/findings.db│
└──────┬───────┘                       └──────────────────┘
       │
       ▼
┌──────────────┐      HTTP             ┌──────────────────┐
│  api/main.py │  ◀─────────────────   │  dashboard/      │
│  127.0.0.1   │     JSON             │  index.html      │
└──────────────┘                       └──────────────────┘
```

## Data flow

1. Operator runs `python -m agent.discovery --scope config/authorized_targets.yaml`
   (or `POST /runs`).
2. `agent/scope.py` validates the scope file. On refusal: a `deny` row goes to
   the immutable `audit_log` and the process exits non-zero — no packets sent.
3. On allow: an `allow` audit row is written, a `runs` row is opened, and the
   discovery sweep runs (thread pool, per-host + global rate limits).
4. Probe results become normalized findings with evidence rows
   (`storage/db.py` upserts on `(target, title)` so re-runs refresh
   `last_seen` and append retest history instead of duplicating).
5. The API serves findings/runs from the local DB; the dashboard renders them.
   Everything binds to loopback.

## Trust boundaries

- **Scope file** is the primary safety boundary. It is read from disk at run
  time; the shipped default authorizes only `127.0.0.1`.
- **Network**: the agent only ever initiates TCP connects to in-scope hosts.
  No raw sockets, no crafted packets, nothing sent during banner grabs.
- **API**: loopback-only by default. Exposing it beyond 127.0.0.1 is an
  explicit operator decision (and out of scope for V0.1 hardening).
- **Database**: local SQLite file; WAL mode. `audit_log` is append-only,
  enforced both by convention and by DB triggers.

## What V0.1 deliberately does not do

- No AI analysis (V0.2), no controlled validation / proof-of-weakness (V0.3),
  no remediation workflow or fix-verification (V0.4), no external/outside-in
  assessment (V0.5). Findings from discovery are always `suspected` until a
  later stage can confirm them.
