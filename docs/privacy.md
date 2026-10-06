# Privacy — Local-First Promise

> **Your security data belongs to you. Local by default.**

## What this means in V0.1

- **All assessment data stays on this machine.** Findings, evidence (including
  banners), run history, and audit logs live in a local SQLite file
  (`data/findings.db`). There is no sync, no cloud backup, no account.
- **No telemetry.** The platform collects no analytics, no behavioral data,
  no usage statistics. There is nothing to opt out of because nothing is
  collected.
- **Crash reports stay local.** Uncaught exceptions produce a JSON report in
  `logs/crashes/` on this machine. They are never uploaded.
- **Logs stay local.** Rotating logs in `logs/` are gitignored and never
  committed or transmitted.

## Data the software touches

| Data | Where it lives | Leaves the machine? |
| --- | --- | --- |
| Findings / evidence | `data/findings.db` | No |
| Run + audit history | `data/findings.db` | No |
| Logs, crash reports | `logs/` | No |
| Scope file | `config/authorized_targets.yaml` | No |

## Future integrations (not in V0.1)

Any future integration that would move data off-device (cloud AI analysis,
external assessment workers, webhooks, exports) must:

1. Be **off by default** and require explicit operator opt-in.
2. **Disclose exactly what data leaves the device** before activation.
3. Support user-controlled retention, export, and deletion.

## V0.5 — external assessment (opt-in)

The outside-in worker is the first integration under the rules above:

- **Off by default.** `PUT /external/status {"enabled": false}` is the
  initial state; the dashboard's 🌐 Outside-in panel shows the disclosure
  before the operator can enable it. Disabling is a kill switch:
  enqueue, worker polling, and result ingest all stop immediately.
- **What leaves the device:** (1) the target list and probe set the
  operator assigns to a worker, sent to that worker; (2) the worker's
  results, which come *back* to the local API as evidence. Raw scan
  data never goes anywhere except the operator's own API.
- **Retention / deletion:** workers are revoked in one click
  (`DELETE /external-workers/{id}`), which kills the token immediately.
  Findings produced from worker results are ordinary findings — they
  follow the same lifecycle and can be marked false-positive / fixed
  like any other. Assessment queue rows live in the local database.
- **Secrets:** worker tokens are stored as sha256 hashes and shown
  exactly once at registration (`SECURITY.md`).

## Secrets

Secrets and credentials must never be committed to the repository
(`SECURITY.md`). Discovery in V0.1 performs no authentication and stores no
credentials.
