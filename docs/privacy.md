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

## Secrets

Secrets and credentials must never be committed to the repository
(`SECURITY.md`). Discovery in V0.1 performs no authentication and stores no
credentials.
