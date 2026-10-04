# Deadbolt

> **Your security data belongs to you. Local by default.**

A privacy-first security assessment platform for systems you own or are
explicitly authorized to test. The core loop: **Discover → Safely Validate →
Explain → Remediate → Retest → Monitor.**

**Current stage: V0.4 — discovery + analyst + controlled validation + fix & verify.** A Python agent discovers
open TCP services on authorized targets, stores evidence-backed findings in a
local SQLite database, a built-in analyst explains each finding in
plain English, operator-triggered read-only validation checks confirm
findings, retests verify fixes against current target state, an explicit
lifecycle state machine tracks every status change, and trend snapshots
power per-day time series — all served through a local API + dashboard.
Nothing leaves the machine.

## Quickstart

```bash
# 1. Create an isolated environment and install
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Review the scope file (default: 127.0.0.1 only — safe anywhere)
cat config/authorized_targets.yaml

# 3. Run discovery against your authorized targets
python -m agent.discovery --scope config/authorized_targets.yaml

# 4. Serve the API + dashboard (binds 127.0.0.1 only)
./scripts/run_dev.sh
# then open http://127.0.0.1:8000  (dashboard) or query the API:
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/findings
```

## Project layout

| Path | Purpose |
| --- | --- |
| `agent/` | Local agent: scope enforcement (`scope.py`) + read-only discovery (`discovery.py`) |
| `api/` | FastAPI service (binds 127.0.0.1): health, runs, findings |
| `dashboard/` | Minimal findings dashboard (served at `/`) |
| `storage/` | SQLite layer: `schema.sql`, dataclasses, `Store` |
| `lifecycle.py` | Finding lifecycle state machine (V0.4) |
| `retest/` | Re-probing findings against current target state (V0.4) |
| `trends.py` | Snapshot-based trend series + summary (V0.4) |
| `common/` | Rotating file logging + local crash-report hook |
| `config/` | `authorized_targets.yaml` — the safety boundary |
| `scripts/` | `run_dev.sh` — launch the API; `simulate_e2e.py` — full pipeline simulation |
| `tests/` | pytest suite (scope, data model, discovery, API) |
| `docs/` | architecture, privacy, data model |
| `logs/` | Rotating logs + local crash reports (gitignored, never committed) |

## Safety & authorization

**Read this before adding targets.** The agent refuses to run unless
`config/authorized_targets.yaml` exists and explicitly lists targets with
`authorized: true`. Public IPs and `0.0.0.0/0` additionally require
`authorization_acknowledged: true`. Every allow/deny decision is logged and
written to an immutable audit table.

- Only assess systems you own or are explicitly authorized to test.
- Discovery is **read-only and non-destructive**: TCP connect + banner grab
  only. No exploits, payloads, brute force, or lateral movement.
- See [SECURITY.md](SECURITY.md) and [docs/architecture.md](docs/architecture.md).

## Roadmap

- **V0.0** ✅ foundation (repo, docs, architecture, privacy)
- **V0.1** ✅ local discovery
- **V0.2** ✅ AI analyst: local evidence-backed explanations + remediation
- **V0.3** ✅ controlled validation: bounded, approved, audited confirmation
- **V0.4** ✅ fix & verify: retesting, finding lifecycle, trend tracking
- **V0.5** → external assessment: verified outside-in worker (next)

See [CHANGELOG.md](CHANGELOG.md) for version history.
