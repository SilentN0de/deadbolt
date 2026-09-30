# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] — 2026-09-30

### Added
- Read-only local discovery agent (`agent/discovery.py`): TCP connect scan of a
  curated common-ports list with recv-only banner grabs, bounded concurrency,
  per-host and global rate limits, and timeouts. Runnable as
  `python -m agent.discovery --scope config/authorized_targets.yaml`.
- Scope & authorization enforcement (`agent/scope.py`): the agent refuses to
  run without an explicit scope file; public IPs and `0.0.0.0/0` require
  `authorization_acknowledged: true` plus per-target `authorized: true`;
  every allow/deny decision is logged and audit-recorded.
- Normalized finding/evidence data model (`storage/`): findings with
  suspected/confirmed/accepted-risk/fixed/false-positive lifecycle, evidence
  items with sha256-hashed excerpts, retest history, run records.
- Immutable `audit_log` table (DB triggers reject UPDATE/DELETE) recording
  every discovery attempt: timestamp, scope hash, authorization flags,
  target count, decision.
- Local FastAPI service (`api/`): `GET /health`, `POST /runs` (validates scope
  before running), `GET /runs`, `GET /findings`, `GET /findings/{id}`.
  Binds 127.0.0.1 by default.
- Minimal dashboard at `/`: findings table rendered from the local API.
- Logging: rotating file logs to `logs/`; uncaught-exception hook writes
  local JSON crash reports to `logs/crashes/` (no exfiltration).
- Test suite (22 tests): scope refusal cases, data-model round-trip,
  live loopback discovery against a fixture TCP server, safe handled
  failure (timeouts → suspected finding, no crash), API smoke tests.
- Docs: README, SECURITY.md, CONTRIBUTING.md, architecture, privacy,
  data model.

### Safety notes
- Non-destructive only: no exploit code, payloads, brute force, or lateral
  movement anywhere in the codebase.
- Shipped scope default is loopback-only (`127.0.0.1`).

## [0.0.0] — 2026-09-30
- Project foundation: repo scaffolding, architecture, privacy principles.
