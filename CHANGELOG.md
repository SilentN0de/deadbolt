# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed
- Socket file-descriptor leaks: `agent/discovery.py::probe_port` and
  `validator/checks.py::tcp_reprobe` now always close the socket via
  try/finally, even when `connect()` is refused or times out. Previously a
  /24 sweep could leak thousands of FDs on closed ports.
- Finding titles are now stable (`Open port <port>/tcp (<service>)`): banner
  text no longer embedded. Findings dedupe on (target, title), so a banner
  change (e.g. service upgrade) now updates the finding and appends evidence
  instead of spawning a duplicate. Banner still stored in evidence detail.
- `/31` scope entries (RFC 3021) now resolve to both usable addresses;
  previously the second address was silently dropped.
- `POST /findings/{id}/validate`: unknown check names now return 400
  (were conflated with 404 "finding not found"); empty `checks: []` is
  rejected with 400; duplicate check names are collapsed so a check never
  runs twice per validation.
- Splunk HEC exporter: empty event batches return early instead of POSTing
  an empty body; non-JSON success responses no longer raise in ack parsing.
- README roadmap was stale (showed V0.1 as current); now marks V0.2/V0.3
  done with V0.4 (fix & verify) as next.

### Added
- Splunk integration (`exporters/splunk.py`): findings export as
  CIM-friendly Splunk events (`sourcetype` `secplatform:finding`; fields
  `dest`, `dest_port`, `severity`, `status`). Two operator-triggered,
  audit-logged paths — spool JSONL files for a Universal Forwarder
  (`data/splunk_spool/`, no Splunk credentials needed) and direct HEC
  POST (via `SPLUNK_HEC_URL` / `SPLUNK_HEC_TOKEN` env vars only).
- `POST /export/splunk` with `mode`, `severity`, `status`, `target`
  filters; 503 when HEC is unconfigured; every attempt audit-logged.
- Dashboard "Export to Splunk" button with spool/HEC mode selector.
- `docs/splunk.md`: forwarder stanza, HEC token setup, field reference.
- 9 new offline tests (54 total): event formatting, spool output, HEC
  payload shape and error handling, endpoint behavior, audit entries.

## [0.3.0] — 2026-09-30

### Added
- Controlled validation (`validator/`): operator-triggered, single-finding,
  read-only follow-up checks — `tcp_reprobe` (confirm still open / detect
  gone), `tls_certificate` (handshake-only cert inspection: expiry,
  self-signed, TLS version), `banner_intel` (offline flagging of
  long-unmaintained releases). No payloads, no brute force, no auth attempts.
- Finding status transitions from validation: `suspected` → `confirmed` or
  `suspected` → `false-positive`; human-set states are never overwritten.
  Every attempt (allowed or denied) is written to the immutable audit log,
  and the finding's host must be inside the authorized scope or validation
  is refused.
- `validations` table + `Validation` model; each check result is stored as
  evidence on the finding.
- Simulated lab (`sim/`): fake SSH/HTTP/HTTPS services on 127.0.0.1 for
  safe end-to-end testing, plus `scripts/simulate_lab.py` for manual runs.
- `POST /findings/{id}/validate` (10s per-finding cooldown) and
  `GET /findings/{id}/validations`; dashboard "Run validation" button with
  per-check results and validation history.
- `docs/validation.md`: checks, outcomes, safety rails, sim lab usage.
- Test suite now 45 tests (was 29): 16 simulation-backed validator tests
  covering confirm/false-positive transitions, TLS parsing, banner intel,
  scope refusal, audit entries, cooldown, and the new endpoints.

### Changed
- Version bumped to 0.3.0 (API, dashboard label, README).

## [0.2.0] — 2026-09-30

### Added
- Local analyst (`analyst/`): deterministic, offline explanation engine with a
  curated per-service knowledge base (what the service is, why exposure
  matters, prioritized remediation steps). No cloud calls — nothing leaves
  the machine.
- `GET /findings/{id}/explanation`: plain-English analysis per finding —
  summary, what was observed (incl. banner/version-disclosure notes), what it
  means, why it matters, what to do, and an explicit confidence statement
  separating proven facts (TCP handshake) from inference (service identity).
- Dashboard: click any finding row to open the analyst explanation panel.
- `docs/analyst.md`: engine design, honesty rules, and how to extend the
  knowledge base. Knowledge-base coverage of every discovery port is enforced
  by test.
- Test suite now 29 tests (was 22): knowledge coverage, explanation quality,
  unknown-port and unresponsive-host fallbacks, and the new endpoint.

### Changed
- Shared pytest fixtures moved to `tests/conftest.py`.
- Version bumped to 0.2.0 (API, dashboard label, README).

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
