-- ============================================================================
-- Deadbolt — SQLite schema (V0.1)
-- ============================================================================
-- All data stays local. Assessment rows never leave this machine unless the
-- user explicitly exports them.
-- ============================================================================

PRAGMA journal_mode=WAL;

-- ----------------------------------------------------------------------------
-- findings: one row per distinct (target, title). Re-runs update last_seen
-- and append retest history instead of duplicating rows.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,          -- uuid4 hex
    target          TEXT NOT NULL,             -- e.g. "127.0.0.1"
    title           TEXT NOT NULL,             -- e.g. "Open port 22/tcp (SSH)"
    severity        TEXT NOT NULL DEFAULT 'info'
                    CHECK (severity IN ('info','low','medium','high','critical')),
    status          TEXT NOT NULL DEFAULT 'suspected'
                    CHECK (status IN ('suspected','confirmed','accepted-risk',
                                      'fixed','false-positive')),
    first_seen      TEXT NOT NULL,             -- ISO-8601 UTC
    last_seen       TEXT NOT NULL,             -- ISO-8601 UTC
    remediation     TEXT NOT NULL DEFAULT '', -- guidance text
    retest_history  TEXT NOT NULL DEFAULT '[]', -- JSON array of retest events
    UNIQUE (target, title)
);
CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status    ON findings(status);

-- ----------------------------------------------------------------------------
-- evidence: immutable supporting observations linked to a finding.
-- excerpt_hash = sha256 of the full raw output the excerpt came from.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    timestamp     TEXT NOT NULL,           -- ISO-8601 UTC
    collector     TEXT NOT NULL,           -- e.g. "discovery.tcp"
    excerpt       TEXT NOT NULL,           -- truncated raw output (<=512 chars)
    excerpt_hash  TEXT NOT NULL,           -- sha256 hex of full raw output
    detail        TEXT NOT NULL DEFAULT '' -- JSON: structured probe metadata
);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);

-- ----------------------------------------------------------------------------
-- runs: one row per discovery execution.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS runs (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at                TEXT NOT NULL,
    finished_at               TEXT,
    scope_file                TEXT NOT NULL,
    scope_hash                TEXT NOT NULL,  -- sha256 of the scope file used
    scope_targets             TEXT NOT NULL,  -- JSON array of resolved targets
    authorization_acknowledged INTEGER NOT NULL DEFAULT 0,
    target_count              INTEGER NOT NULL DEFAULT 0,
    status                    TEXT NOT NULL DEFAULT 'running'
                              CHECK (status IN ('running','completed','failed','denied')),
    summary                   TEXT NOT NULL DEFAULT '{}' -- JSON: counts, notes
);

-- ----------------------------------------------------------------------------
-- audit_log: IMMUTABLE record of every discovery attempt (allowed or denied).
-- Application code must never UPDATE or DELETE rows here; the triggers below
-- enforce that at the database level as a second line of defense.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp                 TEXT NOT NULL,
    event                     TEXT NOT NULL,   -- e.g. "discovery.attempt"
    scope_file                TEXT NOT NULL,
    scope_hash                TEXT,            -- NULL when the file was missing
    authorization_acknowledged INTEGER NOT NULL DEFAULT 0,
    target_count              INTEGER NOT NULL DEFAULT 0,
    decision                  TEXT NOT NULL CHECK (decision IN ('allow','deny')),
    reason                    TEXT NOT NULL DEFAULT ''
);

DROP TRIGGER IF EXISTS audit_log_no_update;
CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is immutable: UPDATE not permitted');
END;

DROP TRIGGER IF EXISTS audit_log_no_delete;
CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is immutable: DELETE not permitted');
END;

-- ----------------------------------------------------------------------------
-- validations: one row per controlled validation of a finding (V0.3).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS validations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    timestamp     TEXT NOT NULL,           -- ISO-8601 UTC
    checks        TEXT NOT NULL DEFAULT '[]', -- JSON array of check names
    results       TEXT NOT NULL DEFAULT '[]', -- JSON array of check results
    outcome       TEXT NOT NULL CHECK (outcome IN
                    ('confirmed','false-positive','intel','inconclusive')),
    status_before TEXT NOT NULL DEFAULT 'suspected',
    status_after  TEXT NOT NULL DEFAULT 'suspected'
);
CREATE INDEX IF NOT EXISTS idx_validations_finding ON validations(finding_id);

-- ----------------------------------------------------------------------------
-- finding_events: append-only lifecycle timeline per finding (V0.4).
-- Every status transition (operator, retest, or validation-driven) and every
-- retest attempt is recorded here. Application code must never UPDATE or
-- DELETE rows here; the triggers below enforce that like audit_log.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finding_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    timestamp     TEXT NOT NULL,           -- ISO-8601 UTC
    event         TEXT NOT NULL CHECK (event IN
                    ('status_changed','retest','note')),
    old_status    TEXT NOT NULL,
    new_status    TEXT NOT NULL,
    actor         TEXT NOT NULL CHECK (actor IN
                    ('operator','retest','system')),
    detail        TEXT NOT NULL DEFAULT '{}' -- JSON: notes, retest summary, ...
);
CREATE INDEX IF NOT EXISTS idx_finding_events_finding
    ON finding_events(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_events_ts
    ON finding_events(timestamp);

DROP TRIGGER IF EXISTS finding_events_no_update;
CREATE TRIGGER finding_events_no_update
BEFORE UPDATE ON finding_events
BEGIN
    SELECT RAISE(ABORT, 'finding_events is immutable: UPDATE not permitted');
END;

DROP TRIGGER IF EXISTS finding_events_no_delete;
CREATE TRIGGER finding_events_no_delete
BEFORE DELETE ON finding_events
BEGIN
    SELECT RAISE(ABORT, 'finding_events is immutable: DELETE not permitted');
END;

-- ----------------------------------------------------------------------------
-- finding_snapshots: point-in-time counts for trend tracking (V0.4).
-- One row per (status, severity) per snapshot batch; written automatically
-- when a discovery run completes and after every retest batch.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finding_snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,              -- ISO-8601 UTC of the snapshot
    run_id     INTEGER,                    -- discovery run id, or NULL
    status     TEXT NOT NULL,
    severity   TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_finding_snapshots_ts
    ON finding_snapshots(timestamp);

-- ----------------------------------------------------------------------------
-- settings: key/value store for operator configuration (scheduler, etc.).
-- Values are JSON. Written only by explicit operator/API actions.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,   -- JSON
    updated_at  TEXT NOT NULL    -- ISO-8601 UTC
);

-- ----------------------------------------------------------------------------
-- external_workers: registered outside-in workers (V0.5).
-- The token itself is NEVER stored: only its sha256 hash (token_hash), and
-- the plaintext token is returned once at registration. Revoke sets
-- revoked=1; token checks fail immediately afterwards.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS external_workers (
    id          TEXT PRIMARY KEY,          -- uuid4 hex
    name        TEXT NOT NULL,             -- operator label, e.g. "pi-at-moms"
    token_hash  TEXT NOT NULL UNIQUE,      -- sha256 hex of the worker token
    created_at  TEXT NOT NULL,             -- ISO-8601 UTC
    last_seen   TEXT,                      -- ISO-8601 UTC of last poll/ingest
    revoked     INTEGER NOT NULL DEFAULT 0,
    revoked_at  TEXT
);

-- ----------------------------------------------------------------------------
-- external_assessments: queued outside-in assessment runs (V0.5).
-- targets/probes are JSON arrays. Findings produced by ingest live in the
-- normal findings/evidence tables (collector "external.<probe>").
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS external_assessments (
    id          TEXT PRIMARY KEY,          -- uuid4 hex
    worker_id   TEXT NOT NULL REFERENCES external_workers(id),
    targets     TEXT NOT NULL DEFAULT '[]', -- JSON array of target strings
    probes      TEXT NOT NULL DEFAULT '[]', -- JSON array of probe names
    ports       TEXT NOT NULL DEFAULT '[]', -- JSON array of ports (optional
                                           -- override; empty = probe default)
    status      TEXT NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','running','completed','failed',
                                 'cancelled')),
    created_at  TEXT NOT NULL,             -- ISO-8601 UTC
    started_at  TEXT,                      -- ISO-8601 UTC
    finished_at TEXT,                      -- ISO-8601 UTC
    summary     TEXT NOT NULL DEFAULT '{}' -- JSON: findings_created, ...
);
CREATE INDEX IF NOT EXISTS idx_ext_assess_worker
    ON external_assessments(worker_id);
CREATE INDEX IF NOT EXISTS idx_ext_assess_status
    ON external_assessments(status);
