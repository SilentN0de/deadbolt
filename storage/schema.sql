-- ============================================================================
-- Local-First Security Assessment Platform — SQLite schema (V0.1)
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
