"""SQLite storage layer (stdlib sqlite3, WAL mode).

Owns: schema init, findings upsert (dedupe on (target, title)), evidence
append, run tracking, and the immutable audit log.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from .models import (AuditEntry, Evidence, Finding, FindingEvent, Run,
                     STATUSES, Validation, dumps, loads)
from common.logging_setup import utc_now_iso

_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


def _connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


class Store:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = _connect(db_path)
        self.init_schema()

    def init_schema(self) -> None:
        # Migration pattern: schema.sql is idempotent (CREATE TABLE/INDEX
        # IF NOT EXISTS, DROP TRIGGER IF EXISTS), so re-executing it on
        # every Store() init automatically upgrades existing findings.db
        # files — new tables appear, old data is untouched.
        with open(_SCHEMA_PATH, "r", encoding="utf-8") as fh:
            self._conn.executescript(fh.read())
        self._conn.commit()
        self._ensure_columns()

    def _ensure_columns(self) -> None:
        """Column-level migrations for tables that already exist.

        CREATE TABLE IF NOT EXISTS never adds a column to an existing
        table, so new columns on shipped tables are added here.
        """
        existing = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(external_assessments)").fetchall()}
        if existing and "ports" not in existing:
            self._conn.execute(
                "ALTER TABLE external_assessments "
                "ADD COLUMN ports TEXT NOT NULL DEFAULT '[]'")
            self._conn.commit()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def close(self) -> None:
        self._conn.close()

    # -- findings -----------------------------------------------------------
    def upsert_finding(self, finding: Finding) -> Finding:
        """Insert or refresh a finding deduped on (target, title).

        On re-observation: last_seen is updated and a retest event is appended.
        Returns the stored finding (with its stable id).
        """
        with self._tx() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE target = ? AND title = ?",
                (finding.target, finding.title),
            ).fetchone()
            if row is None:
                conn.execute(
                    """INSERT INTO findings
                       (id, target, title, severity, status, first_seen, last_seen,
                        remediation, retest_history)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        finding.id,
                        finding.target,
                        finding.title,
                        finding.severity,
                        finding.status,
                        finding.first_seen,
                        finding.last_seen,
                        finding.remediation,
                        dumps(finding.retest_history),
                    ),
                )
                return finding
            # Re-observed: refresh last_seen, keep the stronger severity, log retest.
            history = loads(row["retest_history"])
            if isinstance(history, dict):  # defensive: never store dicts
                history = [history]
            history.append(
                {
                    "timestamp": finding.last_seen,
                    "event": "re-observed",
                    "severity": finding.severity,
                }
            )
            sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            severity = (
                finding.severity
                if sev_rank[finding.severity] > sev_rank[row["severity"]]
                else row["severity"]
            )
            conn.execute(
                """UPDATE findings
                   SET last_seen = ?, severity = ?, retest_history = ?
                   WHERE id = ?""",
                (finding.last_seen, severity, dumps(history), row["id"]),
            )
            stored = self.get_finding(row["id"])
            assert stored is not None
            return stored

    def add_evidence(self, evidence: Evidence) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                """INSERT INTO evidence
                   (finding_id, timestamp, collector, excerpt, excerpt_hash, detail)
                   VALUES (?,?,?,?,?,?)""",
                (
                    evidence.finding_id,
                    evidence.timestamp,
                    evidence.collector,
                    evidence.excerpt,
                    evidence.excerpt_hash,
                    dumps(evidence.detail),
                ),
            )
            return int(cur.lastrowid)

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        row = self._conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_finding(row)

    def list_findings(
        self,
        target: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Finding]:
        query = "SELECT * FROM findings"
        clauses, params = [], []
        if target:
            clauses.append("target = ?")
            params.append(target)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY last_seen DESC"
        return [self._row_to_finding(r) for r in self._conn.execute(query, params)]

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        ev_rows = self._conn.execute(
            "SELECT * FROM evidence WHERE finding_id = ? ORDER BY id", (row["id"],)
        ).fetchall()
        history = loads(row["retest_history"])
        if not isinstance(history, list):
            history = []
        return Finding(
            id=row["id"],
            target=row["target"],
            title=row["title"],
            severity=row["severity"],
            status=row["status"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            remediation=row["remediation"],
            retest_history=history,
            evidence=[
                Evidence(
                    id=e["id"],
                    finding_id=e["finding_id"],
                    timestamp=e["timestamp"],
                    collector=e["collector"],
                    excerpt=e["excerpt"],
                    excerpt_hash=e["excerpt_hash"],
                    detail=loads(e["detail"]) if e["detail"] else {},
                )
                for e in ev_rows
            ],
        )

    # -- validations (V0.3) -------------------------------------------------
    def add_validation(self, validation: Validation) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                """INSERT INTO validations
                   (finding_id, timestamp, checks, results, outcome,
                    status_before, status_after)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    validation.finding_id,
                    validation.timestamp,
                    dumps(validation.checks),
                    dumps(validation.results),
                    validation.outcome,
                    validation.status_before,
                    validation.status_after,
                ),
            )
            return int(cur.lastrowid)

    def list_validations(self, finding_id: str) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM validations WHERE finding_id = ? ORDER BY id",
            (finding_id,),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["checks"] = loads(d["checks"])
            d["results"] = loads(d["results"])
            out.append(d)
        return out

    def update_finding_status(self, finding_id: str, status: str,
                              event: str = "", timestamp: str = "") -> None:
        """Transition a finding's status and record the event in retest_history."""
        if status not in STATUSES:
            raise ValueError(f"invalid status: {status!r}")
        with self._tx() as conn:
            row = conn.execute(
                "SELECT retest_history FROM findings WHERE id = ?",
                (finding_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"finding not found: {finding_id}")
            history = loads(row["retest_history"])
            if not isinstance(history, list):
                history = []
            history.append({"timestamp": timestamp, "event": event,
                            "status": status})
            conn.execute(
                "UPDATE findings SET status = ?, retest_history = ? WHERE id = ?",
                (status, dumps(history), finding_id),
            )

    # -- finding lifecycle events + trend snapshots (V0.4) ------------------
    def add_finding_event(self, event: FindingEvent) -> int:
        """Append one lifecycle event. finding_events is append-only."""
        with self._tx() as conn:
            cur = conn.execute(
                """INSERT INTO finding_events
                   (finding_id, timestamp, event, old_status, new_status,
                    actor, detail)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    event.finding_id,
                    event.timestamp,
                    event.event,
                    event.old_status,
                    event.new_status,
                    event.actor,
                    dumps(event.detail),
                ),
            )
            return int(cur.lastrowid)

    def list_finding_events(self, finding_id: str,
                            limit: int = 200) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM finding_events WHERE finding_id = ? "
            "ORDER BY id LIMIT ?",
            (finding_id, limit),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = loads(d["detail"]) if d["detail"] else {}
            out.append(d)
        return out

    def record_snapshot(self, timestamp: str,
                        run_id: Optional[int] = None) -> int:
        """Write one point-in-time count per (status, severity).

        Called automatically when a discovery run completes and after every
        retest batch. Returns the number of snapshot rows written.
        """
        rows = self._conn.execute(
            "SELECT status, severity, COUNT(*) AS n FROM findings "
            "GROUP BY status, severity"
        ).fetchall()
        with self._tx() as conn:
            for r in rows:
                conn.execute(
                    """INSERT INTO finding_snapshots
                       (timestamp, run_id, status, severity, count)
                       VALUES (?,?,?,?,?)""",
                    (timestamp, run_id, r["status"], r["severity"],
                     r["n"]),
                )
        return len(rows)

    def list_snapshots(self, since: str,
                       limit: int = 10000) -> List[Dict[str, Any]]:
        """Raw snapshot rows at/after `since` (ISO-8601 UTC), oldest first."""
        rows = self._conn.execute(
            "SELECT * FROM finding_snapshots WHERE timestamp >= ? "
            "ORDER BY timestamp ASC, id ASC LIMIT ?",
            (since, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    # -- settings ---------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Read a JSON setting. Returns `default` when unset or corrupt."""
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return loads(row["value"])
        except Exception:
            return default

    def set_setting(self, key: str, value: Any) -> None:
        """Write a JSON setting (upsert)."""
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO settings (key, value, updated_at)
                   VALUES (?,?,?)
                   ON CONFLICT(key) DO UPDATE SET
                     value = excluded.value,
                     updated_at = excluded.updated_at""",
                (key, dumps(value), utc_now_iso()),
            )

    def append_retest_event(self, finding_id: str, event: Dict[str, Any],
                            last_seen: Optional[str] = None) -> None:
        """Append an entry to a finding's retest_history JSON.

        Optionally refreshes last_seen (used on re-observation). Does not
        change the finding's status; use update_finding_status for that.
        """
        with self._tx() as conn:
            row = conn.execute(
                "SELECT retest_history FROM findings WHERE id = ?",
                (finding_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"finding not found: {finding_id}")
            history = loads(row["retest_history"])
            if not isinstance(history, list):
                history = []
            history.append(event)
            if last_seen is not None:
                conn.execute(
                    "UPDATE findings SET retest_history = ?, last_seen = ? "
                    "WHERE id = ?",
                    (dumps(history), last_seen, finding_id),
                )
            else:
                conn.execute(
                    "UPDATE findings SET retest_history = ? WHERE id = ?",
                    (dumps(history), finding_id),
                )

    # -- runs ---------------------------------------------------------------
    def create_run(self, run: Run) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                """INSERT INTO runs
                   (started_at, finished_at, scope_file, scope_hash, scope_targets,
                    authorization_acknowledged, target_count, status, summary)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    run.started_at,
                    run.finished_at,
                    run.scope_file,
                    run.scope_hash,
                    dumps(run.scope_targets),
                    int(run.authorization_acknowledged),
                    run.target_count,
                    run.status,
                    dumps(run.summary),
                ),
            )
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str, summary: Dict[str, Any],
                   finished_at: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE runs SET status = ?, summary = ?, finished_at = ? WHERE id = ?",
                (status, dumps(summary), finished_at, run_id),
            )

    def list_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["scope_targets"] = loads(d["scope_targets"])
            d["summary"] = loads(d["summary"]) if d["summary"] else {}
            d["authorization_acknowledged"] = bool(d["authorization_acknowledged"])
            out.append(d)
        return out

    # -- audit log (append-only) --------------------------------------------
    def audit(self, entry: AuditEntry) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                """INSERT INTO audit_log
                   (timestamp, event, scope_file, scope_hash,
                    authorization_acknowledged, target_count, decision, reason)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    entry.timestamp,
                    entry.event,
                    entry.scope_file,
                    entry.scope_hash,
                    int(entry.authorization_acknowledged),
                    entry.target_count,
                    entry.decision,
                    entry.reason,
                ),
            )
            return int(cur.lastrowid)

    def list_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # -- external workers + assessments (V0.5) --------------------------------
    def create_worker(self, worker_id: str, name: str,
                      token_hash: str) -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO external_workers
                   (id, name, token_hash, created_at, revoked)
                   VALUES (?,?,?,?,0)""",
                (worker_id, name, token_hash, utc_now_iso()),
            )

    def get_worker(self, worker_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT id, name, created_at, last_seen, revoked, revoked_at "
            "FROM external_workers WHERE id = ?", (worker_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["revoked"] = bool(d["revoked"])
        return d

    def get_worker_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        # NOTE: token hashes never leave this method's caller as plaintext
        # tokens; the API layer only ever sees the worker identity.
        row = self._conn.execute(
            "SELECT id, name, created_at, last_seen, revoked, revoked_at "
            "FROM external_workers WHERE token_hash = ?",
            (token_hash,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["revoked"] = bool(d["revoked"])
        return d

    def list_workers(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, name, created_at, last_seen, revoked, revoked_at "
            "FROM external_workers ORDER BY created_at").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["revoked"] = bool(d["revoked"])
            out.append(d)
        return out

    def revoke_worker(self, worker_id: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE external_workers SET revoked = 1, revoked_at = ? "
                "WHERE id = ?", (utc_now_iso(), worker_id))

    def touch_worker(self, worker_id: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE external_workers SET last_seen = ? WHERE id = ?",
                (utc_now_iso(), worker_id))

    def create_assessment(self, assessment_id: str, worker_id: str,
                          targets: List[str], probes: List[str],
                          ports: Optional[List[int]] = None) -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO external_assessments
                   (id, worker_id, targets, probes, ports, status, created_at)
                   VALUES (?,?,?,?,?, 'queued', ?)""",
                (assessment_id, worker_id, dumps(targets), dumps(probes),
                 dumps(ports or []), utc_now_iso()),
            )

    def get_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM external_assessments WHERE id = ?",
            (assessment_id,)).fetchone()
        if row is None:
            return None
        return self._assessment_dict(row)

    def list_assessments(self, worker_id: Optional[str] = None,
                         status: Optional[str] = None,
                         limit: int = 100) -> List[Dict[str, Any]]:
        query = "SELECT * FROM external_assessments"
        clauses, params = [], []
        if worker_id:
            clauses.append("worker_id = ?")
            params.append(worker_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [self._assessment_dict(r)
                for r in self._conn.execute(query, params)]

    def update_assessment(self, assessment_id: str, status: str,
                          started_at: Optional[str] = None,
                          finished_at: Optional[str] = None,
                          summary: Optional[Dict[str, Any]] = None) -> None:
        if status not in ("queued", "running", "completed", "failed",
                          "cancelled"):
            raise ValueError(f"invalid assessment status: {status!r}")
        with self._tx() as conn:
            if summary is not None:
                conn.execute(
                    "UPDATE external_assessments SET status = ?, "
                    "started_at = COALESCE(?, started_at), "
                    "finished_at = COALESCE(?, finished_at), summary = ? "
                    "WHERE id = ?",
                    (status, started_at, finished_at, dumps(summary),
                     assessment_id))
            else:
                conn.execute(
                    "UPDATE external_assessments SET status = ?, "
                    "started_at = COALESCE(?, started_at), "
                    "finished_at = COALESCE(?, finished_at) WHERE id = ?",
                    (status, started_at, finished_at, assessment_id))

    @staticmethod
    def _assessment_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["targets"] = loads(d["targets"])
        d["probes"] = loads(d["probes"])
        d["ports"] = loads(d["ports"]) if d.get("ports") else []
        d["summary"] = loads(d["summary"]) if d["summary"] else {}
        return d


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
