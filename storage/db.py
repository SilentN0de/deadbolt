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

from .models import (AuditEntry, Evidence, Finding, Run, STATUSES, Validation,
                     dumps, loads)

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
        with open(_SCHEMA_PATH, "r", encoding="utf-8") as fh:
            self._conn.executescript(fh.read())
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


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
