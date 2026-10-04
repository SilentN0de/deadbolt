"""Retest orchestration (V0.4).

`retest_finding` re-runs the applicable read-only validation probes against
a finding's target *as it is right now* and reconciles the result with the
stored finding:

  still present  -> event `re-observed` (status unchanged; last_seen bumped),
                    or `fixed` -> `confirmed` regression
  gone           -> event `remediated`, transition confirmed/suspected -> fixed
  probe error    -> event `inconclusive`, status unchanged

Every retest appends to the finding's `retest_history` JSON and writes one
row to the append-only `finding_events` table. Retest-driven status changes
go through the lifecycle state machine with actor="retest".

Same safety posture as validation: single-finding or explicit batch,
read-only probes only, scope-enforced, fully audited.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from agent.scope import ScopeError
from common.logging_setup import utc_now_iso
from lifecycle import transition_finding
from storage.db import Store, sha256_file, sha256_text
from storage.models import STATUSES, AuditEntry, Evidence, FindingEvent
from validator.checks import TLS_PORTS
# Shared read-only probe pipeline (same helpers validation uses).
from validator.runner import (_derive_outcome, _enforce_scope, _host_port,
                              _run_checks)

log = logging.getLogger("deadbolt.retest")

DEFAULT_SCOPE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "config", "authorized_targets.yaml")

# "Open" statuses retested by default in a batch.
OPEN_STATUSES = ("suspected", "confirmed")


class RetestError(Exception):
    """Raised when a retest cannot run (missing finding, bad filter)."""


def select_retest_checks(port: Optional[int]) -> List[str]:
    """Checks applicable to a finding, based on its type (port)."""
    if port is None:
        return []  # nothing to probe against: inconclusive
    checks = ["tcp_reprobe", "banner_intel"]
    if port in TLS_PORTS:
        checks.insert(1, "tls_certificate")
    return checks


def _verdicts(results) -> Dict[str, str]:
    return {r.check: r.verdict for r in results}


def retest_finding(store: Store, finding_id: str,
                   scope_path: str = DEFAULT_SCOPE) -> Dict:
    """Re-probe one finding against the target's current state.

    Returns a per-finding result dict with event, old/new status, and a
    summary. Raises RetestError (unknown finding) or ScopeError
    (target outside the authorized scope).
    """
    finding = store.get_finding(finding_id)
    if finding is None:
        raise RetestError(f"finding not found: {finding_id}")

    host, port = _host_port(finding)
    old_status = finding.status
    timestamp = utc_now_iso()
    decision = _enforce_scope(host, scope_path, store, event="retest.attempt")

    checks = select_retest_checks(port)
    results = _run_checks(host, port, checks)
    finished = utc_now_iso()

    # Each probe result becomes evidence on the finding (same pattern as
    # validation: one immutable row per probe).
    for r in results:
        raw = r.summary
        store.add_evidence(Evidence(
            id=None, finding_id=finding.id, timestamp=finished,
            collector=f"retest.{r.check}",
            excerpt=raw[:512], excerpt_hash=sha256_text(raw),
            detail={"check": r.check, "ok": r.ok, "verdict": r.verdict,
                    **r.detail},
        ))

    outcome = _derive_outcome(results)
    tcp_verdict = _verdicts(results).get("tcp_reprobe")
    new_status = old_status

    if not checks or outcome == "inconclusive" or tcp_verdict == "inconclusive":
        event = "inconclusive"
        summary = (f"retest of {host}:{port} was inconclusive — "
                   "status unchanged.")
    elif tcp_verdict == "contradicted":
        # Service is gone.
        if old_status in ("confirmed", "suspected"):
            event = "remediated"
            summary = (f"{host}:{port} no longer responds — "
                       "finding remediated.")
            transition_finding(store, finding.id, "fixed", actor="retest",
                               note=summary)
            new_status = "fixed"
        elif old_status == "fixed":
            event = "still-fixed"
            summary = f"{host}:{port} still closed — remains fixed."
        else:  # accepted-risk / false-positive: terminal states stand
            event = "not-present"
            summary = (f"{host}:{port} not present; status "
                       f"{old_status} unchanged.")
    else:  # tcp_verdict == "confirmed" (still present)
        event = "re-observed"
        if old_status == "fixed":
            summary = (f"{host}:{port} is back — regression of a fixed "
                       "finding.")
            transition_finding(store, finding.id, "confirmed",
                               actor="retest", note=summary)
            new_status = "confirmed"
        else:
            summary = (f"{host}:{port} still open — finding re-observed.")
    # Every retest lands in retest_history with its own event name. When a
    # transition happened, transition_finding already recorded the
    # lifecycle entry too — both are kept: one says what the probe saw,
    # the other says how the status changed.
    store.append_retest_event(
        finding.id,
        {"timestamp": finished, "event": event, "detail": summary},
        last_seen=finished if (event == "re-observed"
                               and new_status == old_status) else None)

    store.add_finding_event(FindingEvent(
        id=None, finding_id=finding.id, timestamp=finished,
        event="retest", old_status=old_status, new_status=new_status,
        actor="retest",
        detail={"retest_event": event, "summary": summary,
                "outcome": outcome}))

    store.audit(AuditEntry(
        id=None, timestamp=finished, event="retest.attempt",
        scope_file=os.path.abspath(scope_path),
        scope_hash=sha256_file(scope_path),
        authorization_acknowledged=decision.authorization_acknowledged,
        target_count=1,
        decision="allow",
        reason=f"retested finding {finding.id} ({host}:{port}): {event}"))

    log.info("retested finding %s: %s (%s -> %s)",
             finding.id, event, old_status, new_status)
    return {
        "finding_id": finding.id,
        "event": event,
        "old_status": old_status,
        "new_status": new_status,
        "summary": summary,
        "timestamp": finished,
        "results": [{"check": r.check, "ok": r.ok, "verdict": r.verdict,
                     "summary": r.summary} for r in results],
    }


def retest_all(store: Store, status_filter: Optional[str] = None,
               scope_path: str = DEFAULT_SCOPE) -> Dict:
    """Retest every finding matching the filter (default: open findings).

    Records a trend snapshot when the batch completes. Per-finding errors
    are captured in the results instead of aborting the batch.
    """
    if status_filter in (None, "open"):
        statuses: List[str] = list(OPEN_STATUSES)
    elif status_filter in STATUSES:
        statuses = [status_filter]
    else:
        raise RetestError(
            f"invalid status filter {status_filter!r}; use 'open' or one of "
            f"{list(STATUSES)}")

    findings = []
    for s in statuses:
        findings.extend(store.list_findings(status=s))

    results = []
    for f in findings:
        try:
            results.append(retest_finding(store, f.id, scope_path=scope_path))
        except (RetestError, ScopeError) as exc:
            log.warning("retest of finding %s failed: %s", f.id, exc)
            results.append({
                "finding_id": f.id,
                "event": "error",
                "old_status": f.status,
                "new_status": f.status,
                "summary": str(exc),
                "timestamp": utc_now_iso(),
                "results": [],
            })

    snapshot_at = utc_now_iso()
    store.record_snapshot(snapshot_at)
    log.info("retest batch done: %d findings, snapshot at %s",
             len(results), snapshot_at)
    return {"results": results, "snapshot_at": snapshot_at}
