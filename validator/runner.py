"""Validation orchestration (V0.3).

`validate_finding` runs read-only checks against ONE finding's host:port:

  1. finding must exist
  2. host must be inside the authorized scope (else: audit deny + ScopeError)
  3. requested checks run with timeouts; each result becomes evidence
  4. a validation record is stored; finding status may transition:
       suspected -> confirmed      (re-probe still sees the open port)
       suspected -> false-positive (re-probe now refused: service is gone)
  5. every attempt is audit-logged (allow or deny)

Controlled by design: single-finding, operator-triggered, read-only,
rate-limited by the API layer, and fully audited.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Dict, List, Optional

from agent.scope import ScopeError, load_scope
from common.logging_setup import utc_now_iso
from storage.db import Store, sha256_file, sha256_text
from storage.models import AuditEntry, Evidence, Finding, FindingEvent, Validation

from .checks import (CheckResult, banner_intel, tcp_reprobe, tls_certificate,
                     TLS_PORTS)

log = logging.getLogger("secplatform.validator")

_OPEN_PORT_RE = re.compile(r"Open port (\d+)/tcp")
DEFAULT_SCOPE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "config", "authorized_targets.yaml")

ALL_CHECKS = ("tcp_reprobe", "tls_certificate", "banner_intel")


class ValidationError(Exception):
    """Raised when a validation cannot run (missing finding, bad checks)."""


def _host_port(finding: Finding) -> tuple[str, Optional[int]]:
    """Best-effort (host, port) for a finding: evidence detail, then title."""
    for ev in finding.evidence:
        d = ev.detail or {}
        if d.get("host") and d.get("port"):
            try:
                return str(d["host"]), int(d["port"])
            except (TypeError, ValueError):
                pass
    m = _OPEN_PORT_RE.search(finding.title or "")
    port = int(m.group(1)) if m else None
    return finding.target, port


def _enforce_scope(host: str, scope_path: str, store: Store,
                   event: str = "validation.attempt"):
    """Raise ScopeError (after audit-deny) unless host is scope-authorized.
    Returns the ScopeDecision on allow."""
    started = utc_now_iso()
    try:
        decision = load_scope(scope_path)
    except ScopeError as exc:
        store.audit(AuditEntry(
            id=None, timestamp=started, event=event,
            scope_file=os.path.abspath(scope_path), scope_hash=None,
            authorization_acknowledged=False, target_count=0,
            decision="deny", reason=str(exc)))
        raise
    if host not in decision.targets:
        reason = (f"validation target {host} is not in the authorized scope "
                  f"({scope_path})")
        store.audit(AuditEntry(
            id=None, timestamp=started, event=event,
            scope_file=os.path.abspath(scope_path),
            scope_hash=sha256_file(scope_path),
            authorization_acknowledged=decision.authorization_acknowledged,
            target_count=len(decision.targets),
            decision="deny", reason=reason))
        raise ScopeError(reason + ". Refusing to validate.")
    log.info("validation scope allow: %s in authorized scope", host)
    return decision


def _run_checks(host: str, port: Optional[int],
                checks: List[str]) -> List[CheckResult]:
    results: List[CheckResult] = []
    banner = ""
    for name in checks:
        if name == "tcp_reprobe":
            if port is None:
                results.append(CheckResult(
                    name, False, "inconclusive",
                    "tcp_reprobe needs a port; none could be determined.", {}))
                continue
            r = tcp_reprobe(host, port)
            banner = r.detail.get("banner", "") or banner
            results.append(r)
        elif name == "tls_certificate":
            # Explicitly requested: attempt the handshake on whatever port was
            # given. (Default check selection only adds this for TLS_PORTS.)
            if port is None:
                results.append(CheckResult(
                    name, False, "inconclusive",
                    "tls_certificate needs a port; none could be determined.",
                    {}))
                continue
            results.append(tls_certificate(host, port))
        elif name == "banner_intel":
            results.append(banner_intel(banner))
        else:
            raise ValidationError(f"unknown check: {name!r}")
    return results


def _derive_outcome(results: List[CheckResult]) -> str:
    verdicts = {r.check: r.verdict for r in results if r.ok}
    if verdicts.get("tcp_reprobe") == "contradicted":
        return "false-positive"
    if verdicts.get("tcp_reprobe") == "confirmed":
        return "confirmed"
    if not any(r.ok for r in results):
        return "inconclusive"
    return "intel"


def validate_finding(store: Store, finding_id: str,
                     checks: Optional[List[str]] = None,
                     scope_path: str = DEFAULT_SCOPE) -> Dict:
    """Validate one finding. Returns the stored validation as a dict."""
    finding = store.get_finding(finding_id)
    if finding is None:
        raise ValidationError(f"finding not found: {finding_id}")

    host, port = _host_port(finding)
    started = utc_now_iso()
    decision = _enforce_scope(host, scope_path, store)

    if checks is None:
        checks = ["tcp_reprobe", "banner_intel"]
        if port in TLS_PORTS:
            checks.insert(1, "tls_certificate")
    for c in checks:
        if c not in ALL_CHECKS:
            raise ValidationError(
                f"unknown check {c!r}; allowed: {list(ALL_CHECKS)}")

    started = utc_now_iso()
    results = _run_checks(host, port, checks)
    outcome = _derive_outcome(results)
    finished = utc_now_iso()

    # Each check result becomes evidence on the finding.
    for r in results:
        raw = r.summary
        store.add_evidence(Evidence(
            id=None, finding_id=finding.id, timestamp=finished,
            collector=f"validator.{r.check}",
            excerpt=raw[:512], excerpt_hash=sha256_text(raw),
            detail={"check": r.check, "ok": r.ok, "verdict": r.verdict,
                    **r.detail},
        ))

    # Status transitions (only out of 'suspected').
    status_before = finding.status
    status_after = status_before
    if status_before == "suspected":
        if outcome == "confirmed":
            status_after = "confirmed"
        elif outcome == "false-positive":
            status_after = "false-positive"
    if status_after != status_before:
        store.update_finding_status(
            finding.id, status_after,
            event=f"validation:{outcome}",
            timestamp=finished)
        # Keep the append-only lifecycle timeline complete.
        store.add_finding_event(FindingEvent(
            id=None, finding_id=finding.id, timestamp=finished,
            event="status_changed", old_status=status_before,
            new_status=status_after, actor="system",
            detail={"via": "validation", "outcome": outcome}))

    validation = Validation(
        id=None, finding_id=finding.id, timestamp=finished,
        checks=list(checks),
        results=[{"check": r.check, "ok": r.ok, "verdict": r.verdict,
                  "summary": r.summary, "detail": r.detail} for r in results],
        outcome=outcome, status_before=status_before, status_after=status_after,
    )
    vid = store.add_validation(validation)

    store.audit(AuditEntry(
        id=None, timestamp=finished, event="validation.attempt",
        scope_file=os.path.abspath(scope_path),
        scope_hash=sha256_file(scope_path),
        authorization_acknowledged=decision.authorization_acknowledged,
        target_count=1,
        decision="allow",
        reason=f"validated finding {finding.id} ({host}:{port}): {outcome}"))

    log.info("validated finding %s: %s (%s -> %s)",
             finding.id, outcome, status_before, status_after)
    return {**validation.to_dict(), "id": vid}
