"""External-assessment server logic (V0.5).

Worker registry + token auth, assessment queue, and result ingest.
Findings enter the same lifecycle machine as local findings
(`suspected` -> ...) with full evidence and finding_events.

Safety posture (mirrors validator/retest):
  - off by default: `external.enabled` setting gates enqueue, worker poll,
    and result ingest (kill switch)
  - scope guard: every target must resolve inside the operator-approved
    scope file, else 400 (deny is audit-logged)
  - worker tokens: long random, stored as sha256 hash, returned once at
    registration, dead immediately on revoke
  - rate limit: per-worker enqueue cooldown
  - every step audit-logged (allow and deny)
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional

from agent.discovery import PORTS as PORT_LABELS
from agent.scope import ScopeError, load_scope
from common.logging_setup import utc_now_iso
from storage.db import Store, sha256_file, sha256_text
from storage.models import AuditEntry, Evidence, Finding, FindingEvent

from .probes import ALL_PROBES

log = logging.getLogger("deadbolt.external.server")

DEFAULT_SCOPE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "config", "authorized_targets.yaml")

# Settings keys.
KEY_ENABLED = "external.enabled"      # bool, default False (kill switch)

# Per-worker cooldown between enqueued assessments (seconds).
ENQUEUE_COOLDOWN = 60.0
_last_enqueue: Dict[str, float] = {}

# Token: 48 bytes -> ~64 printable chars. Stored as sha256 hex, never plaintext.
TOKEN_BYTES = 48


class ExternalError(Exception):
    """Raised for external-assessment request errors (carries HTTP status)."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def is_enabled(store: Store) -> bool:
    return bool(store.get_setting(KEY_ENABLED, False))


def set_enabled(store: Store, enabled: bool, actor: str = "operator") -> bool:
    """Flip the kill switch. Audit-logged. Returns the new state."""
    store.set_setting(KEY_ENABLED, bool(enabled))
    store.audit(AuditEntry(
        id=None, timestamp=utc_now_iso(), event="external.toggle",
        scope_file="", scope_hash=None, authorization_acknowledged=False,
        target_count=0, decision="allow",
        reason=f"external assessments {'enabled' if enabled else 'disabled'} "
               f"by {actor}"))
    log.info("external assessments %s by %s",
             "enabled" if enabled else "disabled", actor)
    return bool(enabled)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# worker registry
# ---------------------------------------------------------------------------

def register_worker(store: Store, name: str) -> Dict[str, Any]:
    """Register a worker. Returns id + token; the token is shown ONCE —
    only its hash is stored."""
    name = (name or "").strip()
    if not name:
        raise ExternalError(400, "worker name must not be empty")
    if len(name) > 80:
        raise ExternalError(400, "worker name too long (max 80 chars)")
    token = secrets.token_urlsafe(TOKEN_BYTES)
    worker_id = uuid.uuid4().hex
    store.create_worker(worker_id=worker_id, name=name,
                        token_hash=_hash_token(token))
    store.audit(AuditEntry(
        id=None, timestamp=utc_now_iso(), event="external.worker_register",
        scope_file="", scope_hash=None, authorization_acknowledged=False,
        target_count=0, decision="allow",
        reason=f"registered worker {worker_id} ({name})"))
    log.info("registered external worker %s (%s)", worker_id, name)
    return {"id": worker_id, "name": name, "token": token,
            "created_at": utc_now_iso()}


def revoke_worker(store: Store, worker_id: str) -> Dict[str, Any]:
    """Revoke a worker: its token dies immediately. Audit-logged."""
    worker = store.get_worker(worker_id)
    if worker is None:
        raise ExternalError(404, f"worker not found: {worker_id}")
    if worker["revoked"]:
        return {"id": worker_id, "revoked": True, "already": True}
    store.revoke_worker(worker_id)
    store.audit(AuditEntry(
        id=None, timestamp=utc_now_iso(), event="external.worker_revoke",
        scope_file="", scope_hash=None, authorization_acknowledged=False,
        target_count=0, decision="allow",
        reason=f"revoked worker {worker_id} ({worker['name']})"))
    log.info("revoked external worker %s", worker_id)
    return {"id": worker_id, "revoked": True}


def authenticate_worker(store: Store, token: str) -> Dict[str, Any]:
    """Token auth for worker endpoints. Returns the worker row or raises 401."""
    if not token:
        raise ExternalError(401, "missing worker token")
    worker = store.get_worker_by_token_hash(_hash_token(token))
    if worker is None or worker["revoked"]:
        raise ExternalError(401, "invalid or revoked worker token")
    return worker


# ---------------------------------------------------------------------------
# assessment queue
# ---------------------------------------------------------------------------

def _enforce_targets(targets: List[str], scope_path: str,
                     store: Store) -> None:
    """Every target must be operator-authorized. 400 (deny logged) on the
    first out-of-scope target.

    IP targets must resolve inside the scope file's authorized networks
    (via agent.scope.load_scope). Domain targets (for the dns_exposure
    probe) must be listed under the scope file's top-level
    `external_domains:` key with `authorized: true` — local discovery
    ignores that key, so core scope enforcement is untouched.
    """
    import ipaddress

    import yaml

    started = utc_now_iso()

    def _deny(reason: str) -> ExternalError:
        try:
            scope_hash = sha256_file(scope_path)
        except OSError:
            scope_hash = None
        store.audit(AuditEntry(
            id=None, timestamp=started, event="external.enqueue",
            scope_file=os.path.abspath(scope_path), scope_hash=scope_hash,
            authorization_acknowledged=False,
            target_count=len(targets),
            decision="deny", reason=reason))
        return ExternalError(400, reason + ". Refusing to enqueue.")

    try:
        decision = load_scope(scope_path)
    except ScopeError as exc:
        store.audit(AuditEntry(
            id=None, timestamp=started, event="external.enqueue",
            scope_file=os.path.abspath(scope_path), scope_hash=None,
            authorization_acknowledged=False, target_count=0,
            decision="deny", reason=str(exc)))
        raise ExternalError(400, f"scope refused: {exc}")

    try:
        with open(scope_path, "r", encoding="utf-8") as fh:
            raw_cfg = yaml.safe_load(fh) or {}
    except OSError:
        raw_cfg = {}
    allowed_domains = {
        str(e.get("domain", "")).strip().rstrip(".").lower()
        for e in (raw_cfg.get("external_domains") or [])
        if isinstance(e, dict) and e.get("authorized") is True
    }

    allowed_ips = set(decision.targets)
    for t in targets:
        try:
            ipaddress.ip_address(t)
            is_ip = True
        except ValueError:
            is_ip = False
        if is_ip:
            if t not in allowed_ips:
                raise _deny(
                    f"external assessment target {t} is not in the "
                    f"authorized scope ({scope_path})")
        else:
            domain = t.strip().rstrip(".").lower()
            if not domain or domain not in allowed_domains:
                raise _deny(
                    f"external assessment domain {t!r} is not in the "
                    f"scope file's external_domains allowlist "
                    f"({scope_path})")


def enqueue_assessment(store: Store, worker_id: str, targets: List[str],
                       probes: List[str],
                       scope_path: str = DEFAULT_SCOPE,
                       ports: Optional[List[int]] = None) -> Dict[str, Any]:
    """Queue an outside-in assessment for a worker.

    This is the clean hook the scheduled-scans engine (or any future
    trigger) can call directly — the API endpoint is a thin wrapper.

    `ports` optionally overrides the probe default port list (e.g. to
    check specific ports on a target).

    Raises ExternalError with .status in {403 (disabled), 404 (no worker),
    400 (bad targets/probes/ports), 429 (cooldown)}.
    """
    if not is_enabled(store):
        raise ExternalError(403, "external assessments are disabled "
                                 "(opt-in required)")
    worker = store.get_worker(worker_id)
    if worker is None:
        raise ExternalError(404, f"worker not found: {worker_id}")
    if worker["revoked"]:
        raise ExternalError(400, f"worker {worker_id} is revoked")

    if not targets or not isinstance(targets, list):
        raise ExternalError(400, "targets must be a non-empty list")
    targets = [str(t).strip() for t in targets if str(t).strip()]
    if not targets:
        raise ExternalError(400, "targets must be a non-empty list")
    if len(targets) > 64:
        raise ExternalError(400, "at most 64 targets per assessment")

    probes = list(dict.fromkeys(probes or []))  # de-dupe, keep order
    unknown = [p for p in probes if p not in ALL_PROBES]
    if unknown:
        raise ExternalError(
            400, f"unknown probe(s) {unknown}; allowed: {list(ALL_PROBES)}")
    if not probes:
        raise ExternalError(400, "at least one probe is required")

    ports = list(dict.fromkeys(ports or []))
    for p in ports:
        if not isinstance(p, int) or not 1 <= p <= 65535:
            raise ExternalError(400, f"invalid port in ports: {p!r}")

    _enforce_targets(targets, scope_path, store)

    # Per-worker enqueue cooldown, armed only by successful enqueues:
    # denied attempts don't consume it.
    now = time.monotonic()
    last = _last_enqueue.get(worker_id, 0.0)
    if now - last < ENQUEUE_COOLDOWN:
        raise ExternalError(
            429, f"enqueue cooling down for this worker; retry in "
                 f"{ENQUEUE_COOLDOWN - (now - last):.0f}s")
    _last_enqueue[worker_id] = now

    assessment_id = uuid.uuid4().hex
    created = utc_now_iso()
    store.create_assessment(assessment_id=assessment_id, worker_id=worker_id,
                            targets=targets, probes=probes, ports=ports)
    store.audit(AuditEntry(
        id=None, timestamp=created, event="external.enqueue",
        scope_file=os.path.abspath(scope_path),
        scope_hash=sha256_file(scope_path),
        authorization_acknowledged=True, target_count=len(targets),
        decision="allow",
        reason=f"enqueued assessment {assessment_id} for worker {worker_id}: "
               f"targets={targets} probes={probes} ports={ports or 'default'}"))
    log.info("enqueued external assessment %s for worker %s",
             assessment_id, worker_id)
    return {"id": assessment_id, "worker_id": worker_id, "targets": targets,
            "probes": probes, "ports": ports, "status": "queued",
            "created_at": created}


# ---------------------------------------------------------------------------
# result ingest -> findings
# ---------------------------------------------------------------------------

def _finding_for_port_obs(target: str, obs: Dict[str, Any]) -> Optional[Dict]:
    port = obs.get("port")
    if not port:
        return None
    svc, severity, remediation = PORT_LABELS.get(
        port, ("unknown", "low",
               "Identify this service and restrict it to trusted networks "
               "if it is not needed."))
    title = f"External view: open port {port}/tcp ({svc})"
    return {"title": title, "severity": severity, "remediation": remediation,
            "excerpt": (obs.get("banner") or "no banner")[:512],
            "detail": {"host": target, "port": port,
                       "service": svc,
                       "banner": (obs.get("banner") or "")[:512]}}


def _findings_for_banner_obs(target: str, obs: Dict[str, Any]) -> List[Dict]:
    # Only outdated products become findings; current ones are intel the
    # operator can see in the evidence detail.
    if not obs.get("outdated") or not obs.get("product"):
        return []
    product, version = obs["product"], obs["version"]
    return [{
        "title": (f"External view: {product} {version} appears unmaintained "
                  f"({target}:{obs.get('port')})"),
        "severity": "low",
        "remediation": (f"{product} {version} is past its maintained "
                        "releases. Upgrade to a currently supported release."),
        "excerpt": obs.get("summary", "")[:512],
        "detail": {"host": target, "port": obs.get("port"),
                   "product": product, "version": version,
                   "outdated": True},
    }]


def _findings_for_tls_obs(target: str, obs: Dict[str, Any]) -> List[Dict]:
    detail = obs.get("detail", {}) or {}
    problems = []
    if detail.get("expired"):
        problems.append("expired")
    if detail.get("self_signed"):
        problems.append("self-signed")
    if detail.get("tls_version") and not detail.get("tls_version_ok"):
        problems.append(f"weak protocol {detail.get('tls_version')}")
    if not problems:
        return []
    port = obs.get("port", 443)
    return [{
        "title": f"External view: TLS certificate issues on {target}:{port}",
        "severity": "medium",
        "remediation": ("Install a valid, non-expired certificate from a "
                        "trusted CA and negotiate TLS 1.2 or newer."),
        "excerpt": "; ".join(problems)[:512],
        "detail": {"host": target, "port": port, "problems": problems,
                   "subject_cn": detail.get("subject_cn", ""),
                   "issuer_cn": detail.get("issuer_cn", ""),
                   "not_after": detail.get("not_after", ""),
                   "tls_version": detail.get("tls_version", "")},
    }]


def _findings_for_dns_obs(target: str, obs: Dict[str, Any]) -> List[Dict]:
    out: List[Dict] = []
    domain = obs.get("domain", target)
    for mx in obs.get("mx", []) or []:
        out.append({
            "title": (f"External view: mail exchanger {mx.get('exchange')} "
                      f"published for {domain}"),
            "severity": "info",
            "remediation": ("Verify this mail exchanger is intentional and "
                            "hardened against open relay."),
            "excerpt": f"MX preference={mx.get('preference')} "
                       f"exchange={mx.get('exchange')}"[:512],
            "detail": {"domain": domain, "mx": mx},
        })
    if not obs.get("has_spf"):
        out.append({
            "title": f"External view: no SPF record published for {domain}",
            "severity": "low",
            "remediation": ("Publish an SPF TXT record (v=spf1 ...) so "
                            "receivers can reject forged mail from your "
                            "domain."),
            "excerpt": (f"{len(obs.get('mx', []) or [])} MX record(s) found, "
                        "no v=spf1 TXT record")[:512],
            "detail": {"domain": domain, "has_spf": False},
        })
    return out


def _findings_for_headers_obs(target: str, obs: Dict[str, Any]) -> List[Dict]:
    missing = obs.get("missing") or []
    if not missing:
        return []
    port = obs.get("port", 80)
    scheme = "https" if obs.get("use_tls") else "http"
    severity = "low" if "strict-transport-security" in missing else "info"
    return [{
        "title": (f"External view: incomplete HTTP security headers on "
                  f"{target}:{port}"),
        "severity": severity,
        "remediation": ("Set the missing response headers "
                        f"({', '.join(missing)}) — see OWASP Secure Headers "
                        "Project for values."),
        "excerpt": f"{scheme}://{target}:{port} missing: {', '.join(missing)}"[:512],
        "detail": {"host": target, "port": port, "use_tls": obs.get("use_tls"),
                   "missing": missing,
                   "present": obs.get("present", {})},
    }]


_PROBE_MAPPERS = {
    "port_discovery": lambda t, o: ([_finding_for_port_obs(t, o)]
                                    if _finding_for_port_obs(t, o) else []),
    "banner_intel": _findings_for_banner_obs,
    "tls_inspection": _findings_for_tls_obs,
    "dns_exposure": _findings_for_dns_obs,
    "http_security_headers": _findings_for_headers_obs,
}


def ingest_results(store: Store, worker: Dict[str, Any], assessment_id: str,
                   results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Store worker results as findings with full evidence.

    Findings enter at status `suspected` through the normal upsert path and
    each gets a `note` lifecycle event (actor `system`) so the outside-in
    origin is visible in the timeline. A trend snapshot is recorded, like
    local discovery does.
    """
    if not is_enabled(store):
        raise ExternalError(403, "external assessments are disabled")
    assessment = store.get_assessment(assessment_id)
    if assessment is None:
        raise ExternalError(404, f"assessment not found: {assessment_id}")
    if assessment["worker_id"] != worker["id"]:
        raise ExternalError(403, "assessment is not assigned to this worker")
    if assessment["status"] not in ("queued", "running"):
        raise ExternalError(409,
                            f"assessment is {assessment['status']}, "
                            "not accepting results")
    if not isinstance(results, list):
        raise ExternalError(400, "results must be a list")

    finished = utc_now_iso()
    store.update_assessment(assessment_id, status="running",
                            started_at=finished)
    findings_created = 0
    evidence_rows = 0
    for item in results:
        probe = (item or {}).get("probe")
        target = (item or {}).get("target")
        mapper = _PROBE_MAPPERS.get(probe)
        if mapper is None or not target:
            continue  # unknown probe or malformed item: skip, don't abort
        for obs in (item.get("observations") or []):
            for spec in mapper(str(target), obs if isinstance(obs, dict) else {}):
                finding = Finding.new(
                    target=str(target), title=spec["title"],
                    severity=spec["severity"], first_seen=finished,
                    remediation=spec["remediation"])
                stored = store.upsert_finding(finding)
                ev = Evidence(
                    id=None, finding_id=stored.id, timestamp=finished,
                    collector=f"external.{probe}",
                    excerpt=spec["excerpt"][:512],
                    excerpt_hash=sha256_text(
                        f"{probe}:{target}:{spec['excerpt']}"),
                    detail={"worker_id": worker["id"],
                            "assessment_id": assessment_id,
                            **spec["detail"]})
                store.add_evidence(ev)
                store.add_finding_event(FindingEvent(
                    id=None, finding_id=stored.id, timestamp=finished,
                    event="note", old_status=stored.status,
                    new_status=stored.status, actor="system",
                    detail={"via": "external-assessment",
                            "worker_id": worker["id"],
                            "assessment_id": assessment_id,
                            "probe": probe}))
                findings_created += 1
                evidence_rows += 1

    summary = {"findings_created": findings_created,
               "evidence_rows": evidence_rows,
               "result_items": len(results)}
    store.update_assessment(assessment_id, status="completed",
                            finished_at=finished, summary=summary)
    store.record_snapshot(finished)
    store.audit(AuditEntry(
        id=None, timestamp=finished, event="external.results_ingest",
        scope_file="", scope_hash=None, authorization_acknowledged=False,
        target_count=len({(r or {}).get("target") for r in results}),
        decision="allow",
        reason=f"worker {worker['id']} ingested assessment {assessment_id}: "
               f"{findings_created} finding(s), {evidence_rows} evidence row(s)"))
    log.info("ingested external assessment %s: %s", assessment_id, summary)
    return {"assessment_id": assessment_id, "status": "completed",
            "summary": summary}
