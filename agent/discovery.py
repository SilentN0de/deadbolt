"""Read-only local discovery (V0.1).

nmap-in-spirit TCP discovery for AUTHORIZED targets only:
  - TCP connect() to a curated common-ports list (no raw sockets, no SYN scan)
  - recv-only banner grab with short timeouts (nothing is sent to the target)
  - bounded concurrency, per-host + global rate limits, timeouts everywhere

NON-DESTRUCTIVE ONLY: no exploits, no payloads, no brute force, no lateral
movement. Scope is enforced by agent.scope BEFORE any packet is sent.

Usage:
    python -m agent.discovery --scope config/authorized_targets.yaml
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from common.logging_setup import configure_logging, install_crash_hook, utc_now_iso
from storage.db import Store, sha256_file, sha256_text
from storage.models import AuditEntry, Evidence, Finding, Run

from .scope import ScopeError, load_scope

log = logging.getLogger("deadbolt.discovery")

COLLECTOR = "discovery.tcp"

# Curated common-ports list: (port, service label, severity, remediation).
PORTS: Dict[int, tuple] = {
    21:   ("FTP",   "low",    "FTP transmits credentials in cleartext. Disable it or restrict to trusted hosts; prefer SFTP/SCP."),
    22:   ("SSH",   "info",   "Verify SSH uses key-based auth, disable password auth if possible, and keep the server patched."),
    23:   ("Telnet","medium", "Telnet is cleartext and obsolete. Disable it; use SSH instead."),
    25:   ("SMTP",  "low",    "Ensure this mail service is intentional; disable open relay and require authentication."),
    53:   ("DNS",   "info",   "If this is a resolver, ensure recursion is not open to untrusted networks."),
    80:   ("HTTP",  "info",   "Prefer HTTPS; check for exposed admin panels or directory listings."),
    110:  ("POP3",  "low",    "Prefer POP3S/IMAPS; ensure authentication is required."),
    143:  ("IMAP",  "low",    "Prefer IMAPS; ensure authentication is required."),
    443:  ("HTTPS", "info",   "Check TLS certificate validity and protocol versions."),
    445:  ("SMB",   "medium", "SMB exposed to untrusted networks enables ransomware spread. Block at the firewall; require SMB signing."),
    1433: ("MSSQL", "medium", "Database listeners should not face untrusted networks. Restrict by firewall/IP allowlist."),
    3306: ("MySQL", "medium", "Database listeners should not face untrusted networks. Restrict by firewall/IP allowlist."),
    3389: ("RDP",   "medium", "RDP exposed to untrusted networks is a top ransomware vector. Require VPN + MFA, or disable."),
    5432: ("PostgreSQL", "medium", "Database listeners should not face untrusted networks. Restrict by firewall/IP allowlist."),
    5900: ("VNC",   "medium", "VNC is weakly authenticated. Tunnel over SSH/VPN or disable."),
    6379: ("Redis", "medium", "Redis has no auth by default. Bind to localhost, require a password, firewall it."),
    8080: ("HTTP-alt", "info","Check what admin/dev service this is; do not expose dashboards without auth."),
    8443: ("HTTPS-alt","info","Check what admin/dev service this is; verify TLS and authentication."),
    27017:("MongoDB","medium","MongoDB without auth has caused major breaches. Enable auth, bind to localhost, firewall it."),
}

DEFAULT_PORTS = sorted(PORTS)
CONNECT_TIMEOUT = 1.0
BANNER_TIMEOUT = 2.0
MAX_WORKERS = 32
PER_HOST_CONCURRENCY = 8
GLOBAL_MIN_INTERVAL = 0.02  # ~50 connection attempts/sec max


@dataclass
class ProbeResult:
    host: str
    port: int
    open: bool
    banner: str = ""
    timed_out: bool = False
    refused: bool = False
    error: str = ""


class RateLimiter:
    """Simple global pacer: minimum interval between attempts."""

    def __init__(self, min_interval: float):
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


def probe_port(host: str, port: int, limiter: RateLimiter,
               connect_timeout: float = CONNECT_TIMEOUT,
               banner_timeout: float = BANNER_TIMEOUT) -> ProbeResult:
    """Single TCP connect + recv-only banner grab. Never sends payload data."""
    limiter.wait()
    res = ProbeResult(host=host, port=port, open=False)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(connect_timeout)
        try:
            sock.connect((host, port))
        except socket.timeout:
            res.timed_out = True
            res.error = "connect timed out"
            return res
        except ConnectionRefusedError:
            res.refused = True
            return res
        except OSError as exc:
            res.error = f"os error: {exc}"
            return res

        res.open = True
        # Banner grab: recv-only, short timeout, no data sent (non-intrusive).
        sock.settimeout(banner_timeout)
        try:
            data = sock.recv(2048)
            res.banner = data.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            res.banner = ""
        except OSError as exc:
            res.error = f"banner read error: {exc}"
        return res
    finally:
        # Always release the file descriptor, even on connect failure.
        try:
            sock.close()
        except OSError:
            pass


@dataclass
class DiscoveryReport:
    targets: List[str] = field(default_factory=list)
    results: List[ProbeResult] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""


def discover(targets: List[str], ports: Optional[List[int]] = None) -> DiscoveryReport:
    """Run the TCP discovery sweep over authorized targets."""
    ports = ports or DEFAULT_PORTS
    limiter = RateLimiter(GLOBAL_MIN_INTERVAL)
    host_semaphores = {t: threading.Semaphore(PER_HOST_CONCURRENCY) for t in targets}
    report = DiscoveryReport(targets=list(targets), started_at=utc_now_iso())

    def _task(host: str, port: int) -> ProbeResult:
        with host_semaphores[host]:
            return probe_port(host, port, limiter)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(_task, h, p) for h in targets for p in ports]
        for fut in concurrent.futures.as_completed(futures):
            try:
                report.results.append(fut.result())
            except Exception as exc:  # never let one probe kill the run
                log.exception("probe task failed: %s", exc)
    report.finished_at = utc_now_iso()
    return report


def _evidence_for(result: ProbeResult, finding_id: str) -> Evidence:
    raw = result.banner or result.error or "no banner"
    excerpt = raw[:512]
    detail = {
        "host": result.host,
        "port": result.port,
        "open": result.open,
        "timed_out": result.timed_out,
        "refused": result.refused,
        "error": result.error,
        "banner_length": len(result.banner),
    }
    return Evidence(
        id=None,
        finding_id=finding_id,
        timestamp=utc_now_iso(),
        collector=COLLECTOR,
        excerpt=excerpt,
        excerpt_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        detail=detail,
    )


def report_to_findings(report: DiscoveryReport, store: Store) -> List[Finding]:
    """Convert probe results into normalized findings + evidence rows."""
    now = utc_now_iso()
    findings: List[Finding] = []

    by_host: Dict[str, List[ProbeResult]] = {}
    for r in report.results:
        by_host.setdefault(r.host, []).append(r)

    for host, results in by_host.items():
        open_results = [r for r in results if r.open]
        timeouts = [r for r in results if r.timed_out]

        for r in open_results:
            svc, severity, remediation = PORTS.get(
                r.port, ("unknown", "low", "Identify this service and restrict it to trusted networks if it is not needed.")
            )
            # Title is intentionally stable (no banner text): findings dedupe
            # on (target, title), and a banner change (e.g. service upgrade)
            # must update the finding, not spawn a duplicate. The banner
            # lives in the evidence detail.
            title = f"Open port {r.port}/tcp ({svc})"
            finding = Finding.new(
                target=host, title=title, severity=severity,
                first_seen=now, remediation=remediation,
            )
            stored = store.upsert_finding(finding)
            stored_evidence = _evidence_for(r, stored.id)
            store.add_evidence(stored_evidence)
            stored.evidence.append(stored_evidence)
            findings.append(stored)

        # Host never answered at all: suspected finding with timeout evidence.
        # (If anything was refused, the host is up — just filtered/closed.)
        if not open_results and timeouts and not any(r.refused for r in results):
            title = "Host unresponsive to TCP discovery probes (timeouts)"
            finding = Finding.new(
                target=host, title=title, severity="info", first_seen=now,
                remediation="Verify the host is powered on and reachable; check host firewall rules if the host should be up.",
            )
            stored = store.upsert_finding(finding)
            ev = Evidence(
                id=None, finding_id=stored.id, timestamp=now, collector=COLLECTOR,
                excerpt=f"{len(timeouts)} probe(s) timed out after {CONNECT_TIMEOUT}s; host may be down or filtering.",
                excerpt_hash=sha256_text(f"{host}:timeouts:{len(timeouts)}"),
                detail={"host": host, "timed_out_ports": [r.port for r in timeouts]},
            )
            store.add_evidence(ev)
            stored.evidence.append(ev)
            findings.append(stored)

    return findings


def run_discovery(scope_path: str, db_path: str,
                  ports: Optional[List[int]] = None) -> Dict:
    """Full pipeline: enforce scope -> audit -> discover -> store. Returns summary."""
    store = Store(db_path)
    started = utc_now_iso()
    scope_hash: Optional[str] = None
    ack = False
    targets: List[str] = []

    try:
        decision = load_scope(scope_path)
    except ScopeError as exc:
        reason = str(exc)
        log.warning("SCOPE DENY: %s", reason)
        store.audit(AuditEntry(
            id=None, timestamp=started, event="discovery.attempt",
            scope_file=os.path.abspath(scope_path), scope_hash=None,
            authorization_acknowledged=False, target_count=0,
            decision="deny", reason=reason,
        ))
        store.close()
        raise

    scope_hash = sha256_file(scope_path)
    ack = decision.authorization_acknowledged
    targets = decision.targets
    log.info("SCOPE ALLOW: %s", decision.reason)
    store.audit(AuditEntry(
        id=None, timestamp=started, event="discovery.attempt",
        scope_file=os.path.abspath(scope_path), scope_hash=scope_hash,
        authorization_acknowledged=ack, target_count=len(targets),
        decision="allow", reason=decision.reason,
    ))

    run_id = store.create_run(Run(
        id=None, started_at=started, finished_at=None,
        scope_file=os.path.abspath(scope_path), scope_hash=scope_hash,
        scope_targets=targets, authorization_acknowledged=ack,
        target_count=len(targets), status="running",
    ))

    try:
        report = discover(targets, ports)
        findings = report_to_findings(report, store)
        finished = utc_now_iso()
        summary = {
            "hosts_scanned": len(targets),
            "ports_per_host": len(ports or DEFAULT_PORTS),
            "probes": len(report.results),
            "open_ports": sum(1 for r in report.results if r.open),
            "findings_created": len(findings),
        }
        store.finish_run(run_id, "completed", summary, finished)
        store.record_snapshot(finished, run_id=run_id)
        log.info("discovery run %d completed: %s", run_id, summary)
        store.close()
        return {"run_id": run_id, "status": "completed", "summary": summary,
                "findings": [f.to_dict() for f in findings]}
    except Exception as exc:
        finished = utc_now_iso()
        store.finish_run(run_id, "failed", {"error": str(exc)}, finished)
        store.close()
        raise


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only local discovery agent")
    parser.add_argument("--scope", required=True, help="path to authorized_targets.yaml")
    parser.add_argument("--db", default=os.path.join("data", "findings.db"),
                        help="sqlite db path (default: data/findings.db)")
    parser.add_argument("--ports", default="",
                        help="comma-separated port override, e.g. '22,80,443'")
    args = parser.parse_args(argv)

    configure_logging()
    install_crash_hook()

    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    try:
        result = run_discovery(args.scope, args.db, ports)
    except ScopeError as exc:
        print(f"REFUSED: {exc}")
        return 2
    print(f"run {result['run_id']} completed: "
          f"{result['summary']['findings_created']} finding(s), "
          f"{result['summary']['open_ports']} open port(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
