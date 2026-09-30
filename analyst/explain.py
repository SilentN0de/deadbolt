"""Local explanation engine (V0.2).

Turns a stored finding + its evidence into a plain-English analysis using the
curated knowledge base. Fully deterministic and offline: no network calls,
no model weights, nothing leaves the machine.

The engine is honest about its limits — it states exactly what discovery
proved (a TCP handshake completed) versus what it inferred (service identity
from port number and banner).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import List, Optional

from storage.models import Evidence, Finding

from .knowledge import HOST_UNRESPONSIVE, SERVICE_KB, UNKNOWN_SERVICE

_OPEN_PORT_RE = re.compile(r"Open port (\d+)/tcp \(([^)]+)\)")

_BANNER_NONE_MARKERS = ("no banner",)


@dataclass
class Explanation:
    finding_id: str
    target: str
    severity: str
    summary: str                 # one-line plain-English summary
    what_was_observed: str       # what discovery actually saw
    what_it_means: str           # what the service is
    why_it_matters: str          # risk context
    what_to_do: List[str]        # prioritized remediation steps
    confidence: str              # proven vs inferred, and status caveat
    evidence_refs: List[str] = field(default_factory=list)  # "collector:excerpt_hash[:12]"

    def to_dict(self):
        return asdict(self)


def _first_discovery_evidence(finding: Finding) -> Optional[Evidence]:
    for ev in finding.evidence:
        if ev.collector == "discovery.tcp":
            return ev
    return finding.evidence[0] if finding.evidence else None


def _has_banner(evidence: Optional[Evidence]) -> bool:
    """True when evidence holds a real service banner (not 'no banner'/errors)."""
    if evidence is None:
        return False
    excerpt = (evidence.excerpt or "").strip()
    return bool(excerpt) and excerpt not in _BANNER_NONE_MARKERS \
        and not excerpt.startswith("banner read error")


def _banner_note(evidence: Optional[Evidence]) -> str:
    """Describe the banner evidence, noting version disclosure when visible."""
    if evidence is None:
        return "No evidence was stored with this finding."
    excerpt = (evidence.excerpt or "").strip()
    if not excerpt or excerpt in _BANNER_NONE_MARKERS:
        return ("The port accepted the connection but returned no banner, so the "
                "service did not identify itself.")
    if excerpt.startswith("banner read error"):
        return ("The port accepted the connection but the banner could not be read "
                f"({excerpt}). The service did not identify itself.")
    note = f"The service identified itself with this banner: {excerpt[:160]!r}."
    # Version strings in banners help attackers match known vulnerabilities.
    if re.search(r"\d+\.\d+", excerpt):
        note += (" Banners that include version numbers are information disclosure: "
                 "they let an attacker look up known flaws for that exact version.")
    return note


def explain_finding(finding: Finding) -> Explanation:
    """Build a plain-English explanation for a stored finding."""
    ev = _first_discovery_evidence(finding)
    refs = (
        [f"{e.collector}:{e.excerpt_hash[:12]}" for e in finding.evidence]
        if finding.evidence else []
    )

    # Case 1: host never answered.
    if finding.title.startswith("Host unresponsive"):
        kb = HOST_UNRESPONSIVE
        return Explanation(
            finding_id=finding.id,
            target=finding.target,
            severity=finding.severity,
            summary=f"{finding.target} did not respond to any discovery probes.",
            what_was_observed=(
                f"Every TCP connection attempt to {finding.target} timed out. "
                "No port on the host accepted, refused, or reset a connection — "
                "the host was effectively silent."
            ),
            what_it_means=kb["what"],
            why_it_matters=kb["risk"],
            what_to_do=list(kb["remediation_steps"]),
            confidence=(
                "Low: a silent host tells us nothing about what runs on it. "
                "This finding is marked 'suspected' — treat it as 'host not "
                "assessed', not 'host is clean'."
            ),
            evidence_refs=refs,
        )

    # Case 2: open port. Parse port/service from the title.
    match = _OPEN_PORT_RE.search(finding.title)
    port: Optional[int] = int(match.group(1)) if match else None
    service: str = match.group(2) if match else "unknown"
    kb = SERVICE_KB.get(service, UNKNOWN_SERVICE)

    port_str = f"port {port}/tcp" if port is not None else "a port"
    summary = (
        f"{finding.target} has {port_str} open"
        + (f" ({service})" if service != "unknown" else " (unrecognized service)")
        + "."
    )
    observed = (
        f"A TCP connection to {finding.target}:{port if port is not None else '?'} "
        f"completed successfully — the three-way handshake finished, which proves "
        f"a service is listening there. {_banner_note(ev)}"
    )
    confidence = (
        "The open port is confirmed: a completed TCP handshake is proof a service "
        "is listening. The service identity (" + service + ") is inferred from the "
        "port number" + (" and the captured banner" if _has_banner(ev) else "")
        + ", not from deep fingerprinting — it could theoretically be something "
        "else on a non-standard port. That is why the finding status is "
        f"'{finding.status}' (discovery alone can only suspect, not confirm "
        "intent or exploitability)."
    )
    return Explanation(
        finding_id=finding.id,
        target=finding.target,
        severity=finding.severity,
        summary=summary,
        what_was_observed=observed,
        what_it_means=kb["what"],
        why_it_matters=kb["risk"],
        what_to_do=list(kb["remediation_steps"]),
        confidence=confidence,
        evidence_refs=refs,
    )
