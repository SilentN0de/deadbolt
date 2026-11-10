"""Normalized finding/evidence data model (V0.1).

Plain dataclasses mirroring storage/schema.sql. JSON serialization is via
`to_dict()`; `retest_history` / `detail` are stored as JSON text in SQLite.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

SEVERITIES = ("info", "low", "medium", "high", "critical")
STATUSES = ("suspected", "confirmed", "accepted-risk", "fixed", "false-positive")
EVENT_TYPES = ("status_changed", "retest", "note")
ACTORS = ("operator", "retest", "system")


@dataclass
class Evidence:
    id: int | None
    finding_id: str
    timestamp: str          # ISO-8601 UTC
    collector: str          # e.g. "discovery.tcp"
    excerpt: str            # truncated raw output (<= 512 chars)
    excerpt_hash: str       # sha256 hex of the FULL raw output
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    target: str
    title: str
    severity: str = "info"
    status: str = "suspected"
    first_seen: str = ""
    last_seen: str = ""
    remediation: str = ""
    retest_history: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)  # populated on read

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity!r}")
        if self.status not in STATUSES:
            raise ValueError(f"invalid status: {self.status!r}")

    @classmethod
    def new(
        cls,
        target: str,
        title: str,
        severity: str = "info",
        first_seen: str = "",
        remediation: str = "",
    ) -> "Finding":
        return cls(
            id=uuid.uuid4().hex,
            target=target,
            title=title,
            severity=severity,
            status="suspected",  # discovery alone can only *suspect*
            first_seen=first_seen,
            last_seen=first_seen,
            remediation=remediation,
        )

    def to_dict(self, include_evidence: bool = True) -> Dict[str, Any]:
        d = asdict(self)
        if not include_evidence:
            d.pop("evidence", None)
        return d


# ---------------------------------------------------------------------------
# Finding identity (V0.5.1)
#
# A finding's identity is NOT its raw title string. Early versions embedded
# the observed banner in open-port titles ("Open port 445/tcp (SMB) — no
# banner returned", "... — banner: 'SSH-2.0-...'"), so when a banner changed
# — or the title format changed between versions — the exact-match upsert
# spawned a duplicate row for the same host/port/service. Identity therefore
# keys open-port findings on (target, vantage, port, service) parsed from
# the title; the banner-derived suffix is evidence, not identity.
# ---------------------------------------------------------------------------

_OPEN_PORT_TITLE_RE = re.compile(
    r"^(?P<base>(?P<vantage>External view: )?[Oo]pen port "
    r"(?P<port>\d+)/tcp \((?P<service>[^)]+)\))"
)


def canonical_finding_title(title: str) -> str:
    """Canonical form of a finding title.

    Open-port titles reduce to their base ("Open port {port}/tcp ({svc})",
    keeping an "External view: " vantage prefix and original casing) with
    any observational suffix dropped. Other titles are returned with
    whitespace collapsed.
    """
    collapsed = " ".join((title or "").split())
    m = _OPEN_PORT_TITLE_RE.match(collapsed)
    if m:
        return m.group("base")
    return collapsed


def finding_identity(target: str, title: str) -> tuple:
    """Stable identity key for a finding: equal keys == the same finding.

    Open-port findings key on (target, "port", external?, port, service);
    every other finding keys on (target, "title", canonical title).
    """
    collapsed = " ".join((title or "").split())
    m = _OPEN_PORT_TITLE_RE.match(collapsed)
    if m:
        return (target, "port", bool(m.group("vantage")),
                int(m.group("port")), m.group("service").lower())
    return (target, "title", canonical_finding_title(title))


@dataclass
class Run:
    id: int | None
    started_at: str
    finished_at: str | None
    scope_file: str
    scope_hash: str
    scope_targets: List[str]
    authorization_acknowledged: bool
    target_count: int
    status: str = "running"
    summary: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Validation:
    """One controlled validation of a finding (V0.3)."""
    id: int | None
    finding_id: str
    timestamp: str          # ISO-8601 UTC
    checks: List[str]       # e.g. ["tcp_reprobe", "banner_intel"]
    results: List[Dict[str, Any]]  # per-check {check, ok, verdict, summary, detail}
    outcome: str            # "confirmed" | "false-positive" | "intel" | "inconclusive"
    status_before: str = "suspected"
    status_after: str = "suspected"

    def __post_init__(self) -> None:
        if self.outcome not in ("confirmed", "false-positive", "intel", "inconclusive"):
            raise ValueError(f"invalid outcome: {self.outcome!r}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FindingEvent:
    """One append-only lifecycle event for a finding (V0.4)."""
    id: int | None
    finding_id: str
    timestamp: str          # ISO-8601 UTC
    event: str              # "status_changed" | "retest" | "note"
    old_status: str
    new_status: str
    actor: str              # "operator" | "retest" | "system"
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.event not in EVENT_TYPES:
            raise ValueError(f"invalid event: {self.event!r}")
        if self.old_status not in STATUSES:
            raise ValueError(f"invalid old_status: {self.old_status!r}")
        if self.new_status not in STATUSES:
            raise ValueError(f"invalid new_status: {self.new_status!r}")
        if self.actor not in ACTORS:
            raise ValueError(f"invalid actor: {self.actor!r}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditEntry:
    id: int | None
    timestamp: str
    event: str
    scope_file: str
    scope_hash: str | None
    authorization_acknowledged: bool
    target_count: int
    decision: str           # "allow" | "deny"
    reason: str = ""


def dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"))


def loads(text: str) -> Any:
    return json.loads(text) if text else []
