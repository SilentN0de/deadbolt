"""Normalized finding/evidence data model (V0.1).

Plain dataclasses mirroring storage/schema.sql. JSON serialization is via
`to_dict()`; `retest_history` / `detail` are stored as JSON text in SQLite.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

SEVERITIES = ("info", "low", "medium", "high", "critical")
STATUSES = ("suspected", "confirmed", "accepted-risk", "fixed", "false-positive")


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
