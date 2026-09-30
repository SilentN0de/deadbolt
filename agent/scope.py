"""Scope & authorization enforcement.

The agent REFUSES to run unless:
  1. the scope file exists and parses, and
  2. it explicitly lists at least one target, each with `authorized: true`.

Public IPs and 0.0.0.0/0 additionally require BOTH:
  - top-level `authorization_acknowledged: true`, AND
  - per-target `authorized: true`.

Every allow/deny decision is logged (caller writes the audit row).
"""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from typing import List

import yaml

log = logging.getLogger("secplatform.scope")


class ScopeError(Exception):
    """Raised when scope/authorization checks refuse a run."""


# Networks considered non-public for the ack requirement.
_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("10.0.0.0/8"),      # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),   # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),        # unique local
    ipaddress.ip_network("fe80::/10"),       # link-local
]

# Hard safety caps (host count after CIDR expansion).
MAX_HOSTS_NO_ACK = 1024
MAX_HOSTS_ABSOLUTE = 4096


@dataclass
class ScopeDecision:
    allowed: bool
    targets: List[str] = field(default_factory=list)  # resolved IP strings
    authorization_acknowledged: bool = False
    reason: str = ""


def _is_public_network(net: ipaddress._BaseNetwork) -> bool:
    """True when the network is NOT fully inside known-private space.

    0.0.0.0/0 and any public range count as public here.
    """
    return not any(
        net.version == p.version and net.subnet_of(p) for p in _PRIVATE_NETS
    )


def load_scope(scope_path: str) -> ScopeDecision:
    """Validate the scope file. Returns a decision; raises ScopeError on deny."""
    if not os.path.exists(scope_path):
        raise ScopeError(
            f"scope file not found: {scope_path}. "
            "Refusing to run without an explicit authorized-targets file."
        )

    try:
        with open(scope_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ScopeError(f"scope file is not valid YAML: {exc}") from exc

    ack = bool(cfg.get("authorization_acknowledged", False))
    raw_targets = cfg.get("targets")
    if not raw_targets:
        raise ScopeError("scope file lists no targets — refusing to run.")

    resolved: List[str] = []
    for entry in raw_targets:
        if not isinstance(entry, dict) or "target" not in entry:
            raise ScopeError(f"malformed target entry (need 'target'): {entry!r}")
        if entry.get("authorized") is not True:
            raise ScopeError(
                f"target {entry.get('target')!r} is not explicitly authorized "
                "(set `authorized: true`). Refusing to run."
            )
        raw = str(entry["target"]).strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ScopeError(f"invalid target {raw!r}: {exc}") from exc

        if _is_public_network(net):
            if not (ack and entry.get("authorized") is True):
                raise ScopeError(
                    f"target {raw!r} is public (or 0.0.0.0/0) and lacks explicit "
                    "authorization: requires top-level "
                    "`authorization_acknowledged: true` AND per-target "
                    "`authorized: true`. Refusing to run."
                )
            log.warning("public target %s explicitly authorized by user", raw)

        count = net.num_addresses
        # Check caps BEFORE expanding — a huge network (e.g. 0.0.0.0/0) must
        # never be materialized into a host list.
        if count > MAX_HOSTS_ABSOLUTE:
            raise ScopeError(
                f"target {raw!r} expands to {count} hosts "
                f"(absolute cap {MAX_HOSTS_ABSOLUTE}). Narrow the scope."
            )
        if count > MAX_HOSTS_NO_ACK and not ack:
            raise ScopeError(
                f"target {raw!r} expands to {count} hosts; large scans require "
                "`authorization_acknowledged: true`. Refusing to run."
            )
        # For scanning we use usable hosts; keep /32 and /31 intact.
        hosts = [str(h) for h in net.hosts()] if count > 2 else [str(net.network_address)]
        if not hosts:  # e.g. /31 edge cases
            hosts = [str(net.network_address)]
        resolved.extend(hosts)

    # De-dupe while preserving order.
    seen, targets = set(), []
    for t in resolved:
        if t not in seen:
            seen.add(t)
            targets.append(t)

    if not targets:
        raise ScopeError("scope resolved to zero hosts — refusing to run.")

    return ScopeDecision(
        allowed=True,
        targets=targets,
        authorization_acknowledged=ack,
        reason=f"scope authorized: {len(targets)} host(s)",
    )
