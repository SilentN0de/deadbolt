"""Finding lifecycle state machine (V0.4).

Explicit, closed set of allowed status transitions. Every transition —
operator-driven, retest-driven, or validation-driven — is recorded in the
append-only `finding_events` table. Nothing here probes the network.
"""

from __future__ import annotations

import logging
from typing import Dict, List

from common.logging_setup import utc_now_iso
from storage.db import Store
from storage.models import STATUSES, FindingEvent

log = logging.getLogger("deadbolt.lifecycle")

# The full state machine. Retest-driven edges (confirmed/suspected -> fixed,
# fixed -> confirmed regression) go through the same machine with
# actor="retest".
#
# Note: suspected -> fixed exists because retest must be able to mark a
# never-validated finding fixed when its service is gone (the retest spec
# requires confirmed/suspected -> fixed on remediation). An operator may
# also use it directly (e.g. "I removed that service").
TRANSITIONS: Dict[str, List[str]] = {
    "suspected": ["confirmed", "fixed", "false-positive"],
    "confirmed": ["fixed", "accepted-risk", "false-positive"],
    "fixed": ["confirmed"],          # regression: the issue came back
    "accepted-risk": ["confirmed"],  # reopened
    "false-positive": ["suspected"],  # reopened
}


class IllegalTransition(Exception):
    """Raised when a status change is not in TRANSITIONS."""

    def __init__(self, old_status: str, new_status: str):
        self.old_status = old_status
        self.new_status = new_status
        self.allowed = list(TRANSITIONS.get(old_status, []))
        super().__init__(
            f"illegal transition {old_status!r} -> {new_status!r}; "
            f"allowed from {old_status!r}: {self.allowed}"
        )


def allowed_next(status: str) -> List[str]:
    """Statuses a finding may legally move to from `status`."""
    return list(TRANSITIONS.get(status, []))


def transition_finding(store: Store, finding_id: str, new_status: str,
                       actor: str = "operator", note: str = "") -> Dict:
    """Move a finding through the state machine.

    Raises KeyError (unknown finding), ValueError (unknown status/actor),
    or IllegalTransition (edge not allowed). On success returns the
    recorded event as a dict.
    """
    if new_status not in STATUSES:
        raise ValueError(
            f"invalid status {new_status!r}; must be one of {list(STATUSES)}")
    if actor not in ("operator", "retest", "system"):
        raise ValueError(f"invalid actor {actor!r}")

    finding = store.get_finding(finding_id)
    if finding is None:
        raise KeyError(f"finding not found: {finding_id}")

    old_status = finding.status
    if new_status == old_status:
        raise IllegalTransition(old_status, new_status)
    if new_status not in TRANSITIONS.get(old_status, []):
        raise IllegalTransition(old_status, new_status)

    timestamp = utc_now_iso()
    store.update_finding_status(
        finding_id, new_status,
        event=f"lifecycle:{old_status}->{new_status}",
        timestamp=timestamp)
    event = FindingEvent(
        id=None, finding_id=finding_id, timestamp=timestamp,
        event="status_changed", old_status=old_status, new_status=new_status,
        actor=actor, detail={"note": note} if note else {},
    )
    eid = store.add_finding_event(event)
    log.info("finding %s: %s -> %s by %s%s", finding_id, old_status,
             new_status, actor, f" ({note})" if note else "")
    return {**event.to_dict(), "id": eid}
