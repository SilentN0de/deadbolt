"""Finding lifecycle state machine tests (V0.4)."""

import sqlite3

import pytest

from lifecycle import (TRANSITIONS, IllegalTransition, allowed_next,
                       transition_finding)
from storage.db import Store
from storage.models import STATUSES, Finding


@pytest.fixture()
def lstore(tmp_path):
    s = Store(str(tmp_path / "lifecycle.db"))
    yield s
    s.close()


def _seed(store, status="suspected", target="127.0.0.1", title="F"):
    f = Finding.new(target=target, title=title, severity="medium",
                    first_seen="2026-09-30T00:00:00Z")
    stored = store.upsert_finding(f)
    if status != "suspected":
        # Walk the machine legally to the desired start state.
        path = {"confirmed": ["confirmed"],
                "false-positive": ["false-positive"],
                "fixed": ["confirmed", "fixed"],
                "accepted-risk": ["confirmed", "accepted-risk"]}[status]
        for step in path:
            transition_finding(store, stored.id, step, actor="system")
    return store.get_finding(stored.id)


# -- legal transitions ------------------------------------------------------

@pytest.mark.parametrize("old,new", [
    ("suspected", "confirmed"),
    ("suspected", "fixed"),  # retest remediation of a never-validated finding
    ("suspected", "false-positive"),
    ("confirmed", "fixed"),
    ("confirmed", "accepted-risk"),
    ("confirmed", "false-positive"),
    ("fixed", "confirmed"),
    ("accepted-risk", "confirmed"),
    ("false-positive", "suspected"),
])
def test_legal_transitions(lstore, old, new):
    f = _seed(lstore, status=old, title=f"{old}->{new}")
    event = transition_finding(lstore, f.id, new, actor="operator",
                               note="test note")
    assert event["old_status"] == old
    assert event["new_status"] == new
    assert event["actor"] == "operator"
    assert event["detail"] == {"note": "test note"}
    assert lstore.get_finding(f.id).status == new
    # Recorded in the append-only event log.
    events = lstore.list_finding_events(f.id)
    assert events, "expected at least one lifecycle event"
    assert events[-1]["event"] == "status_changed"
    assert (events[-1]["old_status"], events[-1]["new_status"]) == (old, new)


def test_transition_without_note_has_empty_detail(lstore):
    f = _seed(lstore)
    event = transition_finding(lstore, f.id, "confirmed")
    assert event["detail"] == {}


def test_retest_actor_recorded(lstore):
    f = _seed(lstore, status="confirmed")
    transition_finding(lstore, f.id, "fixed", actor="retest",
                       note="service gone")
    events = lstore.list_finding_events(f.id)
    assert events[-1]["actor"] == "retest"
    assert events[-1]["detail"] == {"note": "service gone"}


# -- illegal transitions ----------------------------------------------------

def test_every_illegal_transition_rejected(lstore):
    checked = 0
    for old in STATUSES:
        for new in STATUSES:
            if new in TRANSITIONS[old]:
                continue
            f = _seed(lstore, status=old, title=f"illegal-{old}-{new}")
            with pytest.raises(IllegalTransition) as exc_info:
                transition_finding(lstore, f.id, new)
            assert exc_info.value.allowed == TRANSITIONS[old]
            assert lstore.get_finding(f.id).status == old  # unchanged
            checked += 1
    assert checked > 0


def test_same_status_transition_rejected(lstore):
    f = _seed(lstore, status="confirmed")
    with pytest.raises(IllegalTransition) as exc_info:
        transition_finding(lstore, f.id, "confirmed")
    assert exc_info.value.allowed == ["fixed", "accepted-risk",
                                     "false-positive"]


def test_unknown_status_rejected(lstore):
    f = _seed(lstore)
    with pytest.raises(ValueError, match="invalid status"):
        transition_finding(lstore, f.id, "nuked")


def test_unknown_finding_rejected(lstore):
    with pytest.raises(KeyError):
        transition_finding(lstore, "nope", "confirmed")


def test_unknown_actor_rejected(lstore):
    f = _seed(lstore)
    with pytest.raises(ValueError, match="invalid actor"):
        transition_finding(lstore, f.id, "confirmed", actor="hacker")


def test_allowed_next(lstore):
    assert allowed_next("confirmed") == ["fixed", "accepted-risk",
                                        "false-positive"]
    assert allowed_next("bogus") == []


# -- append-only enforcement -------------------------------------------------

def test_finding_events_immutable(lstore):
    f = _seed(lstore)
    transition_finding(lstore, f.id, "confirmed")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        lstore._conn.execute("UPDATE finding_events SET new_status='fixed'")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        lstore._conn.execute("DELETE FROM finding_events")
