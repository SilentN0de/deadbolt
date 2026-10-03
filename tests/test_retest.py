"""Retest orchestration tests (V0.4).

Uses the simulated lab (fake services on 127.0.0.1) so re-probes exercise
the real read-only probe pipeline without touching any real network.
"""

import pytest
import yaml

from agent.scope import ScopeError
from lifecycle import transition_finding
from retest import RetestError, retest_all, retest_finding, select_retest_checks
from sim import SimulatedLab
from storage.db import Store
from storage.models import Evidence, Finding


@pytest.fixture()
def lab():
    with SimulatedLab() as lab:
        yield lab


@pytest.fixture()
def rstore(tmp_path):
    s = Store(str(tmp_path / "retest.db"))
    yield s
    s.close()


def _scope(tmp_path, target="127.0.0.1"):
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1,
        "authorization_acknowledged": True,
        "targets": [{"target": target, "authorized": True}],
    }))
    return str(p)


def _seed(store, target, port, status="confirmed", title=None,
          with_evidence=True, last_seen="2020-01-01T00:00:00+00:00"):
    """Seed a finding whose evidence points at (target, port)."""
    f = Finding.new(target=target,
                    title=title or f"Open port {port}/tcp (SIM)",
                    severity="medium", first_seen="2020-01-01T00:00:00+00:00")
    stored = store.upsert_finding(f)
    if with_evidence:
        store.add_evidence(Evidence(
            id=None, finding_id=stored.id, timestamp="2020-01-01T00:00:00+00:00",
            collector="discovery.tcp", excerpt="sim",
            excerpt_hash="ab" * 32,
            detail={"host": target, "port": port}))
    # Force an old last_seen so tests can assert it gets refreshed.
    store._conn.execute("UPDATE findings SET last_seen = ? WHERE id = ?",
                        (last_seen, stored.id))
    store._conn.commit()
    if status != "suspected":
        path = {"confirmed": ["confirmed"],
                "fixed": ["confirmed", "fixed"]}[status]
        for step in path:
            transition_finding(store, stored.id, step, actor="system")
    return store.get_finding(stored.id)


# -- check selection ----------------------------------------------------------

def test_select_retest_checks():
    assert select_retest_checks(None) == []
    assert select_retest_checks(2222) == ["tcp_reprobe", "banner_intel"]
    assert select_retest_checks(443) == ["tcp_reprobe", "tls_certificate",
                                        "banner_intel"]


# -- re-observed --------------------------------------------------------------

def test_retest_reobserved_keeps_status(lab, rstore, tmp_path):
    f = _seed(rstore, "127.0.0.1", lab.ports["ssh_old"], status="confirmed")
    res = retest_finding(rstore, f.id, scope_path=_scope(tmp_path))
    assert res["event"] == "re-observed"
    assert res["old_status"] == "confirmed"
    assert res["new_status"] == "confirmed"
    stored = rstore.get_finding(f.id)
    assert stored.status == "confirmed"
    assert stored.last_seen > "2020-01-01T00:00:00+00:00"  # refreshed
    assert any(e["event"] == "re-observed" for e in stored.retest_history)
    events = [e for e in rstore.list_finding_events(f.id)
              if e["event"] == "retest"]
    assert len(events) == 1
    assert events[0]["actor"] == "retest"
    assert events[0]["detail"]["retest_event"] == "re-observed"


def test_retest_reobserved_suspected_stays_suspected(lab, rstore, tmp_path):
    f = _seed(rstore, "127.0.0.1", lab.ports["http_old"], status="suspected")
    res = retest_finding(rstore, f.id, scope_path=_scope(tmp_path))
    assert res["event"] == "re-observed"
    assert res["new_status"] == "suspected"


# -- remediated -----------------------------------------------------------------

def test_retest_remediated_transitions_to_fixed(lab, rstore, tmp_path):
    f = _seed(rstore, "127.0.0.1", lab.ports["closed"], status="confirmed")
    res = retest_finding(rstore, f.id, scope_path=_scope(tmp_path))
    assert res["event"] == "remediated"
    assert res["old_status"] == "confirmed"
    assert res["new_status"] == "fixed"
    stored = rstore.get_finding(f.id)
    assert stored.status == "fixed"
    assert any(e["event"] == "remediated" for e in stored.retest_history)
    kinds = [e["event"] for e in rstore.list_finding_events(f.id)]
    assert "retest" in kinds and "status_changed" in kinds
    change = [e for e in rstore.list_finding_events(f.id)
              if e["event"] == "status_changed" and e["actor"] == "retest"][0]
    assert (change["old_status"], change["new_status"]) == ("confirmed",
                                                           "fixed")
    assert change["actor"] == "retest"


def test_retest_suspected_gone_goes_fixed(lab, rstore, tmp_path):
    f = _seed(rstore, "127.0.0.1", lab.ports["closed"], status="suspected")
    res = retest_finding(rstore, f.id, scope_path=_scope(tmp_path))
    assert res["event"] == "remediated"
    assert res["new_status"] == "fixed"


def test_retest_already_fixed_stays_fixed(lab, rstore, tmp_path):
    f = _seed(rstore, "127.0.0.1", lab.ports["closed"], status="fixed")
    res = retest_finding(rstore, f.id, scope_path=_scope(tmp_path))
    assert res["event"] == "still-fixed"
    assert res["new_status"] == "fixed"
    assert rstore.get_finding(f.id).status == "fixed"


# -- regression -----------------------------------------------------------------

def test_retest_regression_fixed_to_confirmed(lab, rstore, tmp_path):
    f = _seed(rstore, "127.0.0.1", lab.ports["ssh_old"], status="fixed")
    res = retest_finding(rstore, f.id, scope_path=_scope(tmp_path))
    assert res["event"] == "re-observed"
    assert res["old_status"] == "fixed"
    assert res["new_status"] == "confirmed"  # regression
    assert rstore.get_finding(f.id).status == "confirmed"


def test_retest_toggle_service_off_and_on(lab, rstore, tmp_path):
    """Full remediate -> regress cycle using the lab's service toggle."""
    scope = _scope(tmp_path)
    f = _seed(rstore, "127.0.0.1", lab.ports["ssh_old"], status="confirmed")
    lab.disable_service("ssh_old")
    gone = retest_finding(rstore, f.id, scope_path=scope)
    assert gone["event"] == "remediated"
    assert gone["new_status"] == "fixed"
    lab.enable_service("ssh_old")
    back = retest_finding(rstore, f.id, scope_path=scope)
    assert back["event"] == "re-observed"
    assert back["new_status"] == "confirmed"


# -- inconclusive / errors ------------------------------------------------------

def test_retest_inconclusive_without_port(rstore, tmp_path):
    f = _seed(rstore, "127.0.0.1", 0, status="confirmed",
              title="Host unresponsive to TCP discovery probes (timeouts)",
              with_evidence=False)
    res = retest_finding(rstore, f.id, scope_path=_scope(tmp_path))
    assert res["event"] == "inconclusive"
    assert res["new_status"] == "confirmed"  # unchanged
    stored = rstore.get_finding(f.id)
    assert stored.status == "confirmed"
    assert stored.last_seen == "2020-01-01T00:00:00+00:00"  # not refreshed


def test_retest_unknown_finding(rstore, tmp_path):
    with pytest.raises(RetestError):
        retest_finding(rstore, "nope", scope_path=_scope(tmp_path))


def test_retest_scope_refused(lab, rstore, tmp_path):
    f = _seed(rstore, "127.0.0.1", lab.ports["ssh_old"])
    with pytest.raises(ScopeError):
        retest_finding(rstore, f.id,
                       scope_path=_scope(tmp_path, target="127.0.0.2"))


# -- batch ----------------------------------------------------------------------

def test_retest_all_batch_and_snapshot(lab, rstore, tmp_path):
    scope = _scope(tmp_path)
    _seed(rstore, "127.0.0.1", lab.ports["ssh_old"], status="confirmed",
          title="open one")
    _seed(rstore, "127.0.0.1", lab.ports["closed"], status="confirmed",
          title="closed one")
    batch = retest_all(rstore, scope_path=scope)
    assert len(batch["results"]) == 2
    by_title = {rstore.get_finding(r["finding_id"]).title: r["event"]
                for r in batch["results"]}
    assert by_title == {"open one": "re-observed", "closed one": "remediated"}
    # A trend snapshot was recorded automatically.
    snaps = rstore.list_snapshots(since="2020-01-01T00:00:00+00:00")
    assert snaps, "expected snapshot rows after retest batch"
    counts = {(s["status"], s["severity"]): s["count"] for s in snaps}
    assert counts.get(("confirmed", "medium")) == 1
    assert counts.get(("fixed", "medium")) == 1


def test_retest_all_status_filter(lab, rstore, tmp_path):
    scope = _scope(tmp_path)
    _seed(rstore, "127.0.0.1", lab.ports["ssh_old"], status="suspected",
          title="s-one")
    _seed(rstore, "127.0.0.1", lab.ports["http_old"], status="confirmed",
          title="c-one")
    batch = retest_all(rstore, status_filter="suspected", scope_path=scope)
    assert len(batch["results"]) == 1
    assert batch["results"][0]["finding_id"] == \
        rstore.list_findings(status="suspected")[0].id


def test_retest_all_invalid_filter(rstore, tmp_path):
    with pytest.raises(RetestError, match="invalid status filter"):
        retest_all(rstore, status_filter="nuked",
                   scope_path=_scope(tmp_path))


def test_retest_all_captures_per_finding_errors(lab, rstore, tmp_path):
    # One in-scope, one out-of-scope: batch keeps going, error is captured.
    _seed(rstore, "127.0.0.1", lab.ports["ssh_old"], status="confirmed",
          title="ok-one")
    _seed(rstore, "10.9.9.9", lab.ports["ssh_old"], status="confirmed",
          title="bad-one")
    batch = retest_all(rstore, scope_path=_scope(tmp_path))
    events = {r["finding_id"]: r["event"] for r in batch["results"]}
    assert len(events) == 2
    assert "error" in set(events.values())
