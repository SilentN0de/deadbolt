"""API tests for the V0.4 endpoints: retest, lifecycle, trends."""

import pytest

from sim import SimulatedLab
from storage.db import Store
from storage.models import Evidence, Finding


@pytest.fixture()
def lab():
    with SimulatedLab() as lab:
        yield lab


def _seed(db_path, target, port, title, status="suspected"):
    s = Store(str(db_path))
    try:
        f = Finding.new(target=target, title=title, severity="medium",
                        first_seen="2026-10-01T00:00:00+00:00")
        stored = s.upsert_finding(f)
        s.add_evidence(Evidence(
            id=None, finding_id=stored.id,
            timestamp="2026-10-01T00:00:00+00:00",
            collector="discovery.tcp", excerpt="sim",
            excerpt_hash="ab" * 32,
            detail={"host": target, "port": port}))
        return stored.id
    finally:
        s.close()


def test_retest_one_endpoint(client, lab):
    tc, tmp = client
    fid = _seed(tmp / "api.db", "127.0.0.1", lab.ports["ssh_old"], "open-sim")
    r = tc.post(f"/findings/{fid}/retest")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["event"] == "re-observed"
    assert body["finding_id"] == fid


def test_retest_one_cooldown(client, lab):
    tc, tmp = client
    fid = _seed(tmp / "api.db", "127.0.0.1", lab.ports["ssh_old"], "open-sim")
    assert tc.post(f"/findings/{fid}/retest").status_code == 201
    r = tc.post(f"/findings/{fid}/retest")
    assert r.status_code == 429


def test_retest_one_not_found(client):
    tc, _ = client
    assert tc.post("/findings/nope/retest").status_code == 404


def test_retest_batch_endpoint(client, lab):
    tc, tmp = client
    _seed(tmp / "api.db", "127.0.0.1", lab.ports["ssh_old"], "open-sim")
    _seed(tmp / "api.db", "127.0.0.1", lab.ports["closed"], "closed-sim")
    r = tc.post("/retest", json={})
    assert r.status_code == 201, r.text
    body = r.json()
    assert len(body["results"]) == 2
    assert body["snapshot_at"]
    events = {x["event"] for x in body["results"]}
    assert events == {"re-observed", "remediated"}
    # Snapshot is visible through the trends endpoint.
    t = tc.get("/trends?days=30")
    assert t.status_code == 200
    assert t.json()["series"], "expected snapshot series after batch"


def test_retest_batch_bad_filter(client):
    tc, _ = client
    r = tc.post("/retest", json={"status": "nuked"})
    assert r.status_code == 400


def test_status_change_legal(client):
    tc, tmp = client
    fid = _seed(tmp / "api.db", "127.0.0.1", 1, "lc-sim")
    r = tc.post(f"/findings/{fid}/status",
                json={"status": "confirmed", "note": "operator verified"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["old_status"], body["new_status"]) == ("suspected",
                                                       "confirmed")
    assert body["actor"] == "operator"
    # Timeline records it.
    ev = tc.get(f"/findings/{fid}/events")
    assert ev.status_code == 200
    assert ev.json()[0]["event"] == "status_changed"


def test_status_change_illegal_returns_allowed_list(client):
    tc, tmp = client
    fid = _seed(tmp / "api.db", "127.0.0.1", 1, "lc-sim")
    tc.post(f"/findings/{fid}/status", json={"status": "confirmed"})
    r = tc.post(f"/findings/{fid}/status", json={"status": "suspected"})
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert detail["allowed"] == ["fixed", "accepted-risk", "false-positive"]
    assert detail["current"] == "confirmed"


def test_status_change_unknown_status(client):
    tc, tmp = client
    fid = _seed(tmp / "api.db", "127.0.0.1", 1, "lc-sim")
    r = tc.post(f"/findings/{fid}/status", json={"status": "nuked"})
    assert r.status_code == 400


def test_status_change_unknown_finding(client):
    tc, _ = client
    r = tc.post("/findings/nope/status", json={"status": "confirmed"})
    assert r.status_code == 404


def test_trends_endpoints(client, lab):
    tc, tmp = client
    _seed(tmp / "api.db", "127.0.0.1", lab.ports["ssh_old"], "open-sim")
    tc.post("/retest", json={})  # writes a snapshot
    s = tc.get("/trends/summary")
    assert s.status_code == 200
    body = s.json()
    assert body["open"] == 1
    assert body["fixed_total"] == 0
    assert body["mean_time_to_fix_seconds"] is None
    t = tc.get("/trends?days=7")
    assert t.status_code == 200
    assert t.json()["days"] == 7
