"""Regression tests for the 2026-10-02 bug-hunt fixes.

Covers: socket FD leaks (discovery + validator), stable finding titles for
dedupe, /31 scope expansion, API validate check-list hardening, and the
Splunk HEC empty-batch guard.

Also covers the V0.5.1 finding-identity fix: pre-V0.3 titles embedded the
observed banner ("— no banner returned", "— banner: '...'"), and the old
exact-string upsert duplicated those findings on the first modern scan.
"""

import socket

import yaml

import agent.discovery as discovery
from agent.scope import load_scope
from storage.db import Store
from validator import checks as vchecks


def _tracking_socket_factory(calls):
    real = socket.socket

    class TrackingSocket(real):
        def close(self):
            calls.append("close")
            super().close()

    return TrackingSocket


# -- socket leaks -----------------------------------------------------------

def test_probe_port_closes_socket_on_refused(monkeypatch):
    calls = []
    monkeypatch.setattr(
        discovery.socket, "socket", _tracking_socket_factory(calls))
    res = discovery.probe_port("127.0.0.1", 1, discovery.RateLimiter(0))
    assert res.refused
    assert calls, "socket was not closed after refused connect"


def test_probe_port_closes_socket_on_timeout(monkeypatch):
    calls = []

    class TimeoutSocket:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, *a):
            pass

        def connect(self, addr):
            raise socket.timeout("timed out")

        def recv(self, n):
            raise AssertionError("should not get here")

        def close(self):
            calls.append("close")

    monkeypatch.setattr(discovery.socket, "socket", TimeoutSocket)
    res = discovery.probe_port("127.0.0.1", 9999, discovery.RateLimiter(0))
    assert res.timed_out
    assert calls, "socket was not closed after connect timeout"


def test_tcp_reprobe_closes_socket_on_refused(monkeypatch):
    calls = []
    monkeypatch.setattr(
        vchecks.socket, "socket", _tracking_socket_factory(calls))
    res = vchecks.tcp_reprobe("127.0.0.1", 1)
    assert res.verdict == "contradicted"
    assert calls, "validator socket was not closed after refused connect"


# -- stable titles / dedupe -------------------------------------------------

def test_banner_change_updates_finding_instead_of_duplicating(tmp_path):
    db = str(tmp_path / "t.db")
    store = Store(db)
    try:
        ts = "2026-10-02T00:00:00+00:00"
        r1 = discovery.ProbeResult(
            host="127.0.0.1", port=2222, open=True, banner="SSH-2.0-Old_1.0")
        rep1 = discovery.DiscoveryReport(
            targets=["127.0.0.1"], results=[r1],
            started_at=ts, finished_at=ts)
        assert len(discovery.report_to_findings(rep1, store)) == 1

        # Same port, banner changed (service upgrade): must NOT duplicate.
        r2 = discovery.ProbeResult(
            host="127.0.0.1", port=2222, open=True, banner="SSH-2.0-New_2.0")
        rep2 = discovery.DiscoveryReport(
            targets=["127.0.0.1"], results=[r2],
            started_at=ts, finished_at=ts)
        discovery.report_to_findings(rep2, store)

        findings = store.list_findings(target="127.0.0.1")
        assert len(findings) == 1
        assert findings[0].title == "Open port 2222/tcp (unknown)"
        assert len(findings[0].evidence) == 2
        assert "New_2.0" in findings[0].evidence[-1].excerpt
    finally:
        store.close()


# -- /31 scope ---------------------------------------------------------------

def _scope(tmp_path, target):
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump({
        "authorization_acknowledged": False,
        "targets": [{"target": target, "authorized": True}],
    }))
    return str(p)


def test_scope_31_keeps_both_addresses(tmp_path):
    d = load_scope(_scope(tmp_path, "10.0.0.0/31"))
    assert d.targets == ["10.0.0.0", "10.0.0.1"]


def test_scope_32_and_30_unchanged(tmp_path):
    assert load_scope(_scope(tmp_path, "10.0.0.5/32")).targets == ["10.0.0.5"]
    # /30 drops network + broadcast, keeps the two usable hosts
    assert load_scope(_scope(tmp_path, "10.0.0.0/30")).targets == [
        "10.0.0.1", "10.0.0.2"]


# -- API validate check-list hardening ----------------------------------------

def _api_scope(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump({
        "authorization_acknowledged": False,
        "targets": [{"target": "127.0.0.1", "authorized": True}],
    }))
    return str(p)


def _finding_id(client, tmp_path, banner_server):
    c, _ = client
    scope = _api_scope(tmp_path)
    r = c.post("/runs", json={"scope": scope, "ports": str(banner_server)})
    assert r.status_code == 201, r.text
    return c, scope, c.get("/findings").json()[0]["id"]


def test_validate_unknown_check_is_400_not_404(client, tmp_path, banner_server):
    c, scope, fid = _finding_id(client, tmp_path, banner_server)
    r = c.post(f"/findings/{fid}/validate",
               json={"scope": scope, "checks": ["bogus_check"]})
    assert r.status_code == 400
    assert "unknown check" in r.json()["detail"]


def test_validate_empty_checks_is_400(client, tmp_path, banner_server):
    c, scope, fid = _finding_id(client, tmp_path, banner_server)
    r = c.post(f"/findings/{fid}/validate",
               json={"scope": scope, "checks": []})
    assert r.status_code == 400


def test_validate_duplicate_checks_run_once(client, tmp_path, banner_server):
    c, scope, fid = _finding_id(client, tmp_path, banner_server)
    r = c.post(f"/findings/{fid}/validate",
               json={"scope": scope,
                     "checks": ["tcp_reprobe", "tcp_reprobe"]})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["checks"] == ["tcp_reprobe"]
    assert [x["check"] for x in body["results"]] == ["tcp_reprobe"]


# -- Splunk HEC ---------------------------------------------------------------

def test_send_hec_empty_events_skips_post():
    from exporters import splunk as splunk_exporter
    # Would raise/connect if it tried a real POST; must return early.
    res = splunk_exporter.send_hec(
        [], url="http://127.0.0.1:1", token="dummy")
    assert res == {"mode": "hec",
                   "endpoint": "http://127.0.0.1:1/services/collector/event",
                   "events": 0, "ack": {}}


# -- finding identity: title variants must not duplicate (V0.5.1) -------------

from storage.models import (Finding, canonical_finding_title,
                            finding_identity)


def _upsert(store, target, title, ts, severity="info"):
    return store.upsert_finding(Finding.new(
        target=target, title=title, severity=severity, first_seen=ts))


def test_identity_ignores_banner_suffixes():
    base = finding_identity("10.0.0.12", "Open port 445/tcp (SMB)")
    assert finding_identity(
        "10.0.0.12", "Open port 445/tcp (SMB) — no banner returned") == base
    assert finding_identity(
        "10.0.0.12", "Open port 445/tcp (SMB) — banner: 'SMBv1'") == base
    # Port, service, vantage, and target are all part of the identity.
    assert finding_identity("10.0.0.12", "Open port 139/tcp (SMB)") != base
    assert finding_identity("10.0.0.12", "Open port 445/tcp (NetBIOS)") != base
    assert finding_identity("10.0.0.13", "Open port 445/tcp (SMB)") != base
    assert finding_identity(
        "10.0.0.12", "External view: open port 445/tcp (SMB)") != base
    assert canonical_finding_title(
        "Open port 22/tcp (SSH) — banner: 'SSH-2.0-X'"
    ) == "Open port 22/tcp (SSH)"


def test_upsert_matches_legacy_no_banner_title(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    try:
        old = _upsert(store, "127.0.0.1",
                      "Open port 445/tcp (SMB) — no banner returned",
                      "2026-09-30T00:00:00+00:00", severity="medium")
        new = _upsert(store, "127.0.0.1", "Open port 445/tcp (SMB)",
                      "2026-11-10T00:00:00+00:00", severity="medium")
        assert new.id == old.id  # same finding, not a duplicate row
        findings = store.list_findings(target="127.0.0.1")
        assert len(findings) == 1
        assert findings[0].title == "Open port 445/tcp (SMB)"  # canonicalized
        assert findings[0].first_seen == "2026-09-30T00:00:00+00:00"
        assert findings[0].last_seen == "2026-11-10T00:00:00+00:00"
    finally:
        store.close()


def test_upsert_matches_legacy_banner_title(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    try:
        old = _upsert(
            store, "10.0.0.12",
            "Open port 22/tcp (SSH) — banner: 'SSH-2.0-OpenSSH_8.9'",
            "2026-09-30T00:00:00+00:00")
        new = _upsert(store, "10.0.0.12", "Open port 22/tcp (SSH)",
                      "2026-11-10T00:00:00+00:00")
        assert new.id == old.id
        assert len(store.list_findings(target="10.0.0.12")) == 1
    finally:
        store.close()


def test_upsert_variant_after_canonical_still_one_row(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    try:
        first = _upsert(store, "10.0.0.1", "Open port 443/tcp (HTTPS)",
                        "2026-11-10T00:00:00+00:00")
        # A legacy-format writer re-observing must not duplicate either.
        second = _upsert(store, "10.0.0.1",
                         "Open port 443/tcp (HTTPS) — no banner returned",
                         "2026-11-10T01:00:00+00:00")
        assert second.id == first.id
        findings = store.list_findings(target="10.0.0.1")
        assert len(findings) == 1
        assert findings[0].title == "Open port 443/tcp (HTTPS)"
    finally:
        store.close()


def test_distinct_ports_and_vantages_stay_distinct(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    try:
        ts = "2026-11-10T00:00:00+00:00"
        _upsert(store, "10.0.0.12", "Open port 445/tcp (SMB)", ts,
                severity="medium")
        _upsert(store, "10.0.0.12", "Open port 139/tcp (NetBIOS)", ts)
        _upsert(store, "10.0.0.12",
                "External view: open port 445/tcp (SMB)", ts,
                severity="medium")
        _upsert(store, "10.0.0.12",
                "Host unresponsive to TCP discovery probes (timeouts)", ts)
        assert len(store.list_findings(target="10.0.0.12")) == 4
    finally:
        store.close()
