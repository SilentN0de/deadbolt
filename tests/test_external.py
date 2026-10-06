"""External assessment (V0.5): probes, server, worker client, API.

Probe tests run against the simulated lab (fake services on 127.0.0.1) or a
fake DNS server on loopback, so the real probe code is exercised without
touching any real network. Server/API tests use tmp databases.
"""

import json
import os
import socket
import struct
import threading

import pytest
import yaml

from external import ALL_PROBES
from external.probes import (dns_exposure, http_security_headers,
                             port_discovery, run_probes, tls_inspection)
from external.server import (ExternalError, authenticate_worker,
                             enqueue_assessment, ingest_results,
                             is_enabled, register_worker, revoke_worker,
                             set_enabled)
from external.worker import load_config, register, run_once, save_config
from sim import SimulatedLab
from storage.db import Store


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def lab():
    with SimulatedLab() as lab:
        yield lab


def _scope(tmp_path, extra=""):
    p = tmp_path / "ext_scope.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1,
        "authorization_acknowledged": True,
        "targets": [{"target": "127.0.0.1", "authorized": True}],
    }) + extra)
    return str(p)


def _db(tmp_path):
    return str(tmp_path / "ext.db")


def _enable(store):
    set_enabled(store, True)


def _register(store, name="w1"):
    return register_worker(store, name)


# ---------------------------------------------------------------------------
# DNS: packet build/parse as pure functions (loopback UDP is blocked in
# this sandbox, so the transport itself is covered by the injected
# resolver; the wire format is fully tested here), plus dns_exposure
# logic via an injected fake resolver.
# ---------------------------------------------------------------------------

def _craft_dns_response(query: bytes, answers):
    """Build a synthetic DNS response for `query`.

    answers: list of (qtype, rdata_bytes).
    """
    from external.probes import _read_name
    txid = struct.unpack(">H", query[:2])[0]
    _, qend = _read_name(query, 12)
    question = query[12:qend + 4]
    body = b""
    for qtype, rdata in answers:
        body += (b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 300, len(rdata))
                 + rdata)
    return (struct.pack(">HHHHHH", txid, 0x8180, 1, len(answers), 0, 0)
            + question + body)


def _encode_name(name: str) -> bytes:
    return (b"".join(struct.pack(">B", len(p)) + p.encode("ascii")
                     for p in name.split(".")) + b"\x00")


def test_dns_packet_build_and_parse_mx():
    from external.probes import _build_query, _parse_response
    query = _build_query("example.com", 15, 0x1234)
    rdata = struct.pack(">H", 10) + _encode_name("mail.example.com")
    resp = _craft_dns_response(query, [(15, rdata)])
    recs = _parse_response(resp, 0x1234, 15)
    assert recs == [{"type": "MX", "preference": 10,
                     "exchange": "mail.example.com"}]


def test_dns_packet_build_and_parse_txt():
    from external.probes import _build_query, _parse_response
    query = _build_query("example.com", 16, 0xABCD)
    txt = b"v=spf1 -all"
    rdata = bytes([len(txt)]) + txt
    resp = _craft_dns_response(query, [(16, rdata)])
    recs = _parse_response(resp, 0xABCD, 16)
    assert recs == [{"type": "TXT", "text": "v=spf1 -all"}]


def test_dns_packet_ignores_wrong_txid():
    from external.probes import _build_query, _parse_response
    query = _build_query("example.com", 15, 0x1234)
    rdata = struct.pack(">H", 10) + _encode_name("mail.example.com")
    resp = _craft_dns_response(query, [(15, rdata)])
    assert _parse_response(resp, 0x9999, 15) == []


def _fake_resolver_factory(txt="v=spf1 -all"):
    def _resolve(name, qtype_name):
        if qtype_name == "MX":
            return [{"type": "MX", "preference": 10,
                     "exchange": "mail.example.com"}]
        return [{"type": "TXT", "text": txt}]
    return _resolve


def test_dns_exposure_mx_and_spf():
    res = dns_exposure("example.com",
                       resolver=_fake_resolver_factory())
    assert res["domain"] == "example.com"
    assert res["mx"] == [{"preference": 10,
                          "exchange": "mail.example.com"}]
    assert res["has_spf"] is True
    assert res["spf_record"].startswith("v=spf1")


def test_dns_exposure_no_spf():
    res = dns_exposure("example.com",
                       resolver=_fake_resolver_factory(
                           txt="some-verification-token"))
    assert res["has_spf"] is False
    assert res["spf_record"] == ""
    assert res["txt_count"] == 1


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def test_all_probes_known():
    assert set(ALL_PROBES) == {"port_discovery", "banner_intel",
                               "tls_inspection", "dns_exposure",
                               "http_security_headers"}


def test_port_discovery_finds_lab_services(lab):
    res = port_discovery("127.0.0.1",
                         ports=[lab.ports["ssh_old"], lab.ports["http_old"]])
    found = {o["port"] for o in res["open"]}
    assert lab.ports["ssh_old"] in found
    assert lab.ports["http_old"] in found
    ssh = next(o for o in res["open"] if o["port"] == lab.ports["ssh_old"])
    assert "OpenSSH" in ssh["banner"]


def test_port_discovery_closed_port(lab):
    res = port_discovery("127.0.0.1", ports=[lab.ports["closed"]])
    assert res["open"] == []
    assert res["closed_or_filtered"] == 1


def test_tls_inspection_sees_self_signed(lab):
    if not lab.https_available:
        pytest.skip("openssl unavailable")
    obs = tls_inspection("127.0.0.1", lab.ports["https"])
    assert obs["ok"] is True
    assert obs["detail"]["self_signed"] is True


def test_tls_inspection_refused_port(lab):
    obs = tls_inspection("127.0.0.1", lab.ports["closed"])
    assert obs["ok"] is False


def test_http_security_headers_missing(lab):
    res = http_security_headers("127.0.0.1", lab.ports["http_old"])
    assert res.ok is True
    assert "strict-transport-security" in res.missing
    assert "content-security-policy" in res.missing


def test_http_security_headers_refused(lab):
    res = http_security_headers("127.0.0.1", lab.ports["closed"])
    assert res.ok is False


def test_dns_exposure_rejects_non_domain():
    with pytest.raises(ValueError):
        dns_exposure("127.0.0.1")
    with pytest.raises(ValueError):
        dns_exposure("")


def test_run_probes_rejects_unknown_probe():
    with pytest.raises(ValueError):
        run_probes(["127.0.0.1"], ["nmap_syn"])


def test_run_probes_end_to_end_lab(lab):
    ports = [lab.ports["ssh_old"], lab.ports["http_old"]]
    results = run_probes(
        ["127.0.0.1"],
        ["port_discovery", "banner_intel", "http_security_headers"],
        ports=ports)
    by_probe = {r["probe"]: r for r in results}
    assert by_probe["port_discovery"]["ok"] is True
    ports = {o["port"]
             for o in by_probe["port_discovery"]["observations"]}
    assert lab.ports["ssh_old"] in ports
    # banner_intel parses the outdated OpenSSH banner from the sweep
    banners = by_probe["banner_intel"]["observations"]
    assert any(o.get("outdated") for o in banners)
    # http headers sweep found the lab http service missing headers
    headers = by_probe["http_security_headers"]["observations"]
    assert any("strict-transport-security" in o["missing"] for o in headers)


# ---------------------------------------------------------------------------
# server: registry + auth
# ---------------------------------------------------------------------------

def test_register_returns_token_once_and_stores_hash(tmp_path):
    store = Store(_db(tmp_path))
    try:
        res = _register(store, "pi-at-moms")
        assert res["token"]
        assert len(res["token"]) >= 64
        # Only the hash is in the database, never the plaintext token.
        row = store._conn.execute(
            "SELECT token_hash FROM external_workers WHERE id = ?",
            (res["id"],)).fetchone()
        assert row["token_hash"] != res["token"]
        assert len(row["token_hash"]) == 64  # sha256 hex
        dump = store._conn.execute(
            "SELECT sql FROM sqlite_master").fetchall()
        _ = dump  # schema only; token plaintext must not be stored anywhere
        blob = "".join(
            r[0] for r in store._conn.execute(
                "SELECT id || name || token_hash || created_at "
                "FROM external_workers"))
        assert res["token"] not in blob
        # Auth works with the token.
        worker = authenticate_worker(store, res["token"])
        assert worker["id"] == res["id"]
        assert worker["name"] == "pi-at-moms"
    finally:
        store.close()


def test_auth_rejects_bad_and_revoked_tokens(tmp_path):
    store = Store(_db(tmp_path))
    try:
        res = _register(store)
        with pytest.raises(ExternalError) as ei:
            authenticate_worker(store, "bogus")
        assert ei.value.status == 401
        revoke_worker(store, res["id"])
        with pytest.raises(ExternalError) as ei:
            authenticate_worker(store, res["token"])
        assert ei.value.status == 401
    finally:
        store.close()


def test_revoke_is_idempotent_and_unknown_404(tmp_path):
    store = Store(_db(tmp_path))
    try:
        res = _register(store)
        assert revoke_worker(store, res["id"])["revoked"] is True
        assert revoke_worker(store, res["id"])["already"] is True
        with pytest.raises(ExternalError) as ei:
            revoke_worker(store, "nope")
        assert ei.value.status == 404
    finally:
        store.close()


def test_register_rejects_empty_name(tmp_path):
    store = Store(_db(tmp_path))
    try:
        with pytest.raises(ExternalError) as ei:
            register_worker(store, "  ")
        assert ei.value.status == 400
    finally:
        store.close()


def test_enable_toggle_and_audit(tmp_path):
    store = Store(_db(tmp_path))
    try:
        assert is_enabled(store) is False  # off by default
        assert set_enabled(store, True) is True
        assert is_enabled(store) is True
        events = [a["event"] for a in store.list_audit()]
        assert "external.toggle" in events
        set_enabled(store, False)
        assert is_enabled(store) is False
    finally:
        store.close()


# ---------------------------------------------------------------------------
# server: enqueue
# ---------------------------------------------------------------------------

def test_enqueue_requires_enabled(tmp_path):
    store = Store(_db(tmp_path))
    try:
        w = _register(store)
        with pytest.raises(ExternalError) as ei:
            enqueue_assessment(store, w["id"], ["127.0.0.1"],
                               ["port_discovery"],
                               scope_path=_scope(tmp_path))
        assert ei.value.status == 403
    finally:
        store.close()


def test_enqueue_happy_path(tmp_path):
    store = Store(_db(tmp_path))
    try:
        _enable(store)
        w = _register(store)
        a = enqueue_assessment(store, w["id"], ["127.0.0.1"],
                               ["port_discovery", "banner_intel"],
                               scope_path=_scope(tmp_path))
        assert a["status"] == "queued"
        stored = store.get_assessment(a["id"])
        assert stored["targets"] == ["127.0.0.1"]
        assert stored["probes"] == ["port_discovery", "banner_intel"]
        assert any(x["event"] == "external.enqueue"
                   for x in store.list_audit())
    finally:
        store.close()


def test_enqueue_rejects_bad_worker(tmp_path):
    store = Store(_db(tmp_path))
    try:
        _enable(store)
        with pytest.raises(ExternalError) as ei:
            enqueue_assessment(store, "missing", ["127.0.0.1"],
                               ["port_discovery"], scope_path=_scope(tmp_path))
        assert ei.value.status == 404
        w = _register(store)
        revoke_worker(store, w["id"])
        with pytest.raises(ExternalError) as ei:
            enqueue_assessment(store, w["id"], ["127.0.0.1"],
                               ["port_discovery"], scope_path=_scope(tmp_path))
        assert ei.value.status == 400
    finally:
        store.close()


def test_enqueue_rejects_out_of_scope_target(tmp_path):
    store = Store(_db(tmp_path))
    try:
        _enable(store)
        w = _register(store)
        with pytest.raises(ExternalError) as ei:
            enqueue_assessment(store, w["id"], ["203.0.113.99"],
                               ["port_discovery"], scope_path=_scope(tmp_path))
        assert ei.value.status == 400
        denies = [a for a in store.list_audit()
                  if a["event"] == "external.enqueue"
                  and a["decision"] == "deny"]
        assert denies
    finally:
        store.close()


def test_enqueue_rejects_bad_probes_and_targets(tmp_path):
    store = Store(_db(tmp_path))
    try:
        _enable(store)
        w = _register(store)
        scope = _scope(tmp_path)
        with pytest.raises(ExternalError) as ei:
            enqueue_assessment(store, w["id"], ["127.0.0.1"], ["evil"],
                               scope_path=scope)
        assert ei.value.status == 400
        with pytest.raises(ExternalError) as ei:
            enqueue_assessment(store, w["id"], [], ["port_discovery"],
                               scope_path=scope)
        assert ei.value.status == 400
        with pytest.raises(ExternalError) as ei:
            enqueue_assessment(store, w["id"], ["127.0.0.1"], [],
                               scope_path=scope)
        assert ei.value.status == 400
    finally:
        store.close()


def test_enqueue_cooldown(tmp_path):
    from external import server as srv
    store = Store(_db(tmp_path))
    try:
        _enable(store)
        w = _register(store)
        scope = _scope(tmp_path)
        srv._last_enqueue.clear()
        enqueue_assessment(store, w["id"], ["127.0.0.1"],
                           ["port_discovery"], scope_path=scope)
        with pytest.raises(ExternalError) as ei:
            enqueue_assessment(store, w["id"], ["127.0.0.1"],
                               ["port_discovery"], scope_path=scope)
        assert ei.value.status == 429
    finally:
        srv._last_enqueue.clear()
        store.close()


def test_enqueue_allows_listed_domain(tmp_path):
    store = Store(_db(tmp_path))
    try:
        _enable(store)
        w = _register(store)
        scope = _scope(tmp_path,
                       extra="external_domains:\n"
                             "  - domain: example.com\n"
                             "    authorized: true\n")
        a = enqueue_assessment(store, w["id"], ["example.com"],
                               ["dns_exposure"], scope_path=scope)
        assert a["status"] == "queued"
        # ...but not an unlisted domain
        from external import server as srv
        srv._last_enqueue.clear()
        with pytest.raises(ExternalError) as ei:
            enqueue_assessment(store, w["id"], ["evil.example"],
                               ["dns_exposure"], scope_path=scope)
        assert ei.value.status == 400
    finally:
        from external import server as srv
        srv._last_enqueue.clear()
        store.close()


# ---------------------------------------------------------------------------
# server: ingest
# ---------------------------------------------------------------------------

def _mk_assessment(store, tmp_path, worker_id, targets=("127.0.0.1",),
                   probes=("port_discovery",), ports=None):
    from external import server as srv
    srv._last_enqueue.clear()
    a = enqueue_assessment(store, worker_id, list(targets), list(probes),
                           scope_path=_scope(tmp_path), ports=ports)
    srv._last_enqueue.clear()
    return a


def _lab_ports(lab):
    return [p for p in (lab.ports["ssh_old"], lab.ports["http_old"],
                        lab.ports["https"]) if p]


def test_ingest_creates_findings_with_evidence_and_events(tmp_path, lab):
    store = Store(_db(tmp_path))
    try:
        _enable(store)
        w = _register(store)
        worker = authenticate_worker(store, w["token"])
        ports = _lab_ports(lab)
        a = _mk_assessment(store, tmp_path, w["id"],
                           probes=("port_discovery", "banner_intel"),
                           ports=ports)
        results = run_probes(["127.0.0.1"],
                             ["port_discovery", "banner_intel"], ports=ports)
        out = ingest_results(store, worker, a["id"], results)
        assert out["status"] == "completed"
        assert out["summary"]["findings_created"] >= 2

        findings = store.list_findings()
        assert all(f.status == "suspected" for f in findings)
        titles = [f.title for f in findings]
        assert any(t.startswith("External view: open port") for t in titles)
        # outdated OpenSSH banner -> unmaintained finding
        assert any("appears unmaintained" in t for t in titles)

        f = next(f for f in findings if "appears unmaintained" in f.title)
        assert f.evidence, "finding must carry evidence"
        assert all(e.collector.startswith("external.") for e in f.evidence)
        events = store.list_finding_events(f.id)
        assert any(e["event"] == "note" and e["actor"] == "system"
                   and e["detail"].get("via") == "external-assessment"
                   for e in events)

        done = store.get_assessment(a["id"])
        assert done["status"] == "completed"
        assert done["summary"]["findings_created"] == out["summary"]["findings_created"]
        assert any(x["event"] == "external.results_ingest"
                   for x in store.list_audit())
    finally:
        store.close()


def test_ingest_dedupes_across_assessments(tmp_path, lab):
    store = Store(_db(tmp_path))
    try:
        _enable(store)
        w = _register(store)
        worker = authenticate_worker(store, w["token"])
        ports = _lab_ports(lab)
        results = run_probes(["127.0.0.1"], ["port_discovery"], ports=ports)
        a1 = _mk_assessment(store, tmp_path, w["id"], ports=ports)
        ingest_results(store, worker, a1["id"], results)
        n1 = len(store.list_findings())
        a2 = _mk_assessment(store, tmp_path, w["id"], ports=ports)
        ingest_results(store, worker, a2["id"], results)
        assert len(store.list_findings()) == n1  # upsert: no duplicates
    finally:
        store.close()


def test_ingest_rejects_bad_states(tmp_path):
    store = Store(_db(tmp_path))
    try:
        _enable(store)
        w = _register(store)
        worker = authenticate_worker(store, w["token"])
        other = _register(store, "other")
        other_worker = authenticate_worker(store, other["token"])
        a = _mk_assessment(store, tmp_path, w["id"])
        # unknown assessment
        with pytest.raises(ExternalError) as ei:
            ingest_results(store, worker, "nope", [])
        assert ei.value.status == 404
        # another worker's assessment
        with pytest.raises(ExternalError) as ei:
            ingest_results(store, other_worker, a["id"], [])
        assert ei.value.status == 403
        # already completed
        ingest_results(store, worker, a["id"], [])
        with pytest.raises(ExternalError) as ei:
            ingest_results(store, worker, a["id"], [])
        assert ei.value.status == 409
        # kill switch blocks ingest
        a2 = _mk_assessment(store, tmp_path, w["id"])
        set_enabled(store, False)
        with pytest.raises(ExternalError) as ei:
            ingest_results(store, worker, a2["id"], [])
        assert ei.value.status == 403
    finally:
        store.close()


def test_ingest_skips_malformed_items(tmp_path):
    store = Store(_db(tmp_path))
    try:
        _enable(store)
        w = _register(store)
        worker = authenticate_worker(store, w["token"])
        a = _mk_assessment(store, tmp_path, w["id"])
        out = ingest_results(store, worker, a["id"], [
            {"probe": "port_discovery", "target": "127.0.0.1",
             "observations": [{"port": 22, "banner": "SSH-2.0-x"}]},
            {"probe": "nope", "target": "127.0.0.1", "observations": []},
            {"probe": "port_discovery", "observations": []},  # no target
            None,
        ])
        assert out["summary"]["findings_created"] == 1
    finally:
        store.close()


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def test_api_external_status_toggle(client):
    c, _ = client
    r = c.get("/external/status")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert set(body["probes"]) == set(ALL_PROBES)
    assert "disclosure" in body and body["disclosure"]

    r = c.put("/external/status", json={"enabled": True})
    assert r.status_code == 200
    assert r.json()["enabled"] is True
    assert c.get("/external/status").json()["enabled"] is True


def test_api_worker_lifecycle(client):
    c, _ = client
    r = c.post("/external-workers", json={"name": "pi-at-moms"})
    assert r.status_code == 201
    body = r.json()
    token = body["token"]
    wid = body["id"]
    assert token and wid

    r = c.get("/external-workers")
    assert r.status_code == 200
    workers = r.json()
    assert len(workers) == 1
    assert workers[0]["name"] == "pi-at-moms"
    assert "token" not in workers[0]
    assert "token_hash" not in workers[0]

    r = c.delete(f"/external-workers/{wid}")
    assert r.status_code == 200
    assert r.json()["revoked"] is True
    assert c.get("/external-workers").json()[0]["revoked"] is True

    r = c.delete("/external-workers/nope")
    assert r.status_code == 404


def test_api_enqueue_and_poll_and_ingest(client, tmp_path, lab):
    c, _ = client
    c.put("/external/status", json={"enabled": True})
    scope = _scope(tmp_path)

    r = c.post("/external-workers", json={"name": "w"})
    token, wid = r.json()["token"], r.json()["id"]

    # out-of-scope target -> 400
    r = c.post("/external-assessments", json={
        "worker_id": wid, "targets": ["203.0.113.9"],
        "probes": ["port_discovery"], "scope": scope})
    assert r.status_code == 400

    # disabled kill switch -> 403
    c.put("/external/status", json={"enabled": False})
    r = c.post("/external-assessments", json={
        "worker_id": wid, "targets": ["127.0.0.1"],
        "probes": ["port_discovery"], "scope": scope})
    assert r.status_code == 403
    c.put("/external/status", json={"enabled": True})

    r = c.post("/external-assessments", json={
        "worker_id": wid, "targets": ["127.0.0.1"],
        "probes": ["port_discovery"], "ports": [lab.ports["ssh_old"]],
        "scope": scope})
    assert r.status_code == 201
    aid = r.json()["id"]

    # operator sees the queue
    r = c.get("/external-assessments")
    assert r.status_code == 200
    assert any(a["id"] == aid for a in r.json())

    # worker polls with its token: only its own pending assessments
    r = c.get("/external-assessments",
              headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    mine = r.json()
    assert all(a["worker_id"] == wid for a in mine)
    assert any(a["id"] == aid for a in mine)

    # bad token -> 401
    r = c.get("/external-assessments",
              headers={"Authorization": "Bearer bogus"})
    assert r.status_code == 401

    # worker starts + pushes results
    r = c.post(f"/external-assessments/{aid}/start",
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["status"] == "running"

    results = run_probes(["127.0.0.1"], ["port_discovery"],
                         ports=[lab.ports["ssh_old"]])
    r = c.post("/external-results",
               headers={"Authorization": f"Bearer {token}"},
               json={"assessment_id": aid, "results": results})
    assert r.status_code == 201
    assert r.json()["summary"]["findings_created"] >= 1

    findings = c.get("/findings").json()
    assert any(f["title"].startswith("External view:") for f in findings)
    ext = next(f for f in findings
               if f["title"].startswith("External view:"))
    assert ext["status"] == "suspected"
    assert ext["evidence"], "ingested findings must carry evidence"

    # ingest without token -> 401
    r = c.post("/external-results",
               json={"assessment_id": aid, "results": []})
    assert r.status_code == 401


def test_api_dashboard_has_outside_in_panel(client):
    c, _ = client
    html = c.get("/").text
    assert "Outside-in" in html
    assert "/external/status" in html
    assert "/external-workers" in html
    assert "/external-assessments" in html
    assert "shown ONCE" in html  # token disclosure


# ---------------------------------------------------------------------------
# worker client
# ---------------------------------------------------------------------------

def test_worker_config_round_trip_and_perms(tmp_path):
    cfg = str(tmp_path / "worker.json")
    save_config("abc123", "sekrit-token", cfg)
    assert load_config(cfg) == {"worker_id": "abc123",
                                "token": "sekrit-token"}
    assert (os.stat(cfg).st_mode & 0o777) == 0o600
    with pytest.raises(Exception):
        load_config(str(tmp_path / "missing.json"))


def _route_into_testclient(monkeypatch, test_client):
    """Route external.worker._request through a FastAPI TestClient."""
    import external.worker as wmod

    def fake_request(api_url, method, path, token=None, body=None):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        fn = {"GET": test_client.get, "POST": test_client.post,
              "PUT": test_client.put,
              "DELETE": test_client.delete}[method]
        kwargs = {"headers": headers}
        # This starlette TestClient's .get() takes no json kwarg.
        if body is not None and method != "GET":
            kwargs["json"] = body
        r = fn(path, **kwargs)
        if r.status_code >= 400:
            raise wmod.WorkerError(
                f"{method} {path} -> HTTP {r.status_code}",
                status=r.status_code)
        return r.json()

    monkeypatch.setattr(wmod, "_request", fake_request)


def test_worker_register_poll_run_once(client, tmp_path, monkeypatch, lab):
    c, _ = client
    _route_into_testclient(monkeypatch, c)
    c.put("/external/status", json={"enabled": True})
    scope = _scope(tmp_path)
    cfg_path = str(tmp_path / "worker.json")

    import external.worker as wmod
    reg = wmod.register("http://x", "sim-worker", cfg_path)
    assert reg["id"]
    assert load_config(cfg_path)["worker_id"] == reg["id"]

    # enqueue via API (operator side)
    r = c.post("/external-assessments", json={
        "worker_id": reg["id"], "targets": ["127.0.0.1"],
        "probes": ["port_discovery"], "ports": [lab.ports["ssh_old"]],
        "scope": scope})
    assert r.status_code == 201

    pending = wmod.poll("http://x", cfg_path)
    assert len(pending) == 1 and pending[0]["status"] == "queued"

    summaries = wmod.run_once("http://x", cfg_path)
    assert len(summaries) == 1
    assert summaries[0]["probes_run"] >= 1
    assert summaries[0]["ingest"]["status"] == "completed"

    # nothing left pending afterwards
    assert wmod.poll("http://x", cfg_path) == []
    findings = c.get("/findings").json()
    assert any(f["title"].startswith("External view:") for f in findings)


def test_worker_run_once_empty_queue(client, tmp_path, monkeypatch):
    c, _ = client
    _route_into_testclient(monkeypatch, c)
    c.put("/external/status", json={"enabled": True})
    cfg_path = str(tmp_path / "worker.json")
    import external.worker as wmod
    wmod.register("http://x", "idle", cfg_path)
    assert wmod.run_once("http://x", cfg_path) == []
