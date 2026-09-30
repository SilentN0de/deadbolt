"""Validator tests: checks + orchestration against the simulated lab (V0.3).

The sim lab spins up FAKE services on 127.0.0.1 (outdated SSH banner, outdated
nginx header, self-signed HTTPS, guaranteed-closed port) so validation is
tested end-to-end without touching any real network.
"""

from datetime import datetime, timezone

import pytest
import yaml

from agent.scope import ScopeError
from sim import SimulatedLab
from storage.db import Store
from storage.models import Evidence, Finding
from validator import banner_intel, tcp_reprobe, tls_certificate, validate_finding
from validator.checks import _parse_notafter
from validator.runner import ValidationError


@pytest.fixture()
def lab():
    with SimulatedLab() as lab:
        yield lab


@pytest.fixture()
def vstore(tmp_path):
    s = Store(str(tmp_path / "v.db"))
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


def _seed_finding(store, target, port, banner=""):
    f = Finding.new(target=target, title=f"Open port {port}/tcp (SIM)",
                    severity="info", first_seen="2026-09-30T00:00:00Z")
    stored = store.upsert_finding(f)
    raw = banner or "no banner"
    store.add_evidence(Evidence(
        id=None, finding_id=stored.id, timestamp="2026-09-30T00:00:00Z",
        collector="discovery.tcp", excerpt=raw[:512],
        excerpt_hash="ab" * 32,
        detail={"host": target, "port": port}))
    return store.get_finding(stored.id)


# -- individual checks --------------------------------------------------------

def test_tcp_reprobe_confirms_open(lab):
    r = tcp_reprobe("127.0.0.1", lab.ports["ssh_old"])
    assert r.ok and r.verdict == "confirmed"
    assert "OpenSSH_7.2" in r.detail["banner"]


def test_tcp_reprobe_contradicted_closed(lab):
    r = tcp_reprobe("127.0.0.1", lab.ports["closed"])
    assert r.ok and r.verdict == "contradicted"
    assert r.detail["open"] is False


def test_tls_certificate_selfsigned(lab):
    if not lab.https_available:
        pytest.skip("openssl unavailable: https sim disabled")
    r = tls_certificate("127.0.0.1", lab.ports["https"])
    assert r.ok, r.summary
    assert r.detail["self_signed"] is True
    assert r.detail["tls_version"].startswith("TLSv1")
    assert "self-signed" in r.summary


def test_tls_notafter_parsing():
    dt = _parse_notafter("Oct 12 21:34:00 2027 GMT")
    assert dt is not None and dt.year == 2027
    past = _parse_notafter("Jan 01 00:00:00 2020 GMT")
    assert past < datetime.now(timezone.utc)
    assert _parse_notafter("garbage") is None


def test_banner_intel_flags_outdated_openssh():
    r = banner_intel("SSH-2.0-OpenSSH_7.2p2 Debian-4ubuntu2.8")
    assert r.verdict == "intel" and r.detail["outdated"] is True
    assert r.detail["product"] == "OpenSSH"
    assert "2016" in r.summary


def test_banner_intel_modern_version_ok():
    r = banner_intel("SSH-2.0-OpenSSH_9.3")
    assert r.detail["outdated"] is False
    assert "verify it is patched" in r.summary


def test_banner_intel_unknown_banner():
    r = banner_intel("HELLO STRANGER")
    assert r.verdict == "intel"
    assert "no known product/version pattern" in r.summary


def test_banner_intel_empty():
    r = banner_intel("")
    assert r.verdict == "inconclusive"


# -- orchestration ------------------------------------------------------------

def test_validate_confirms_and_transitions(vstore, tmp_path, lab):
    f = _seed_finding(vstore, "127.0.0.1", lab.ports["ssh_old"],
                      banner="SSH-2.0-OpenSSH_7.2p2")
    out = validate_finding(vstore, f.id, scope_path=_scope(tmp_path))
    assert out["outcome"] == "confirmed"
    assert out["status_before"] == "suspected"
    assert out["status_after"] == "confirmed"
    assert [r["check"] for r in out["results"]] == ["tcp_reprobe", "banner_intel"]

    stored = vstore.get_finding(f.id)
    assert stored.status == "confirmed"
    assert any(e.collector == "validator.tcp_reprobe" for e in stored.evidence)
    assert any("unmaintained" in e.excerpt or "outdated" in e.excerpt
               for e in stored.evidence if e.collector == "validator.banner_intel")

    vals = vstore.list_validations(f.id)
    assert len(vals) == 1 and vals[0]["outcome"] == "confirmed"

    audits = vstore.list_audit()
    assert any(a["event"] == "validation.attempt" and a["decision"] == "allow"
               for a in audits)


def test_validate_false_positive_on_closed_port(vstore, tmp_path, lab):
    f = _seed_finding(vstore, "127.0.0.1", lab.ports["closed"])
    out = validate_finding(vstore, f.id,
                           checks=["tcp_reprobe"],
                           scope_path=_scope(tmp_path))
    assert out["outcome"] == "false-positive"
    assert out["status_after"] == "false-positive"
    assert vstore.get_finding(f.id).status == "false-positive"


def test_validate_tls_check_on_https_sim(vstore, tmp_path, lab):
    if not lab.https_available:
        pytest.skip("openssl unavailable: https sim disabled")
    f = _seed_finding(vstore, "127.0.0.1", lab.ports["https"])
    out = validate_finding(vstore, f.id,
                           checks=["tls_certificate"],
                           scope_path=_scope(tmp_path))
    assert out["outcome"] == "intel"  # no reprobe run: intel only
    tls = next(r for r in out["results"] if r["check"] == "tls_certificate")
    assert tls["detail"]["self_signed"] is True


def test_validate_scope_refused(vstore, tmp_path, lab):
    f = _seed_finding(vstore, "127.0.0.1", lab.ports["ssh_old"])
    with pytest.raises(ScopeError):
        validate_finding(vstore, f.id, scope_path=_scope(tmp_path, "127.0.0.2"))
    audits = vstore.list_audit()
    assert any(a["event"] == "validation.attempt" and a["decision"] == "deny"
               for a in audits)
    # No validation stored, status untouched.
    assert vstore.list_validations(f.id) == []
    assert vstore.get_finding(f.id).status == "suspected"


def test_validate_unknown_check(vstore, tmp_path, lab):
    f = _seed_finding(vstore, "127.0.0.1", lab.ports["ssh_old"])
    with pytest.raises(ValidationError):
        validate_finding(vstore, f.id, checks=["nmap_nuke"],
                         scope_path=_scope(tmp_path))


def test_validate_missing_finding(vstore, tmp_path):
    with pytest.raises(ValidationError):
        validate_finding(vstore, "nope", scope_path=_scope(tmp_path))


# -- API ----------------------------------------------------------------------

def test_validate_endpoint_flow(client, tmp_path, lab):
    c, _ = client
    from storage.db import Store as _Store
    s = _Store(str(tmp_path / "api.db"))
    f = _seed_finding(s, "127.0.0.1", lab.ports["ssh_old"],
                      banner="SSH-2.0-OpenSSH_7.2p2")
    s.close()
    scope = _scope(tmp_path)

    r = c.post(f"/findings/{f.id}/validate", json={"scope": scope})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["outcome"] == "confirmed"
    assert body["status_after"] == "confirmed"

    r = c.get(f"/findings/{f.id}/validations")
    assert r.status_code == 200 and len(r.json()) == 1

    # Cooldown: immediate repeat is rejected.
    r = c.post(f"/findings/{f.id}/validate", json={"scope": scope})
    assert r.status_code == 429

    r = c.post("/findings/does-not-exist/validate", json={"scope": scope})
    assert r.status_code == 404

    r = c.get("/findings/does-not-exist/validations")
    assert r.status_code == 404


def test_validate_endpoint_scope_refused(client, tmp_path, lab):
    c, _ = client
    from storage.db import Store as _Store
    s = _Store(str(tmp_path / "api.db"))
    f = _seed_finding(s, "127.0.0.1", lab.ports["ssh_old"])
    s.close()
    r = c.post(f"/findings/{f.id}/validate",
               json={"scope": _scope(tmp_path, "127.0.0.2")})
    assert r.status_code == 400
    assert "scope refused" in r.json()["detail"]
