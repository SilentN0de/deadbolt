"""Analyst tests: knowledge coverage and explanation quality (V0.2)."""

from agent.discovery import PORTS
from analyst.explain import explain_finding
from analyst.knowledge import HOST_UNRESPONSIVE, SERVICE_KB, UNKNOWN_SERVICE
from storage.models import Evidence, Finding


def _finding(title, severity="info", banner=""):
    f = Finding.new(target="10.0.0.5", title=title, severity=severity,
                    first_seen="2026-09-30T00:00:00Z")
    raw = banner or "no banner"
    f.evidence.append(Evidence(
        id=1, finding_id=f.id, timestamp="2026-09-30T00:00:00Z",
        collector="discovery.tcp", excerpt=raw[:512],
        excerpt_hash="ab" * 32, detail={"host": "10.0.0.5", "port": 22},
    ))
    return f


def test_kb_covers_every_discovery_port():
    for port, (service, _sev, _rem) in PORTS.items():
        assert service in SERVICE_KB, f"no knowledge for {service} (port {port})"
        kb = SERVICE_KB[service]
        assert kb["what"] and kb["risk"], f"empty knowledge for {service}"
        assert len(kb["remediation_steps"]) >= 2, f"thin steps for {service}"


def test_explanation_structure_ssh():
    f = _finding("Open port 22/tcp (SSH) — banner: 'SSH-2.0-OpenSSH_8.9'",
                 banner="SSH-2.0-OpenSSH_8.9")
    e = explain_finding(f)
    d = e.to_dict()
    assert d["finding_id"] == f.id
    assert "10.0.0.5" in d["summary"] and "22" in d["summary"]
    assert "handshake" in d["what_was_observed"]
    assert "SSH-2.0-OpenSSH_8.9" in d["what_was_observed"]
    # Version in banner -> information-disclosure note.
    assert "information disclosure" in d["what_was_observed"]
    assert "brute-force" in d["why_it_matters"] or "brute" in d["why_it_matters"]
    assert len(d["what_to_do"]) >= 3
    assert "suspected" in d["confidence"]
    assert d["evidence_refs"] == ["discovery.tcp:abababababab"]


def test_explanation_no_banner():
    f = _finding("Open port 80/tcp (HTTP) — no banner returned")
    e = explain_finding(f)
    assert "no banner" in e.what_was_observed
    assert "captured banner" not in e.confidence


def test_explanation_unknown_port_falls_back():
    f = _finding("Open port 9999/tcp (unknown) — no banner returned")
    e = explain_finding(f)
    assert e.what_it_means == UNKNOWN_SERVICE["what"]
    assert e.what_to_do == UNKNOWN_SERVICE["remediation_steps"]


def test_explanation_unresponsive_host():
    f = Finding.new(target="10.0.0.99",
                    title="Host unresponsive to TCP discovery probes (timeouts)",
                    severity="info", first_seen="2026-09-30T00:00:00Z")
    e = explain_finding(f)
    assert e.what_it_means == HOST_UNRESPONSIVE["what"]
    assert e.what_to_do == HOST_UNRESPONSIVE["remediation_steps"]
    assert "not assessed" in e.confidence


def test_explanation_without_evidence():
    f = Finding.new(target="10.0.0.5", title="Open port 443/tcp (HTTPS)",
                    severity="info", first_seen="2026-09-30T00:00:00Z")
    e = explain_finding(f)
    assert e.evidence_refs == []
    assert "No evidence was stored" in e.what_was_observed


def test_explanation_endpoint(client):
    c, tmp_path = client
    from storage.db import Store
    store = Store(str(tmp_path / "api.db"))
    f = Finding.new(target="10.0.0.5", title="Open port 22/tcp (SSH)",
                    severity="info", first_seen="2026-09-30T00:00:00Z")
    stored = store.upsert_finding(f)
    store.close()

    r = c.get(f"/findings/{stored.id}/explanation")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["finding_id"] == stored.id
    for key in ("summary", "what_was_observed", "what_it_means",
                "why_it_matters", "what_to_do", "confidence"):
        assert body[key], f"empty {key}"
    assert "SSH" in body["summary"]

    r = c.get("/findings/does-not-exist/explanation")
    assert r.status_code == 404
