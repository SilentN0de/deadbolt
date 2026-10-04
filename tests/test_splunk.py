"""Splunk exporter tests. All offline: no Splunk instance needed."""

import json
import os

import pytest

from exporters import splunk as splunk_mod
from storage.db import Store
from storage.models import Finding


def _finding(**kw):
    base = dict(id="f1", target="10.0.0.12",
                title="Open port 445/tcp", severity="medium",
                status="suspected", first_seen="2026-09-30T16:57:00+00:00",
                last_seen="2026-09-30T17:01:00+00:00", remediation="Verify.")
    base.update(kw)
    return Finding(**base)


def test_finding_to_event_fields():
    ev = splunk_mod.finding_to_event(_finding())
    assert ev["sourcetype"] == "deadbolt:finding"
    assert ev["source"] == "deadbolt"
    inner = ev["event"]
    assert inner["dest"] == "10.0.0.12"
    assert inner["dest_port"] == 445
    assert inner["severity"] == "medium"
    assert inner["finding_id"] == "f1"
    assert isinstance(ev["time"], float)


def test_finding_to_event_no_port():
    ev = splunk_mod.finding_to_event(_finding(title="Host silent"))
    assert "dest_port" not in ev["event"]


def test_write_spool_creates_jsonl(tmp_path):
    events = [splunk_mod.finding_to_event(_finding()),
              splunk_mod.finding_to_event(_finding(id="f2"))]
    result = splunk_mod.write_spool(events, spool_dir=str(tmp_path))
    assert result["events"] == 2
    assert result["mode"] == "spool"
    lines = open(result["path"], encoding="utf-8").read().strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0])["event"]["finding_id"] == "f1"


def test_send_hec_requires_config(monkeypatch):
    monkeypatch.setattr(splunk_mod, "HEC_URL", "")
    monkeypatch.setattr(splunk_mod, "HEC_TOKEN", "")
    with pytest.raises(RuntimeError, match="not configured"):
        splunk_mod.send_hec([])


def test_send_hec_payload_shape(monkeypatch):
    calls = {}

    class FakeResp:
        status_code = 200
        text = '{"text":"Success"}'

        def json(self):
            return {"text": "Success"}

    class FakeClient:
        def __init__(self, timeout=None):
            calls["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, endpoint, headers=None, content=None):
            calls["endpoint"] = endpoint
            calls["headers"] = headers
            calls["content"] = content
            return FakeResp()

    import httpx
    monkeypatch.setattr(httpx, "Client", FakeClient)
    events = [splunk_mod.finding_to_event(_finding())]
    result = splunk_mod.send_hec(
        events, url="https://splunk.example:8088", token="tok",
        index="security")
    assert result["events"] == 1
    assert calls["endpoint"] == \
        "https://splunk.example:8088/services/collector/event"
    assert calls["headers"] == {"Authorization": "Splunk tok"}
    body = json.loads(calls["content"])
    assert body["index"] == "security"
    assert body["event"]["dest_port"] == 445


def test_send_hec_rejects_on_http_error(monkeypatch):
    class FakeResp:
        status_code = 403
        text = "forbidden"

    class FakeClient:
        def __init__(self, timeout=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, *a, **k):
            return FakeResp()

    import httpx
    monkeypatch.setattr(httpx, "Client", FakeClient)
    with pytest.raises(RuntimeError, match="HTTP 403"):
        splunk_mod.send_hec([splunk_mod.finding_to_event(_finding())],
                            url="https://x:8088", token="tok")


def _seed_finding(db_path):
    store = Store(db_path)
    try:
        store.upsert_finding(_finding())
    finally:
        store.close()


def test_api_export_spool(client, tmp_path, monkeypatch):
    c, _ = client
    monkeypatch.setattr(splunk_mod, "SPOOL_DIR", str(tmp_path / "spool"))
    _seed_finding(os.environ["SECURITY_PLATFORM_DB"])
    r = c.post("/export/splunk", json={"mode": "spool"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["events"] == 1
    assert os.path.exists(body["path"])
    # audit-logged
    store = Store(os.environ["SECURITY_PLATFORM_DB"])
    try:
        audits = store.list_audit(limit=5)
    finally:
        store.close()
    assert any(a["event"] == "export.splunk" and a["decision"] == "allow"
               for a in audits)


def test_api_export_hec_unconfigured_is_503(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(splunk_mod, "HEC_URL", "")
    monkeypatch.setattr(splunk_mod, "HEC_TOKEN", "")
    r = c.post("/export/splunk", json={"mode": "hec"})
    assert r.status_code == 503


def test_api_export_bad_mode(client):
    c, _ = client
    r = c.post("/export/splunk", json={"mode": "carrier-pigeon"})
    assert r.status_code == 400
