"""API smoke tests (FastAPI TestClient)."""

import importlib
import socket
import threading

import pytest
import yaml
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = str(tmp_path / "api.db")
    monkeypatch.setenv("SECURITY_PLATFORM_DB", db)
    import api.main as main
    importlib.reload(main)
    return TestClient(main.app), tmp_path


@pytest.fixture()
def banner_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with conn:
                try:
                    conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
                except OSError:
                    pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    yield port
    stop.set()
    t.join(timeout=2)
    srv.close()


def _write_scope(tmp_path, targets, ack=False):
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1,
        "authorization_acknowledged": ack,
        "targets": targets,
    }))
    return str(p)


def test_health(client):
    c, _ = client
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_run_and_findings_flow(client, banner_server):
    c, tmp_path = client
    scope = _write_scope(tmp_path, [{"target": "127.0.0.1", "authorized": True}])

    r = c.post("/runs", json={"scope": scope, "ports": str(banner_server)})
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "completed"

    r = c.get("/findings")
    assert r.status_code == 200
    findings = r.json()
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["collector"] == "discovery.tcp"

    fid = findings[0]["id"]
    r = c.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert r.json()["id"] == fid

    r = c.get("/findings/nope")
    assert r.status_code == 404

    r = c.get("/runs")
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_run_refused_scope_returns_400(client):
    c, tmp_path = client
    scope = _write_scope(tmp_path, [{"target": "0.0.0.0/0", "authorized": True}])
    r = c.post("/runs", json={"scope": scope})
    assert r.status_code == 400
    assert "scope refused" in r.json()["detail"]


def test_dashboard_serves_html(client):
    c, _ = client
    r = c.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "findings" in r.text.lower()
