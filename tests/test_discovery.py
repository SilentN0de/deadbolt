"""Discovery tests: real loopback scan + safe handled failure."""

import socket
import threading

import pytest
import yaml

import agent.discovery as discovery
from agent.scope import ScopeError
from storage.db import Store


@pytest.fixture()
def banner_server():
    """A temporary TCP server on 127.0.0.1 that sends a banner then closes."""
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
                    conn.sendall(b"SSH-2.0-TestBanner_1.0\r\n")
                except OSError:
                    pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    yield port
    stop.set()
    t.join(timeout=2)
    srv.close()


def _scope_for(tmp_path, target="127.0.0.1"):
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1,
        "authorization_acknowledged": False,
        "targets": [{"target": target, "authorized": True}],
    }))
    return str(p)


def test_discovery_finds_open_port_with_banner(tmp_path, banner_server):
    db = str(tmp_path / "findings.db")
    result = discovery.run_discovery(
        _scope_for(tmp_path), db, ports=[banner_server])

    assert result["status"] == "completed"
    assert result["summary"]["open_ports"] == 1

    store = Store(db)
    try:
        findings = store.list_findings(target="127.0.0.1")
        assert len(findings) == 1
        f = findings[0]
        assert f.title.startswith(f"Open port {banner_server}/tcp")
        assert f.status == "suspected"
        assert len(f.evidence) == 1
        assert "TestBanner" in f.evidence[0].excerpt
        assert len(f.evidence[0].excerpt_hash) == 64  # sha256 hex

        runs = store.list_runs()
        assert len(runs) == 1 and runs[0]["status"] == "completed"
        audit = store.list_audit()
        assert len(audit) == 1 and audit[0]["decision"] == "allow"
    finally:
        store.close()


def test_discovery_denied_scope_writes_audit_and_raises(tmp_path):
    db = str(tmp_path / "findings.db")
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1,
        "targets": [{"target": "0.0.0.0/0", "authorized": True}],
    }))
    with pytest.raises(ScopeError):
        discovery.run_discovery(str(p), db, ports=[80])

    store = Store(db)
    try:
        audit = store.list_audit()
        assert len(audit) == 1
        assert audit[0]["decision"] == "deny"
        assert store.list_runs() == []  # denied runs never start
    finally:
        store.close()


def test_unreachable_host_yields_suspected_finding_no_crash(tmp_path, monkeypatch):
    """Safe handled failure: every probe times out -> suspected finding, no crash."""

    class TimeoutSocket:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, *a):
            pass

        def connect(self, addr):
            raise socket.timeout("timed out")

        def close(self):
            pass

    monkeypatch.setattr(discovery.socket, "socket", TimeoutSocket)

    db = str(tmp_path / "findings.db")
    result = discovery.run_discovery(_scope_for(tmp_path), db, ports=[9999])
    assert result["status"] == "completed"  # did not crash

    store = Store(db)
    try:
        findings = store.list_findings(target="127.0.0.1")
        assert len(findings) == 1
        f = findings[0]
        assert "unresponsive" in f.title
        assert f.status == "suspected"
        assert "timed out" in f.evidence[0].excerpt
    finally:
        store.close()


def test_closed_ports_produce_no_findings_but_complete(tmp_path):
    db = str(tmp_path / "findings.db")
    # Ports 1-3 are (almost) certainly closed on loopback -> refused, not timeouts.
    result = discovery.run_discovery(_scope_for(tmp_path), db, ports=[1, 2, 3])
    assert result["status"] == "completed"
    assert result["summary"]["open_ports"] == 0

    store = Store(db)
    try:
        assert store.list_findings() == []
    finally:
        store.close()
