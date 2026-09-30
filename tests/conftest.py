"""Shared fixtures for the test suite."""

import importlib
import socket
import threading

import pytest
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
