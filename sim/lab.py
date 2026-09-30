"""Simulated target lab (V0.3).

Spins up FAKE network services bound to 127.0.0.1 on ephemeral ports so the
validator (and the API) can be exercised end-to-end without touching any real
network. Used by the test suite and by scripts/simulate_lab.py for manual runs.

Services:
  ssh_old   - TCP server greeting with an outdated OpenSSH banner
  http_old  - HTTP server with an outdated nginx Server header
  https     - TLS server with a throwaway self-signed cert (needs `openssl`;
              omitted when openssl is unavailable)
  closed    - a port that is guaranteed closed (reserved then released)

Everything is loopback-only, daemon-threaded, and torn down on exit.
"""

from __future__ import annotations

import logging
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
from typing import Callable, Dict, Optional

log = logging.getLogger("secplatform.sim")

Handler = Callable[[socket.socket], None]


class _TCPServer:
    def __init__(self, handler: Handler, tls_cert: Optional[str] = None,
                 tls_key: Optional[str] = None):
        self._handler = handler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._ctx: Optional[ssl.SSLContext] = None
        if tls_cert and tls_key:
            self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ctx.load_cert_chain(tls_cert, tls_key)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "_TCPServer":
        self._thread.start()
        return self

    def _serve(self) -> None:
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            t.start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            if self._ctx is not None:
                conn = self._ctx.wrap_socket(conn, server_side=True)
            with conn:
                self._handler(conn)
        except OSError:
            pass

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


def _greet(banner: bytes) -> Handler:
    def _h(conn: socket.socket) -> None:
        try:
            conn.sendall(banner)
        except OSError:
            pass
        # Hold briefly so a banner grab sees an open connection.
        conn.settimeout(2.0)
        try:
            conn.recv(1024)
        except OSError:
            pass
    return _h


def _make_selfsigned_cert(workdir: str) -> tuple[Optional[str], Optional[str]]:
    """Generate a throwaway self-signed cert with openssl. Returns (cert, key)
    paths, or (None, None) when openssl is unavailable."""
    if shutil.which("openssl") is None:
        log.warning("openssl not found: https sim service disabled")
        return None, None
    cert = f"{workdir}/sim-cert.pem"
    key = f"{workdir}/sim-key.pem"
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "2",
             "-subj", "/CN=127.0.0.1"],
            capture_output=True, check=True, timeout=30)
    except (subprocess.SubprocessError, OSError) as exc:
        log.warning("openssl cert generation failed: %s", exc)
        return None, None
    return cert, key


class SimulatedLab:
    """Context manager: fake services up on entry, down on exit."""

    def __init__(self):
        self._servers: Dict[str, _TCPServer] = {}
        self._workdir: Optional[tempfile.TemporaryDirectory] = None
        self.ports: Dict[str, Optional[int]] = {}

    def __enter__(self) -> "SimulatedLab":
        self._workdir = tempfile.TemporaryDirectory(prefix="secplatform-sim-")
        self._add("ssh_old", _greet(b"SSH-2.0-OpenSSH_7.2p2 Debian-4ubuntu2.8\r\n"))
        self._add("http_old", _greet(
            b"HTTP/1.0 200 OK\r\nServer: nginx/1.14.0\r\n"
            b"Content-Length: 2\r\n\r\nok"))
        cert, key = _make_selfsigned_cert(self._workdir.name)
        if cert and key:
            self._add("https", _greet(b""), tls_cert=cert, tls_key=key)
        else:
            self.ports["https"] = None
        # Guaranteed-closed port: bind, record, release.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
        s.close()
        self.ports["closed"] = closed_port
        log.info("sim lab up: %s", self.ports)
        return self

    def _add(self, name: str, handler: Handler, tls_cert=None, tls_key=None):
        srv = _TCPServer(handler, tls_cert=tls_cert, tls_key=tls_key).start()
        self._servers[name] = srv
        self.ports[name] = srv.port

    def __exit__(self, *exc) -> None:
        for srv in self._servers.values():
            srv.stop()
        if self._workdir is not None:
            self._workdir.cleanup()
        log.info("sim lab down")

    @property
    def https_available(self) -> bool:
        return self.ports.get("https") is not None
