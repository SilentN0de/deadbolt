"""Read-only outside-in probes (V0.5).

The same probe family the local validation pipeline uses, run from the
other side of the network boundary. Every probe is non-destructive:

  port_discovery       TCP connect + recv-only banner grab (no data sent)
  banner_intel         offline parsing of an already-captured banner
                       (reuses validator.checks.banner_intel)
  tls_inspection       TLS handshake only; reads the server certificate.
                       Never verifies (we want to SEE bad certs), never
                       sends application data (reuses validator.checks)
  dns_exposure         MX / TXT lookups via a minimal DNS-over-UDP client.
                       Reads public DNS only; no zone transfers, no
                       brute-forcing subdomains.
  http_security_headers one plain GET / ; reads response headers only to
                       check for standard security headers. No payloads,
                       no auth attempts, no crawling.

Each probe returns a JSON-serializable observation dict. The server
(external/server.py) maps observations to findings — the worker never
decides severities.
"""

from __future__ import annotations

import logging
import random
import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from agent.discovery import RateLimiter
from validator.checks import (CONNECT_TIMEOUT, banner_intel, tcp_reprobe,
                              tls_certificate)

log = logging.getLogger("deadbolt.external.probes")

ALL_PROBES = ("port_discovery", "banner_intel", "tls_inspection",
              "dns_exposure", "http_security_headers")

# Curated ports for outside-in discovery: services commonly (and
# accidentally) exposed to the internet. Deliberately short — an
# outside-in sweep should be quiet, not a full port scan.
EXTERNAL_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306,
                  3389, 5432, 5900, 8080, 8443]

# Security headers checked by http_security_headers.
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)


# ---------------------------------------------------------------------------
# port_discovery
# ---------------------------------------------------------------------------

def port_discovery(host: str, ports: Optional[List[int]] = None,
                   timeout: float = CONNECT_TIMEOUT) -> Dict[str, Any]:
    """TCP connect sweep + recv-only banner grab over curated ports.

    Returns {"host":..., "open": [{"port","banner","service"}, ...],
    "closed_or_filtered": N}. Paced by a per-call rate limiter so an
    outside-in sweep stays quiet.
    """
    from agent.discovery import PORTS as _PORT_LABELS

    ports = ports or EXTERNAL_PORTS
    limiter = RateLimiter(0.05)  # ~20 attempts/sec max, per worker
    open_ports: List[Dict[str, Any]] = []
    closed = 0
    for port in ports:
        limiter.wait()
        res = tcp_reprobe(host, port, timeout=timeout)
        if res.detail.get("open"):
            svc = _PORT_LABELS.get(port, ("unknown",))[0]
            open_ports.append({
                "port": port,
                "service": svc,
                "banner": res.detail.get("banner", "")[:512],
            })
        else:
            closed += 1
    return {"host": host, "open": open_ports,
            "closed_or_filtered": closed}


# ---------------------------------------------------------------------------
# tls_inspection
# ---------------------------------------------------------------------------

def tls_inspection(host: str, port: int = 443) -> Dict[str, Any]:
    """Inspect the TLS certificate presented by host:port (handshake only)."""
    res = tls_certificate(host, port)
    return {"host": host, "port": port, "ok": res.ok,
            "verdict": res.verdict, "summary": res.summary,
            "detail": res.detail}


# ---------------------------------------------------------------------------
# dns_exposure — minimal DNS-over-UDP client (MX / TXT only)
# ---------------------------------------------------------------------------

_QTYPE = {"MX": 15, "TXT": 16}
_DNS_PORT = 53


def _build_query(name: str, qtype: int, txid: int) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        struct.pack(">B", len(part)) + part.encode("ascii")
        for part in name.rstrip(".").split(".")
    ) + b"\x00" + struct.pack(">HH", qtype, 1)
    return header + question


def _read_name(packet: bytes, offset: int) -> Tuple[str, int]:
    """Read a (possibly compressed) domain name at offset."""
    labels: List[str] = []
    jumped = False
    end = offset
    for _ in range(64):  # paranoia: never loop forever on hostile packets
        if offset >= len(packet):
            break
        length = packet[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(packet):
                break
            pointer = struct.unpack(">H", packet[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        offset += 1
        labels.append(packet[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), end


def _parse_response(packet: bytes, txid: int, qtype: int) -> List[Dict[str, Any]]:
    if len(packet) < 12:
        return []
    (rxid, _flags, qdcount, ancount, _, _) = struct.unpack(">HHHHHH", packet[:12])
    if rxid != txid or ancount == 0:
        return []
    offset = 12
    for _ in range(qdcount):  # skip questions
        _, offset = _read_name(packet, offset)
        offset += 4
    records: List[Dict[str, Any]] = []
    for _ in range(ancount):
        _, offset = _read_name(packet, offset)
        if offset + 10 > len(packet):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlen]
        offset += rdlen
        if rtype != qtype:
            continue
        if rtype == 15 and len(rdata) >= 2:  # MX
            preference = struct.unpack(">H", rdata[:2])[0]
            exchange, _ = _read_name(packet, offset - rdlen + 2)
            records.append({"type": "MX", "preference": preference,
                            "exchange": exchange})
        elif rtype == 16:  # TXT: one or more <len><bytes> strings
            parts: List[str] = []
            i = 0
            while i < len(rdata):
                n = rdata[i]
                i += 1
                parts.append(rdata[i:i + n].decode("utf-8", "replace"))
                i += n
            records.append({"type": "TXT", "text": "".join(parts)})
    return records


def _udp_resolver(name: str, qtype_name: str, server: str,
                  timeout: float) -> List[Dict[str, Any]]:
    qtype = _QTYPE[qtype_name]
    txid = random.randint(0, 65535)
    packet = _build_query(name, qtype, txid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, _DNS_PORT))
        data, _ = sock.recvfrom(4096)
    except OSError as exc:
        raise RuntimeError(f"DNS query for {name}/{qtype_name} failed: {exc}")
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return _parse_response(packet=data, txid=txid, qtype=qtype)


# SPF regex: v=spf1 somewhere in a TXT record (case-insensitive, first token).
_SPF_RE = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)


def dns_exposure(domain: str,
                 resolver: Optional[Callable[[str, str], List[Dict[str, Any]]]] = None,
                 dns_server: str = "8.8.8.8",
                 timeout: float = 3.0) -> Dict[str, Any]:
    """Read public MX / TXT records for a domain. No zone transfers, no
    subdomain brute-forcing — just the records the domain publishes.

    `resolver(name, qtype_name)` may be injected (tests / lab); otherwise a
    minimal DNS-over-UDP client is used.
    """
    domain = domain.strip().rstrip(".").lower()
    import ipaddress
    try:
        ipaddress.ip_address(domain)
        raise ValueError(f"dns_exposure needs a bare domain, got {domain!r}")
    except ValueError as exc:
        if "bare domain" in str(exc):
            raise
    if not domain or "/" in domain or ":" in domain or " " in domain:
        raise ValueError(f"dns_exposure needs a bare domain, got {domain!r}")

    def _resolve(name: str, qtype: str) -> List[Dict[str, Any]]:
        if resolver is not None:
            return resolver(name, qtype)
        return _udp_resolver(name, qtype, dns_server, timeout)

    mx = _resolve(domain, "MX")
    txt = _resolve(domain, "TXT")
    spf = [r for r in txt if _SPF_RE.match(r.get("text", "").strip())]
    return {
        "domain": domain,
        "mx": [{"preference": r["preference"], "exchange": r["exchange"]}
               for r in mx],
        "txt_count": len(txt),
        "has_spf": bool(spf),
        "spf_record": spf[0]["text"][:512] if spf else "",
        # Never include raw TXT contents beyond SPF: TXT records can hold
        # verification tokens and other semi-sensitive strings. Counts only.
    }


# ---------------------------------------------------------------------------
# http_security_headers
# ---------------------------------------------------------------------------

@dataclass
class HeaderResult:
    ok: bool
    missing: List[str] = field(default_factory=list)
    present: Dict[str, str] = field(default_factory=dict)
    summary: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)


def http_security_headers(host: str, port: int = 80, use_tls: bool = False,
                          timeout: float = 5.0) -> HeaderResult:
    """One plain GET / ; read response headers only.

    Checks for standard security headers. Sends nothing but a minimal
    GET request — no payloads, no auth attempts, no crawling. The body is
    never read beyond the header terminator.
    """
    detail: Dict[str, Any] = {"host": host, "port": port, "use_tls": use_tls}
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((host, port))
        sock: socket.socket = raw
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # observe only, like tls_inspection
            sock = ctx.wrap_socket(raw, server_hostname=host)
    except OSError as exc:
        try:
            raw.close()
        except OSError:
            pass
        return HeaderResult(False, summary=f"could not connect to {host}:{port}: {exc}",
                            detail={**detail, "error": str(exc)})
    try:
        # Minimal, well-formed request. HTTP/1.0 + Connection: close keeps
        # the server from holding the connection open.
        request = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                   f"User-Agent: Deadbolt-ExternalAssessment/0.5\r\n"
                   f"Connection: close\r\n\r\n").encode("ascii")
        sock.settimeout(timeout)
        try:
            sock.sendall(request)
        except OSError as exc:
            return HeaderResult(False, summary=f"request to {host}:{port} failed: {exc}",
                                detail={**detail, "error": str(exc)})
        # Read until the header terminator; never slurp the body.
        buf = b""
        try:
            while b"\r\n\r\n" not in buf and len(buf) < 16384:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        head = buf.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        lines = head.split("\r\n")
        status_line = lines[0] if lines else ""
        if not status_line.startswith("HTTP/"):
            # Not an HTTP service (e.g. an SSH banner): nothing to check.
            return HeaderResult(
                False,
                summary=f"{host}:{port} did not answer like HTTP "
                        f"(got {status_line[:60]!r}) — skipping header check.",
                detail={**detail, "status_line": status_line[:128],
                        "looks_like_http": False})
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        detail.update({"status_line": status_line[:128],
                       "present": present, "missing": missing})
        if missing:
            summary = (f"{host}:{port} is missing {len(missing)} security "
                       f"header(s): {', '.join(missing)}.")
        else:
            summary = (f"{host}:{port} presents all {len(SECURITY_HEADERS)} "
                       "checked security headers.")
        return HeaderResult(True, missing=missing, present=present,
                            summary=summary, detail=detail)
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# one-shot assessment runner (used by the worker client)
# ---------------------------------------------------------------------------

def run_probes(targets: List[str], probes: List[str],
               ports: Optional[List[int]] = None,
               dns_resolver: Optional[Callable] = None) -> List[Dict[str, Any]]:
    """Run the requested probes against each target. Returns observation
    dicts in the wire format the API ingests:

      {"probe": <name>, "target": <host-or-domain>, "observations": [...]}

    `ports` overrides the default port list for port_discovery (and the
    banner sweep built on it). Unknown probe names raise ValueError.
    `dns_resolver` is injected for tests/lab; the real UDP client is used
    otherwise.
    """
    unknown = [p for p in probes if p not in ALL_PROBES]
    if unknown:
        raise ValueError(f"unknown probe(s) {unknown}; allowed: {list(ALL_PROBES)}")
    results: List[Dict[str, Any]] = []
    for target in targets:
        for probe in probes:
            started = time.time()
            try:
                if probe == "port_discovery":
                    sweep = port_discovery(target, ports=ports)
                    # One observation per open port (the shape ingest maps
                    # to findings); the sweep totals ride along on each.
                    obs = [{**o,
                            "closed_or_filtered": sweep["closed_or_filtered"]}
                           for o in sweep["open"]]
                elif probe == "banner_intel":
                    # Banner intel needs banners: sweep the (possibly
                    # overridden) ports, then parse offline.
                    obs = _banner_sweep(target, ports=ports)
                elif probe == "tls_inspection":
                    obs = _tls_sweep(target, ports=ports)
                elif probe == "dns_exposure":
                    obs = dns_exposure(target, resolver=dns_resolver)
                elif probe == "http_security_headers":
                    obs = _headers_sweep(target, ports=ports)
                else:  # unreachable: validated above
                    raise ValueError(f"unknown probe: {probe}")
                results.append({"probe": probe, "target": target,
                                "observations": obs if isinstance(obs, list) else [obs],
                                "ok": True,
                                "elapsed_s": round(time.time() - started, 2)})
            except Exception as exc:  # one probe never kills the assessment
                log.warning("probe %s on %s failed: %s", probe, target, exc)
                results.append({"probe": probe, "target": target,
                                "observations": [],
                                "ok": False, "error": str(exc)[:300],
                                "elapsed_s": round(time.time() - started, 2)})
    return results


def _banner_sweep(host: str,
                  ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """Parse banners from ports found open by port_discovery, offline.

    Basing banner intel on discovered-open ports (rather than a fixed port
    list) keeps the probe self-contained: it only touches what the
    discovery sweep already found.
    """
    out: List[Dict[str, Any]] = []
    found = port_discovery(host, ports=ports)
    for entry in found["open"]:
        banner = entry.get("banner", "")
        if not banner:
            continue
        intel = banner_intel(banner)
        out.append({"host": host, "port": entry["port"],
                    "banner": banner[:512],
                    "product": intel.detail.get("product", ""),
                    "version": intel.detail.get("version", ""),
                    "outdated": bool(intel.detail.get("outdated", False)),
                    "summary": intel.summary})
    return out


def _tls_sweep(host: str,
               ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """TLS inspection on HTTPS ports (handshake only)."""
    out: List[Dict[str, Any]] = []
    limiter = RateLimiter(0.05)
    for port in ports or (443, 8443):
        limiter.wait()
        obs = tls_inspection(host, port)
        if obs["ok"]:
            out.append(obs)
    return out


def _headers_sweep(host: str,
                   ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """Security-header check. Default: plain HTTP on 80, TLS on 443.

    With a port override, each port is tried plain first, then TLS —
    ports that don't answer like HTTP are skipped.
    """
    out: List[Dict[str, Any]] = []

    def _record(res: HeaderResult, port: int, use_tls: bool) -> None:
        out.append({"host": host, "port": port, "use_tls": use_tls,
                    "missing": res.missing, "present": res.present,
                    "summary": res.summary})

    if ports:
        for port in ports:
            plain = http_security_headers(host, port, use_tls=False)
            if plain.ok:
                _record(plain, port, False)
                continue
            tls = http_security_headers(host, port, use_tls=True)
            if tls.ok:
                _record(tls, port, True)
        return out

    http = http_security_headers(host, 80, use_tls=False)
    if http.ok:
        _record(http, 80, False)
    https = http_security_headers(host, 443, use_tls=True)
    if https.ok:
        _record(https, 443, True)
    return out
