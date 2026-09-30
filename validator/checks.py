"""Read-only validation checks (V0.3).

Every check is non-destructive and sends no payload data:
  - tcp_reprobe:    plain TCP connect + recv-only banner grab (like discovery)
  - tls_certificate: TLS handshake only; reads the server certificate
  - banner_intel:   offline parsing of an already-captured banner

Nothing here exploits, brute-forces, authenticates, or persists.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import tempfile
from base64 import b64encode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("secplatform.validator")

CONNECT_TIMEOUT = 3.0
BANNER_TIMEOUT = 2.0

# Ports where a TLS handshake is worth attempting.
TLS_PORTS = {443, 8443}


@dataclass
class CheckResult:
    check: str          # "tcp_reprobe" | "tls_certificate" | "banner_intel"
    ok: bool            # the check ran without transport errors
    verdict: str        # "confirmed" | "contradicted" | "intel" | "inconclusive"
    summary: str        # one-line human summary
    detail: Dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# tcp_reprobe
# ---------------------------------------------------------------------------

def tcp_reprobe(host: str, port: int,
                timeout: float = CONNECT_TIMEOUT) -> CheckResult:
    """Re-connect to host:port. Open -> confirmed; refused -> contradicted."""
    detail: Dict = {"host": host, "port": port}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        return CheckResult("tcp_reprobe", True, "contradicted",
                           f"{host}:{port} refused the connection — the service "
                           "appears to be gone.", {**detail, "open": False})
    except socket.timeout:
        return CheckResult("tcp_reprobe", True, "inconclusive",
                           f"{host}:{port} timed out on re-probe — host may be "
                           "down or filtering.", {**detail, "open": False,
                                                   "timed_out": True})
    except OSError as exc:
        return CheckResult("tcp_reprobe", False, "inconclusive",
                           f"re-probe of {host}:{port} failed: {exc}",
                           {**detail, "error": str(exc)})

    # Connected: recv-only banner grab, nothing sent.
    banner = ""
    sock.settimeout(BANNER_TIMEOUT)
    try:
        banner = sock.recv(2048).decode("utf-8", errors="replace").strip()
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    detail.update({"open": True, "banner": banner[:512]})
    return CheckResult(
        "tcp_reprobe", True, "confirmed",
        f"{host}:{port} is still open — finding confirmed."
        + (f" Banner: {banner[:80]!r}." if banner else " No banner returned."),
        detail,
    )


# ---------------------------------------------------------------------------
# tls_certificate
# ---------------------------------------------------------------------------

def _parse_notafter(value: str) -> Optional[datetime]:
    # Format from ssl.getpeercert(): 'Oct 12 21:34:00 2027 GMT'
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _dn_part(dn_tuple, key: str) -> str:
    for rdn in dn_tuple or ():
        for k, v in rdn:
            if k == key:
                return v
    return ""


def _decode_peer_cert(tls: ssl.SSLSocket) -> Optional[dict]:
    """Decode the peer certificate to the getpeercert() dict format.

    With verify_mode=CERT_NONE (deliberate: we want to SEE bad certs instead
    of aborting on them) the dict form of getpeercert() comes back empty, but
    binary_form=True still yields the DER bytes. Decode those via a temp PEM
    file. Returns None when no cert was presented or decoding fails.
    """
    try:
        der = tls.getpeercert(binary_form=True)
    except (ValueError, ssl.SSLError):
        return None
    if not der:
        return None
    pem = ("-----BEGIN CERTIFICATE-----\n"
           + b64encode(der).decode("ascii")
           + "\n-----END CERTIFICATE-----\n")
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem",
                                         delete=True) as fh:
            fh.write(pem)
            fh.flush()
            decoded = ssl._ssl._test_decode_cert(fh.name)  # noqa: SLF001
    except Exception:  # noqa: BLE001 - cert observed but unparsable
        return None
    return decoded or None


def tls_certificate(host: str, port: int,
                    timeout: float = CONNECT_TIMEOUT + 2.0) -> CheckResult:
    """TLS handshake; inspect the certificate. Never verifies (we want to SEE
    bad certs), never sends application data."""
    detail: Dict = {"host": host, "port": port}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # intentional: observe, don't trust
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((host, port))
        tls = ctx.wrap_socket(raw, server_hostname=host)
    except OSError as exc:
        try:
            raw.close()
        except OSError:
            pass
        return CheckResult("tls_certificate", False, "inconclusive",
                           f"TLS handshake with {host}:{port} failed: {exc}",
                           {**detail, "error": str(exc)})
    try:
        cert = _decode_peer_cert(tls)
        version = tls.version() or ""
    finally:
        try:
            tls.close()
        except OSError:
            pass

    if not cert:
        return CheckResult("tls_certificate", True, "inconclusive",
                           f"{host}:{port} completed TLS but no certificate "
                           "could be read.", {**detail, "tls_version": version})

    subject_cn = _dn_part(cert.get("subject"), "commonName")
    issuer_cn = _dn_part(cert.get("issuer"), "commonName")
    not_after = _parse_notafter(cert.get("notAfter", ""))
    now = datetime.now(timezone.utc)
    expired = not_after is not None and not_after < now
    self_signed = bool(subject_cn and issuer_cn and subject_cn == issuer_cn)
    tls_ok = version in ("TLSv1.2", "TLSv1.3")

    detail.update({
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "not_after": cert.get("notAfter", ""),
        "expired": expired,
        "self_signed": self_signed,
        "tls_version": version,
        "tls_version_ok": tls_ok,
    })
    problems = []
    if expired:
        problems.append("certificate is EXPIRED")
    if self_signed:
        problems.append("certificate is self-signed")
    if not tls_ok:
        problems.append(f"negotiated {version or 'unknown TLS version'} (< 1.2)")
    if problems:
        summary = (f"{host}:{port} TLS issues: " + "; ".join(problems) + ".")
        verdict = "intel"
    else:
        summary = (f"{host}:{port} presents a valid certificate for "
                   f"{subject_cn or '(no CN)'} via {version}.")
        verdict = "intel"
    return CheckResult("tls_certificate", True, verdict, summary, detail)


# ---------------------------------------------------------------------------
# banner_intel (offline)
# ---------------------------------------------------------------------------

_BANNER_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("OpenSSH", re.compile(r"OpenSSH_(\d+)\.(\d+)(?:p(\d+))?")),
    ("nginx",   re.compile(r"nginx/(\d+)\.(\d+)\.(\d+)")),
    ("Apache",  re.compile(r"Apache/(\d+)\.(\d+)(?:\.(\d+))?")),
    ("vsftpd",  re.compile(r"vsFTPd (\d+)\.(\d+)\.(\d+)")),
    ("ProFTPD", re.compile(r"ProFTPD (\d+)\.(\d+)\.(\d+)")),
]

# product -> (minimum sane version tuple, why-older-is-bad). Conservative:
# every threshold below is years past release, stated factually.
NOTABLE_EOL: Dict[str, Tuple[Tuple[int, ...], str]] = {
    "OpenSSH": ((7, 4), "OpenSSH 7.4 was released in December 2016; earlier "
                "releases no longer receive security fixes."),
    "nginx":   ((1, 18, 0), "nginx 1.18.0 was released in April 2020; earlier "
                "releases are unmaintained."),
    "Apache":  ((2, 4), "Apache httpd 2.2 reached end of life in January 2018; "
                "only the 2.4 branch is maintained."),
    "vsftpd":  ((3, 0, 3), "vsftpd 3.0.3 dates to 2015."),
    "ProFTPD": ((1, 3, 6), "ProFTPD 1.3.6 dates to 2017."),
}


def _version_tuple(groups: Tuple[str, ...]) -> Tuple[int, ...]:
    return tuple(int(g) for g in groups if g is not None)


def banner_intel(banner: str) -> CheckResult:
    """Parse product/version from a banner; flag long-unmaintained releases."""
    banner = (banner or "").strip()
    if not banner:
        return CheckResult("banner_intel", True, "inconclusive",
                           "No banner to analyze.", {})
    for product, pattern in _BANNER_PATTERNS:
        m = pattern.search(banner)
        if not m:
            continue
        version = _version_tuple(m.groups())
        min_ok, note = NOTABLE_EOL[product]
        # Compare on shared length so (7, 2) < (7, 4) and (8, 9) >= (7, 4).
        outdated = version[:len(min_ok)] < min_ok
        detail = {"product": product, "version": ".".join(map(str, version)),
                  "outdated": outdated}
        if outdated:
            return CheckResult(
                "banner_intel", True, "intel",
                f"{product} {detail['version']} looks unmaintained: {note}",
                detail)
        return CheckResult(
            "banner_intel", True, "intel",
            f"{product} {detail['version']} disclosed in banner; verify it is "
            "patched to a current release.", detail)
    return CheckResult("banner_intel", True, "intel",
                       "Banner parsed but no known product/version pattern "
                       "matched; version status unknown.",
                       {"banner_excerpt": banner[:160]})
