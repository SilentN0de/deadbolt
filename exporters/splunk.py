"""Splunk integration: export findings as Splunk-ready events.

Two ingest paths, both local-first and operator-triggered:

1. Spool file (default, no Splunk credentials needed):
   findings are appended as JSON Lines to data/splunk_spool/. Point a
   Splunk Universal Forwarder at that directory with sourcetype
   "secplatform:finding" and Splunk ingests them on its own schedule.

2. HEC (HTTP Event Collector):
   POSTs events straight to your Splunk HEC endpoint. Requires
   SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN in the environment -- never in
   the repo, never in the config file.

Events use Splunk CIM-friendly field names (dest, dest_port, severity)
so they work with the Common Information Model out of the box.
"""
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from validator.runner import _host_port

SOURCETYPE = "secplatform:finding"
SOURCE = "security-platform"

SPOOL_DIR = os.environ.get(
    "SECURITY_PLATFORM_SPLUNK_SPOOL",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "data", "splunk_spool"),
)

HEC_URL = os.environ.get("SPLUNK_HEC_URL", "")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
HEC_INDEX = os.environ.get("SPLUNK_HEC_INDEX", "")
HEC_SOURCETYPE = os.environ.get("SPLUNK_HEC_SOURCETYPE", SOURCETYPE)


def _epoch(iso_ts: str) -> float:
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError, AttributeError):
        return time.time()


def finding_to_event(finding) -> Dict[str, Any]:
    """Convert a Finding into a Splunk HEC event envelope."""
    host, port = _host_port(finding)
    inner = {
        "finding_id": finding.id,
        "dest": host,
        "target": finding.target,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "remediation": finding.remediation,
        "evidence_count": len(finding.evidence or []),
        "vendor_product": "security-platform",
    }
    if port is not None:
        inner["dest_port"] = port
    return {
        "time": _epoch(finding.last_seen or finding.first_seen),
        "source": SOURCE,
        "sourcetype": SOURCETYPE,
        "event": inner,
    }


def write_spool(events: List[Dict[str, Any]],
                spool_dir: Optional[str] = None) -> Dict[str, Any]:
    """Append events as JSON Lines for a Universal Forwarder to pick up."""
    spool_dir = spool_dir or SPOOL_DIR
    os.makedirs(spool_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = os.path.join(spool_dir, f"secplatform-{stamp}.log")
    with open(path, "a", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev, default=str) + "\n")
    return {"mode": "spool", "path": path, "events": len(events)}


def send_hec(events: List[Dict[str, Any]],
             url: Optional[str] = None,
             token: Optional[str] = None,
             index: Optional[str] = None,
             timeout: float = 15.0) -> Dict[str, Any]:
    """POST events to a Splunk HEC endpoint. Raises RuntimeError if
    unconfigured; raises on HTTP errors so failures are never silent."""
    import httpx  # local import: only needed for the HEC path

    url = (url or HEC_URL).rstrip("/")
    token = token or HEC_TOKEN
    if not url or not token:
        raise RuntimeError(
            "HEC not configured: set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN "
            "in the environment.")
    if not events:
        # Nothing to send: don't POST an empty body (HEC would 400).
        return {"mode": "hec", "endpoint": f"{url}/services/collector/event",
                "events": 0, "ack": {}}
    endpoint = f"{url}/services/collector/event"
    payload_events = []
    for ev in events:
        e = dict(ev)
        e["sourcetype"] = HEC_SOURCETYPE
        if index or HEC_INDEX:
            e["index"] = index or HEC_INDEX
        payload_events.append(e)
    # HEC accepts one event per request or newline-delimited batching.
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            endpoint,
            headers={"Authorization": f"Splunk {token}"},
            content="\n".join(json.dumps(e, default=str)
                              for e in payload_events),
        )
    if resp.status_code not in (200, 201):
        raise RuntimeError(
            f"HEC rejected the batch: HTTP {resp.status_code}: "
            f"{resp.text[:200]}")
    try:
        ack = resp.json() if resp.text else {}
    except ValueError:
        ack = {"raw": resp.text[:200]}
    return {"mode": "hec", "endpoint": endpoint, "events": len(events),
            "ack": ack}
