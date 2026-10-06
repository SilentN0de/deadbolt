"""External assessment worker client (V0.5).

Runs on a machine *outside* the assessed network (second Pi, cheap VPS, or
a friend's box over Tailscale — anything with Python 3). Flow:

    python -m external.worker --api http://<deadbolt-host>:8000 register --name my-pi
    python -m external.worker --api http://<deadbolt-host>:8000 run-once
    python -m external.worker --api http://<deadbolt-host>:8000 loop --interval 3600

The worker only ever probes targets listed in the assessments the Deadbolt
API assigns it (defense in depth: the server is the authority on scope).
Credentials are the per-worker token stored in the config file; it is sent
as an Authorization header and never logged.

Config file (JSON): {"worker_id": ..., "token": ...}
Default path: ./worker.json (override with --config or
DEADBOLT_WORKER_CONFIG).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

DEFAULT_CONFIG = os.environ.get("DEADBOLT_WORKER_CONFIG",
                                os.path.join(os.getcwd(), "worker.json"))


class WorkerError(Exception):
    """Raised for worker-side failures (HTTP errors carry status)."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


def _request(api_url: str, method: str, path: str,
             token: Optional[str] = None,
             body: Optional[Dict[str, Any]] = None) -> Any:
    url = api_url.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise WorkerError(f"{method} {path} -> HTTP {exc.code}: {detail}",
                          status=exc.code)
    except urllib.error.URLError as exc:
        raise WorkerError(f"{method} {path} failed: {exc.reason}")


def load_config(path: str = DEFAULT_CONFIG) -> Dict[str, str]:
    if not os.path.exists(path):
        raise WorkerError(
            f"no worker config at {path}; run `register` first")
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    if not cfg.get("worker_id") or not cfg.get("token"):
        raise WorkerError(f"config at {path} is missing worker_id/token")
    return cfg


def save_config(worker_id: str, token: str,
                path: str = DEFAULT_CONFIG) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"worker_id": worker_id, "token": token}, fh, indent=2)
    os.chmod(path, 0o600)  # token on disk: owner-only


def register(api_url: str, name: str,
             path: str = DEFAULT_CONFIG) -> Dict[str, Any]:
    """Register with the Deadbolt API. The token is returned ONCE — it is
    saved to the config file immediately, so copy it there and then."""
    res = _request(api_url, "POST", "/external-workers", body={"name": name})
    save_config(res["id"], res["token"], path)
    return {"id": res["id"], "name": res.get("name", name),
            "config": path}


def poll(api_url: str, path: str = DEFAULT_CONFIG) -> List[Dict[str, Any]]:
    """Fetch this worker's pending (queued/running) assessments."""
    cfg = load_config(path)
    res = _request(api_url, "GET", "/external-assessments",
                   token=cfg["token"])
    items = res if isinstance(res, list) else res.get("assessments", [])
    return [a for a in items
            if a.get("worker_id") == cfg["worker_id"]
            and a.get("status") in ("queued", "running")]


def run_assessment(api_url: str, assessment: Dict[str, Any],
                   path: str = DEFAULT_CONFIG,
                   dns_resolver: Optional[Any] = None) -> Dict[str, Any]:
    """Run one assessment's probes and push the results back.

    `dns_resolver` is injected by tests/lab; the real DNS client is used
    otherwise. Only the assessment's own targets are probed, never more.
    """
    # Local import so `python -m external.worker` stays light until needed.
    from .probes import run_probes

    cfg = load_config(path)
    assessment_id = assessment["id"]
    targets = assessment.get("targets") or []
    probes = assessment.get("probes") or []
    ports = assessment.get("ports") or None
    if not targets:
        raise WorkerError("assessment has no targets; refusing to run")
    try:
        _request(api_url, "POST",
                 f"/external-assessments/{assessment_id}/start",
                 token=cfg["token"])
    except WorkerError as exc:
        if exc.status != 404:  # /start is best-effort
            raise
    results = run_probes(targets, probes, ports=ports,
                         dns_resolver=dns_resolver)
    pushed = _request(api_url, "POST", "/external-results", token=cfg["token"],
                      body={"assessment_id": assessment_id,
                            "results": results})
    return {"assessment_id": assessment_id,
            "probes_run": len(results), "ingest": pushed}


def run_once(api_url: str, path: str = DEFAULT_CONFIG,
             dns_resolver: Optional[Any] = None) -> List[Dict[str, Any]]:
    """Poll, run every pending assessment, push results. Returns per-run
    summaries."""
    summaries = []
    for assessment in poll(api_url, path):
        summaries.append(run_assessment(api_url, assessment, path,
                                        dns_resolver=dns_resolver))
    return summaries


def loop(api_url: str, interval: int = 3600,
         path: str = DEFAULT_CONFIG) -> "int":  # noqa: F821
    """Poll forever. Ctrl-C stops."""
    print(f"worker polling {api_url} every {interval}s (Ctrl-C to stop)")
    while True:
        try:
            for summary in run_once(api_url, path):
                print(f"completed assessment {summary['assessment_id']}: "
                      f"{summary['probes_run']} probe result(s) pushed")
        except WorkerError as exc:
            print(f"worker error: {exc}", file=sys.stderr)
        time.sleep(interval)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deadbolt external assessment worker")
    parser.add_argument("--api", required=True,
                        help="Deadbolt API base URL, e.g. http://127.0.0.1:8000")
    parser.add_argument("--config", default=DEFAULT_CONFIG,
                        help="worker config file (default: ./worker.json)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_reg = sub.add_parser("register", help="register this worker, save token")
    p_reg.add_argument("--name", required=True, help="worker name")

    sub.add_parser("run-once",
                   help="poll, run pending assessments, push results")
    p_loop = sub.add_parser("loop", help="poll forever")
    p_loop.add_argument("--interval", type=int, default=3600,
                        help="poll interval seconds (default 3600)")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "register":
            res = register(args.api, args.name, args.config)
            print(f"registered worker {res['id']} ({res['name']})")
            print(f"token saved to {res['config']} (owner-only permissions). "
                  "Keep it secret.")
        elif args.cmd == "run-once":
            summaries = run_once(args.api, args.config)
            if not summaries:
                print("no pending assessments")
            for s in summaries:
                print(f"assessment {s['assessment_id']}: "
                      f"{s['probes_run']} probe result(s) pushed")
        elif args.cmd == "loop":
            return loop(args.api, args.interval, args.config)
    except WorkerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
