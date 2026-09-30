"""Local FastAPI service (V0.1).

Binds 127.0.0.1 by default — the dashboard and API are only reachable from
this machine unless the operator deliberately changes the bind address.
"""

from __future__ import annotations

import os
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from agent.discovery import run_discovery
from agent.scope import ScopeError
from analyst import explain_finding
from common.logging_setup import configure_logging, install_crash_hook
from storage.db import Store

VERSION = "0.2.0"
DEFAULT_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "data", "findings.db")
DEFAULT_SCOPE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "config", "authorized_targets.yaml")

DB_PATH = os.environ.get("SECURITY_PLATFORM_DB", DEFAULT_DB)

configure_logging()
install_crash_hook()

app = FastAPI(title="Local Security Assessment Platform", version=VERSION)


def _store() -> Store:
    return Store(DB_PATH)


class RunRequest(BaseModel):
    scope: Optional[str] = None  # path to authorized_targets.yaml
    ports: Optional[str] = None  # comma-separated override, e.g. "22,80"


@app.get("/health")
def health():
    return {"status": "ok", "version": VERSION}


@app.post("/runs", status_code=201)
def trigger_run(req: RunRequest):
    """Validate scope, then run discovery synchronously. 400 on scope refusal."""
    scope_path = req.scope or DEFAULT_SCOPE
    ports = None
    if req.ports:
        try:
            ports = [int(p.strip()) for p in req.ports.split(",") if p.strip()]
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid --ports value")
    try:
        result = run_discovery(scope_path, DB_PATH, ports)
    except ScopeError as exc:
        # run_discovery already wrote the deny audit entry.
        raise HTTPException(status_code=400, detail=f"scope refused: {exc}")
    except Exception as exc:  # noqa: BLE001 - surfaced as 500, logged + crash-hooked
        raise HTTPException(status_code=500, detail=f"discovery failed: {exc}")
    return result


@app.get("/runs")
def list_runs(limit: int = Query(50, ge=1, le=200)):
    store = _store()
    try:
        return store.list_runs(limit=limit)
    finally:
        store.close()


@app.get("/findings")
def list_findings(
    target: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
):
    store = _store()
    try:
        return [f.to_dict() for f in store.list_findings(
            target=target, severity=severity, status=status)]
    finally:
        store.close()


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str):
    store = _store()
    try:
        finding = store.get_finding(finding_id)
    finally:
        store.close()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding.to_dict()


@app.get("/findings/{finding_id}/explanation")
def explain(finding_id: str):
    """Plain-English analyst explanation for a finding (local, deterministic)."""
    store = _store()
    try:
        finding = store.get_finding(finding_id)
    finally:
        store.close()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return explain_finding(finding).to_dict()


@app.get("/", include_in_schema=False)
def dashboard():
    here = os.path.dirname(os.path.abspath(__file__))
    page = os.path.join(here, "..", "dashboard", "index.html")
    return FileResponse(page, media_type="text/html")
