"""Local FastAPI service (V0.1).

Binds 127.0.0.1 by default — the dashboard and API are only reachable from
this machine unless the operator deliberately changes the bind address.
"""

from __future__ import annotations

import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from agent.discovery import run_discovery
from agent.scope import ScopeError
from analyst import explain_finding
from common.logging_setup import (configure_logging, install_crash_hook,
                                  utc_now_iso)
from exporters import splunk as splunk_exporter
from lifecycle import IllegalTransition, transition_finding
from retest import RetestError, retest_all, retest_finding
from scheduler import (ScheduleConfig, ScheduleError, compute_next_run,
                       config_from_dict, config_to_dict, run_scheduled_scan)
from scheduler.engine import (KEY_CONFIG, KEY_LAST_RESULT, KEY_LAST_RUN,
                              KEY_NEXT_RUN, SchedulerThread)
from storage.db import Store
from storage.models import STATUSES, AuditEntry
from trends import get_summary, get_trends
from validator import ALL_CHECKS, ValidationError, validate_finding

VERSION = "0.4.0"
DEFAULT_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "data", "findings.db")
DEFAULT_SCOPE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "config", "authorized_targets.yaml")

DB_PATH = os.environ.get("SECURITY_PLATFORM_DB", DEFAULT_DB)

configure_logging()
install_crash_hook()

_scheduler_thread: Optional[SchedulerThread] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the scheduled-scan background thread on boot (uvicorn only)."""
    global _scheduler_thread
    _scheduler_thread = SchedulerThread(DB_PATH)
    _scheduler_thread.start()
    yield
    if _scheduler_thread is not None:
        _scheduler_thread.stop()
        _scheduler_thread = None


app = FastAPI(title="Deadbolt", version=VERSION, lifespan=lifespan)


def _store() -> Store:
    return Store(DB_PATH)


class RunRequest(BaseModel):
    scope: Optional[str] = None  # path to authorized_targets.yaml
    ports: Optional[str] = None  # comma-separated override, e.g. "22,80"


class ValidateRequest(BaseModel):
    scope: Optional[str] = None  # path to authorized_targets.yaml
    checks: Optional[List[str]] = None  # subset of tcp_reprobe, tls_certificate, banner_intel


class RetestBatchRequest(BaseModel):
    status: Optional[str] = None  # "open" (default: suspected+confirmed) or one status


class StatusChangeRequest(BaseModel):
    status: str
    note: Optional[str] = None


# Cooldown between validations of the same finding (seconds): prevents
# accidental double-submits from re-probing the target.
VALIDATION_COOLDOWN = 10.0
_last_validation: Dict[str, float] = {}
# Same idea for single-finding retests (batch retests are explicit).
RETEST_COOLDOWN = 10.0
_last_retest: Dict[str, float] = {}


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


@app.post("/findings/{finding_id}/validate", status_code=201)
def validate(req: ValidateRequest, finding_id: str):
    """Run controlled, read-only validation checks against one finding.

    The finding's target must be inside the authorized scope, else 400.
    """
    now = time.monotonic()
    last = _last_validation.get(finding_id, 0.0)
    if now - last < VALIDATION_COOLDOWN:
        raise HTTPException(
            status_code=429,
            detail=f"validation cooling down; retry in "
                   f"{VALIDATION_COOLDOWN - (now - last):.0f}s")
    # Validate the requested checks up front: unknown names and empty lists
    # are client errors (400), not "finding not found" (404). Duplicates are
    # collapsed so a check never runs twice per validation.
    checks = req.checks
    if checks is not None:
        unknown = [c for c in checks if c not in ALL_CHECKS]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"unknown check(s) {unknown}; allowed: {list(ALL_CHECKS)}")
        if not checks:
            raise HTTPException(
                status_code=400, detail="checks must not be empty")
        checks = list(dict.fromkeys(checks))
    store = _store()
    try:
        try:
            result = validate_finding(
                store, finding_id,
                checks=checks,
                scope_path=req.scope or DEFAULT_SCOPE)
        except ValidationError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ScopeError as exc:
            # validate_finding already wrote the deny audit entry.
            raise HTTPException(status_code=400, detail=f"scope refused: {exc}")
    finally:
        store.close()
    _last_validation[finding_id] = time.monotonic()
    return result


@app.get("/findings/{finding_id}/validations")
def list_validations(finding_id: str):
    store = _store()
    try:
        if store.get_finding(finding_id) is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return store.list_validations(finding_id)
    finally:
        store.close()


@app.post("/findings/{finding_id}/retest", status_code=201)
def retest_one(finding_id: str, scope: Optional[str] = None):
    """Re-probe one finding against the target's current state.

    Outcomes: re-observed (status kept, last_seen bumped), remediated
    (-> fixed), still-fixed / not-present, or inconclusive. The finding's
    target must be inside the authorized scope, else 400.
    """
    now = time.monotonic()
    last = _last_retest.get(finding_id, 0.0)
    if now - last < RETEST_COOLDOWN:
        raise HTTPException(
            status_code=429,
            detail=f"retest cooling down; retry in "
                   f"{RETEST_COOLDOWN - (now - last):.0f}s")
    store = _store()
    try:
        try:
            result = retest_finding(
                store, finding_id, scope_path=scope or DEFAULT_SCOPE)
        except RetestError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ScopeError as exc:
            raise HTTPException(status_code=400, detail=f"scope refused: {exc}")
    finally:
        store.close()
    _last_retest[finding_id] = time.monotonic()
    return result


@app.post("/retest", status_code=201)
def retest_batch(req: RetestBatchRequest, scope: Optional[str] = None):
    """Retest every finding matching the status filter (default: open).

    Records a trend snapshot when the batch completes. Per-finding
    results are returned; a single finding's failure doesn't abort
    the batch.
    """
    store = _store()
    try:
        try:
            result = retest_all(
                store, status_filter=req.status,
                scope_path=scope or DEFAULT_SCOPE)
        except RetestError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except ScopeError as exc:
            raise HTTPException(status_code=400, detail=f"scope refused: {exc}")
    finally:
        store.close()
    return result


@app.post("/findings/{finding_id}/status")
def change_status(req: StatusChangeRequest, finding_id: str):
    """Move a finding through the lifecycle state machine.

    400 on unknown status or illegal transition (the response names the
    allowed next statuses). Every transition is recorded in finding_events.
    """
    if req.status not in STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"unknown status {req.status!r}; "
                   f"must be one of {list(STATUSES)}")
    store = _store()
    try:
        try:
            event = transition_finding(
                store, finding_id, req.status,
                actor="operator", note=req.note or "")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except IllegalTransition as exc:
            raise HTTPException(status_code=400, detail={
                "error": str(exc),
                "current": exc.old_status,
                "allowed": exc.allowed,
            })
    finally:
        store.close()
    return event


@app.get("/findings/{finding_id}/events")
def list_events(finding_id: str, limit: int = Query(200, ge=1, le=1000)):
    """Append-only lifecycle timeline for a finding."""
    store = _store()
    try:
        if store.get_finding(finding_id) is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return store.list_finding_events(finding_id, limit=limit)
    finally:
        store.close()


@app.get("/trends")
def trends(days: int = Query(30, ge=1, le=365)):
    """Per-day time series of finding counts grouped by status."""
    store = _store()
    try:
        return get_trends(store, days=days)
    finally:
        store.close()


@app.get("/trends/summary")
def trends_summary(days: int = Query(30, ge=1, le=365)):
    """Current totals, period activity, and mean time-to-fix."""
    store = _store()
    try:
        return get_summary(store, days=days)
    finally:
        store.close()


class ExportRequest(BaseModel):
    mode: str = "spool"  # "spool" (Universal Forwarder file) or "hec"
    severity: Optional[str] = None
    status: Optional[str] = None
    target: Optional[str] = None


@app.post("/export/splunk", status_code=201)
def export_splunk(req: ExportRequest):
    """Export findings as Splunk-ready events.

    mode="spool" (default): append JSON Lines to data/splunk_spool/ for a
    Universal Forwarder to ingest. No Splunk credentials needed.
    mode="hec": POST to the HEC endpoint from SPLUNK_HEC_URL /
    SPLUNK_HEC_TOKEN. 503 if unconfigured. Every export is audit-logged.
    """
    if req.mode not in ("spool", "hec"):
        raise HTTPException(status_code=400,
                            detail="mode must be 'spool' or 'hec'")
    started = utc_now_iso()
    store = _store()
    try:
        findings = store.list_findings(
            target=req.target, severity=req.severity, status=req.status)
        events = [splunk_exporter.finding_to_event(f) for f in findings]
        try:
            if req.mode == "spool":
                result = splunk_exporter.write_spool(events)
            else:
                result = splunk_exporter.send_hec(events)
        except RuntimeError as exc:
            store.audit(AuditEntry(
                id=None, timestamp=started, event="export.splunk",
                scope_file="", scope_hash=None,
                authorization_acknowledged=False,
                target_count=len(findings),
                decision="deny", reason=str(exc)))
            raise HTTPException(status_code=503, detail=str(exc))
        store.audit(AuditEntry(
            id=None, timestamp=started, event="export.splunk",
            scope_file="", scope_hash=None,
            authorization_acknowledged=False,
            target_count=len(findings),
            decision="allow",
            reason=f"mode={req.mode} events={len(events)}"))
        return result
    finally:
        store.close()


def _schedule_status(store: Store) -> Dict[str, Any]:
    """Current schedule config + last/next run bookkeeping for the dashboard."""
    raw = store.get_setting(KEY_CONFIG)
    try:
        cfg = config_from_dict(raw) if raw else ScheduleConfig()
    except ScheduleError:
        cfg = ScheduleConfig()
    next_run = store.get_setting(KEY_NEXT_RUN)
    if next_run is None and cfg.enabled:
        # Enabled but never scheduled (e.g. config written by hand): show
        # when the first run will happen.
        last_raw = store.get_setting(KEY_LAST_RUN)
        last_run = (datetime.fromisoformat(last_raw) if last_raw else None)
        next_run = compute_next_run(cfg, datetime.now(),
                                     last_run=last_run).isoformat()
    return {
        "config": config_to_dict(cfg),
        "last_run": store.get_setting(KEY_LAST_RUN),
        "next_run": next_run,
        "last_result": store.get_setting(KEY_LAST_RESULT),
    }


@app.get("/schedule")
def get_schedule():
    """Show the automatic-scan schedule and its last/next run."""
    store = _store()
    try:
        return _schedule_status(store)
    finally:
        store.close()


@app.put("/schedule")
def put_schedule(body: Dict[str, Any]):
    """Replace the automatic-scan schedule. 400 on invalid config.

    Body is the full schedule object, e.g.
    {"enabled": true, "cadence": "daily", "time": "02:00",
     "weekday": 0, "interval_hours": 24, "auto_validate": true,
     "scope_path": "", "ports": null}
    Times are HH:MM in the server's local timezone.
    """
    try:
        cfg = config_from_dict(body or {})
    except ScheduleError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    started = utc_now_iso()
    store = _store()
    try:
        store.set_setting(KEY_CONFIG, config_to_dict(cfg))
        if cfg.enabled:
            last_raw = store.get_setting(KEY_LAST_RUN)
            last_run = (datetime.fromisoformat(last_raw)
                        if last_raw else None)
            nxt = compute_next_run(cfg, datetime.now(), last_run=last_run)
            store.set_setting(KEY_NEXT_RUN, nxt.isoformat())
        else:
            store.set_setting(KEY_NEXT_RUN, None)
        store.audit(AuditEntry(
            id=None, timestamp=started, event="schedule.update",
            scope_file="", scope_hash=None,
            authorization_acknowledged=False,
            target_count=0,
            decision="allow",
            reason=f"enabled={cfg.enabled} cadence={cfg.cadence}"))
        return _schedule_status(store)
    finally:
        store.close()


def _run_scan_background(db_path: str, cfg: ScheduleConfig) -> None:
    try:
        run_scheduled_scan(db_path, cfg)
    except Exception:
        import traceback
        traceback.print_exc()


@app.post("/schedule/run")
def run_schedule_now(sync: bool = Query(False)):
    """Trigger a scheduled-style scan immediately.

    Uses the saved schedule's scope/ports/auto_validate settings.
    Runs in the background by default (202 "started"); pass
    ?sync=true to wait for the result (handy for scripts/tests).
    """
    store = _store()
    try:
        raw = store.get_setting(KEY_CONFIG)
        try:
            cfg = config_from_dict(raw) if raw else ScheduleConfig()
        except ScheduleError:
            cfg = ScheduleConfig()
        store.audit(AuditEntry(
            id=None, timestamp=utc_now_iso(), event="schedule.run",
            scope_file="", scope_hash=None,
            authorization_acknowledged=False,
            target_count=0, decision="allow", reason="manual trigger"))
    finally:
        store.close()
    if sync:
        result = run_scheduled_scan(DB_PATH, cfg)
        return JSONResponse({"status": "completed", "result": result},
                            status_code=200)
    thread = threading.Thread(
        target=_run_scan_background, args=(DB_PATH, cfg),
        name="deadbolt-manual-scan", daemon=True)
    thread.start()
    return JSONResponse({"status": "started"}, status_code=202)


@app.get("/", include_in_schema=False)
def dashboard():
    here = os.path.dirname(os.path.abspath(__file__))
    page = os.path.join(here, "..", "dashboard", "index.html")
    return FileResponse(page, media_type="text/html")
