"""Scheduled-scan engine: next-run math, the scan pipeline, background thread."""

from __future__ import annotations

import threading
import time
import traceback
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Optional

from common.logging_setup import utc_now_iso

from .config import ScheduleConfig

# Settings keys (stored via Store.get_setting / set_setting as JSON).
KEY_CONFIG = "schedule.config"
KEY_LAST_RUN = "schedule.last_run"      # ISO timestamp of last completed run
KEY_NEXT_RUN = "schedule.next_run"      # ISO timestamp of next planned run
KEY_LAST_RESULT = "schedule.last_result"  # JSON summary of last run

# How often the background thread re-checks whether a scan is due.
TICK_SECONDS = 60.0


def compute_next_run(cfg: ScheduleConfig, now: datetime,
                     last_run: Optional[datetime] = None) -> datetime:
    """Next scheduled run strictly after `now` (naive local datetimes)."""
    hh, mm = int(cfg.time[:2]), int(cfg.time[3:5])
    if cfg.cadence == "daily":
        candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate
    if cfg.cadence == "weekly":
        days_ahead = (cfg.weekday - now.weekday()) % 7
        candidate = (now + timedelta(days=days_ahead)).replace(
            hour=hh, minute=mm, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=7)
        return candidate
    # interval: anchor on the last completed run so drift doesn't accumulate.
    anchor = last_run if last_run is not None else now
    candidate = anchor + timedelta(hours=cfg.interval_hours)
    if candidate <= now:
        candidate = now  # overdue -> run as soon as possible
    return candidate


def due_now(cfg: ScheduleConfig, now: datetime,
            next_run: Optional[datetime]) -> bool:
    """True when a scan should start right now."""
    if not cfg.enabled:
        return False
    if next_run is None:
        return True  # enabled but never scheduled -> run once, then schedule
    return now >= next_run


def run_scheduled_scan(db_path: str, cfg: ScheduleConfig,
                       ) -> Dict[str, Any]:
    """Run the standard pipeline once: discovery -> validation -> retest.

    Reuses the exact code paths as manual runs, so scheduled and manual
    scans produce identical findings. Records last_run / next_run /
    last_result in the settings table.
    """
    from agent.discovery import run_discovery
    from storage.db import Store
    from validator import validate_finding

    started = utc_now_iso()
    scope_path = cfg.scope_path or None

    discovery = run_discovery(
        scope_path or _default_scope(), db_path, cfg.ports)

    store = Store(db_path)
    try:
        validated = 0
        validation_errors = 0
        if cfg.auto_validate:
            for f in store.list_findings(status="suspected"):
                try:
                    validate_finding(
                        store, f.id,
                        scope_path=scope_path or _default_scope())
                    validated += 1
                except Exception:
                    validation_errors += 1

        from retest import retest_all
        batch = retest_all(
            store, scope_path=scope_path or _default_scope())

        finished = utc_now_iso()
        last_run = datetime.fromisoformat(finished)
        next_run = compute_next_run(cfg, last_run, last_run=last_run)
        result = {
            "started": started,
            "finished": finished,
            "discovery": {
                "run_id": discovery.get("run_id"),
                "findings": discovery.get("summary", {}).get(
                    "findings_created"),
            },
            "validated": validated,
            "validation_errors": validation_errors,
            "retest": {
                "results": len(batch.get("results", [])),
                "snapshot": batch.get("snapshot_at"),
            },
        }
        store.set_setting(KEY_LAST_RUN, finished)
        store.set_setting(KEY_NEXT_RUN, next_run.isoformat())
        store.set_setting(KEY_LAST_RESULT, result)
        return result
    finally:
        store.close()


def _default_scope() -> str:
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "..", "config", "authorized_targets.yaml")


class SchedulerThread(threading.Thread):
    """Background thread: wakes every TICK_SECONDS, runs due scans.

    started_cb / finished_cb are optional hooks (used by tests and the API's
    "run now" path to observe progress).
    """

    def __init__(self, db_path: str,
                 store_factory: Optional[Callable] = None,
                 scan_fn: Optional[Callable] = None,
                 tick_seconds: float = TICK_SECONDS):
        super().__init__(name="deadbolt-scheduler", daemon=True)
        self.db_path = db_path
        self._store_factory = store_factory
        self._scan_fn = scan_fn or run_scheduled_scan
        self._tick = tick_seconds
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def stopped(self) -> bool:
        return self._stop.is_set()

    def run(self) -> None:  # noqa: C901 - small state machine, keep linear
        while not self._stop.wait(self._tick):
            try:
                self.tick(datetime.now())
            except Exception:
                traceback.print_exc()

    def tick(self, now: datetime) -> Optional[Dict[str, Any]]:
        """Single due-check. Returns the scan result if a scan ran."""
        from scheduler.config import config_from_dict
        from storage.db import Store

        factory = self._store_factory or Store
        store = factory(self.db_path)
        try:
            raw = store.get_setting(KEY_CONFIG)
            cfg = config_from_dict(raw) if raw else ScheduleConfig()
            if not cfg.enabled:
                return None
            next_raw = store.get_setting(KEY_NEXT_RUN)
            next_run = (datetime.fromisoformat(next_raw)
                        if next_raw else None)
            if not due_now(cfg, now, next_run):
                return None
            result = self._scan_fn(self.db_path, cfg)
            return result
        finally:
            store.close()
