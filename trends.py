"""Trend tracking over finding snapshots (V0.4).

Snapshots are written automatically when a discovery run completes and
after every retest batch (see Store.record_snapshot). This module turns the
raw snapshot rows into the per-day time series and summary numbers the
dashboard and API serve.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from storage.db import Store

log = logging.getLogger("deadbolt.trends")

OPEN_STATUSES = ("suspected", "confirmed")


def _cutoff(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def get_trends(store: Store, days: int = 30) -> Dict[str, Any]:
    """Per-day time series of finding counts, grouped by status.

    Within a day, only the latest snapshot batch is used (a batch writes
    one timestamp for all its rows), so multiple snapshots per day don't
    double-count.
    """
    rows = store.list_snapshots(since=_cutoff(days))
    # date -> timestamp -> (status -> count, severity -> count)
    by_day: Dict[str, Dict[str, Dict[str, int]]] = {}
    latest_ts: Dict[str, str] = {}
    for r in rows:
        day = r["timestamp"][:10]  # ISO date prefix, UTC
        ts = r["timestamp"]
        bucket = by_day.setdefault(day, {})
        slot = bucket.setdefault(ts, {"by_status": {}, "by_severity": {}})
        slot["by_status"][r["status"]] = (
            slot["by_status"].get(r["status"], 0) + r["count"])
        slot["by_severity"][r["severity"]] = (
            slot["by_severity"].get(r["severity"], 0) + r["count"])
        if ts > latest_ts.get(day, ""):
            latest_ts[day] = ts

    series = []
    for day in sorted(by_day):
        slot = by_day[day][latest_ts[day]]
        by_status = slot["by_status"]
        open_count = sum(by_status.get(s, 0) for s in OPEN_STATUSES)
        series.append({
            "date": day,
            "open": open_count,
            "by_status": by_status,
            "by_severity": slot["by_severity"],
        })
    return {"days": days, "series": series}


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def mean_time_to_fix(store: Store) -> Optional[float]:
    """Mean seconds from first_seen to the first `-> fixed` transition.

    Returns None when no finding has ever been fixed (null-safe).
    """
    durations: List[float] = []
    for f in store.list_findings():
        first_seen = _parse_ts(f.first_seen)
        if first_seen is None:
            continue
        fixed_at: Optional[datetime] = None
        for e in store.list_finding_events(f.id):
            if e["new_status"] == "fixed":
                fixed_at = _parse_ts(e["timestamp"])
                break  # events are ordered by id: first fixed transition
        if fixed_at is not None:
            durations.append((fixed_at - first_seen).total_seconds())
    if not durations:
        return None
    return sum(durations) / len(durations)


def get_summary(store: Store, days: int = 30) -> Dict[str, Any]:
    """Current totals + period activity + mean time-to-fix."""
    cutoff = _cutoff(days)
    open_count = fixed_total = fp_total = 0
    new_in_period = 0
    for f in store.list_findings():
        if f.status in OPEN_STATUSES:
            open_count += 1
        if f.status == "fixed":
            fixed_total += 1
        if f.status == "false-positive":
            fp_total += 1
        if f.first_seen and f.first_seen >= cutoff:
            new_in_period += 1
    return {
        "days": days,
        "open": open_count,               # suspected + confirmed
        "fixed_total": fixed_total,
        "false_positive_total": fp_total,
        "new_in_period": new_in_period,
        "mean_time_to_fix_seconds": mean_time_to_fix(store),
    }
