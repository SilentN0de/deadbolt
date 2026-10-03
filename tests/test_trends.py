"""Trend tracking tests (V0.4): snapshots, series, summary math."""

from lifecycle import transition_finding
from storage.db import Store
from storage.models import Finding
from trends import get_summary, get_trends, mean_time_to_fix


def _mk(store, title, status="suspected", severity="medium",
        first_seen="2026-10-01T00:00:00+00:00"):
    f = Finding.new(target="127.0.0.1", title=title, severity=severity,
                    first_seen=first_seen)
    stored = store.upsert_finding(f)
    if status != "suspected":
        path = {"confirmed": ["confirmed"],
                "false-positive": ["false-positive"],
                "fixed": ["confirmed", "fixed"],
                "accepted-risk": ["confirmed", "accepted-risk"]}[status]
        for step in path:
            transition_finding(store, stored.id, step, actor="system")
    return store.get_finding(stored.id)


def test_record_snapshot_counts(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    try:
        _mk(s, "a", status="confirmed", severity="high")
        _mk(s, "b", status="confirmed", severity="high")
        _mk(s, "c", status="fixed", severity="low")
        n = s.record_snapshot("2026-10-02T00:00:00+00:00")
        assert n == 2
        rows = s.list_snapshots(since="2026-10-01T00:00:00+00:00")
        counts = {(r["status"], r["severity"]): r["count"] for r in rows}
        assert counts == {("confirmed", "high"): 2, ("fixed", "low"): 1}
    finally:
        s.close()


def test_record_snapshot_empty_db(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    try:
        assert s.record_snapshot("2026-10-02T00:00:00+00:00") == 0
        assert s.list_snapshots(since="2026-10-01T00:00:00+00:00") == []
        # Series and summary stay well-formed with no data.
        assert get_trends(s)["series"] == []
        summary = get_summary(s)
        assert summary["open"] == 0
        assert summary["mean_time_to_fix_seconds"] is None
    finally:
        s.close()


def test_trends_series_uses_latest_snapshot_per_day(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    try:
        _mk(s, "a", status="confirmed", severity="high")
        s.record_snapshot("2026-10-02T10:00:00+00:00")
        _mk(s, "b", status="confirmed", severity="high")  # new finding
        s.record_snapshot("2026-10-02T12:00:00+00:00")  # same day, later
        s.record_snapshot("2026-10-03T09:00:00+00:00")
        series = get_trends(s, days=30)["series"]
        assert [p["date"] for p in series] == ["2026-10-02", "2026-10-03"]
        day2 = series[0]
        assert day2["open"] == 2  # latest batch only, not 1+2 double-counted
        assert day2["by_status"] == {"confirmed": 2}
        assert day2["by_severity"] == {"high": 2}
    finally:
        s.close()


def test_summary_counts_and_new_in_period(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    try:
        _mk(s, "a", status="confirmed", first_seen="2026-10-02T00:00:00+00:00")
        _mk(s, "b", status="suspected", first_seen="2026-10-02T00:00:00+00:00")
        _mk(s, "c", status="fixed", first_seen="2020-01-01T00:00:00+00:00")
        _mk(s, "d", status="false-positive",
            first_seen="2026-10-02T00:00:00+00:00")
        summary = get_summary(s, days=30)
        assert summary["open"] == 2  # suspected + confirmed
        assert summary["fixed_total"] == 1
        assert summary["false_positive_total"] == 1
        assert summary["new_in_period"] == 3  # 'c' is from 2020
    finally:
        s.close()


def test_mean_time_to_fix_none_when_nothing_fixed(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    try:
        _mk(s, "a", status="confirmed")
        assert mean_time_to_fix(s) is None
    finally:
        s.close()


def test_mean_time_to_fix_math(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    try:
        # Fixed ~1 day after first_seen; open findings don't affect the mean.
        _mk(s, "old", status="fixed", first_seen="2020-01-01T00:00:00+00:00")
        _mk(s, "still-open", status="confirmed",
            first_seen="2020-01-01T00:00:00+00:00")
        mttf = mean_time_to_fix(s)
        assert mttf is not None
        assert mttf > 1_000_000  # > ~11 days in seconds
        summary = get_summary(s)
        assert summary["mean_time_to_fix_seconds"] == mttf
    finally:
        s.close()


def test_mean_time_to_fix_uses_first_fixed_transition(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    try:
        f = _mk(s, "flappy", status="confirmed",
                first_seen="2020-01-01T00:00:00+00:00")
        # fixed -> confirmed (regression) -> fixed again: first fix counts.
        transition_finding(s, f.id, "fixed", actor="retest")
        transition_finding(s, f.id, "confirmed", actor="retest")
        transition_finding(s, f.id, "fixed", actor="retest")
        mttf = mean_time_to_fix(s)
        assert mttf is not None and mttf > 0
    finally:
        s.close()
