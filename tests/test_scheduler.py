"""Scheduled scans: config validation, next-run math, engine, thread, API.

Engine/API tests use the simulated lab (fake services on 127.0.0.1) so the
real discovery -> validation -> retest pipeline runs without touching any
real network.
"""

from datetime import datetime, timedelta

import pytest
import yaml

from scheduler import (ScheduleConfig, ScheduleError, SchedulerThread,
                       compute_next_run, config_from_dict, config_to_dict,
                       due_now, run_scheduled_scan)
from scheduler.engine import KEY_CONFIG, KEY_LAST_RESULT, KEY_LAST_RUN, KEY_NEXT_RUN
from sim import SimulatedLab
from storage.db import Store


# -- config validation -------------------------------------------------------

def test_config_defaults_valid():
    ScheduleConfig().validate()


def test_config_rejects_bad_cadence():
    with pytest.raises(ScheduleError):
        config_from_dict({"cadence": "hourly"})


@pytest.mark.parametrize("bad", ["2", "25:00", "02-00", "2pm", ""])
def test_config_rejects_bad_time(bad):
    with pytest.raises(ScheduleError):
        config_from_dict({"time": bad})


@pytest.mark.parametrize("bad", [-1, 7, "monday", 1.5])
def test_config_rejects_bad_weekday(bad):
    with pytest.raises(ScheduleError):
        config_from_dict({"weekday": bad})


@pytest.mark.parametrize("bad", [0, 0.1, 745, "daily"])
def test_config_rejects_bad_interval(bad):
    with pytest.raises(ScheduleError):
        config_from_dict({"interval_hours": bad})


def test_config_rejects_unknown_keys():
    with pytest.raises(ScheduleError):
        config_from_dict({"cron": "* * * * *"})


def test_config_round_trip():
    cfg = config_from_dict({
        "enabled": True, "cadence": "weekly", "time": "03:30",
        "weekday": 6, "interval_hours": 12, "auto_validate": False,
        "scope_path": "/tmp/s.yaml", "ports": [22, 80],
    })
    assert config_from_dict(config_to_dict(cfg)).validate() == cfg


# -- next-run math ------------------------------------------------------------

def _cfg(**kw):
    base = {"time": "02:00", "weekday": 0, "interval_hours": 6}
    base.update(kw)
    return ScheduleConfig(**base).validate()


def test_daily_before_time_runs_today():
    now = datetime(2026, 10, 4, 1, 0)  # Sunday
    assert compute_next_run(_cfg(cadence="daily"), now) == datetime(2026, 10, 4, 2, 0)


def test_daily_after_time_runs_tomorrow():
    now = datetime(2026, 10, 4, 3, 0)
    assert compute_next_run(_cfg(cadence="daily"), now) == datetime(2026, 10, 5, 2, 0)


def test_weekly_finds_next_weekday():
    # 2026-10-04 is a Sunday; weekday=0 (Monday) -> 2026-10-05 02:00.
    now = datetime(2026, 10, 4, 12, 0)
    assert compute_next_run(_cfg(cadence="weekly"), now) == datetime(2026, 10, 5, 2, 0)


def test_weekly_same_day_before_time():
    now = datetime(2026, 10, 5, 1, 0)  # Monday
    assert compute_next_run(_cfg(cadence="weekly"), now) == datetime(2026, 10, 5, 2, 0)


def test_weekly_same_day_after_time_rolls_a_week():
    now = datetime(2026, 10, 5, 3, 0)  # Monday
    assert compute_next_run(_cfg(cadence="weekly"), now) == datetime(2026, 10, 12, 2, 0)


def test_interval_anchors_on_last_run():
    now = datetime(2026, 10, 4, 12, 0)
    last = datetime(2026, 10, 4, 10, 0)
    assert compute_next_run(_cfg(cadence="interval"), now,
                            last_run=last) == datetime(2026, 10, 4, 16, 0)


def test_interval_overdue_runs_now():
    now = datetime(2026, 10, 4, 12, 0)
    last = datetime(2026, 10, 4, 1, 0)  # 11h ago, interval 6h
    assert compute_next_run(_cfg(cadence="interval"), now,
                            last_run=last) == now


def test_due_now():
    cfg = _cfg(enabled=True)
    now = datetime(2026, 10, 4, 12, 0)
    assert due_now(cfg, now, None) is True
    assert due_now(cfg, now, now - timedelta(minutes=1)) is True
    assert due_now(cfg, now, now + timedelta(minutes=1)) is False
    assert due_now(_cfg(enabled=False), now, None) is False


# -- engine against the sim lab ----------------------------------------------

@pytest.fixture()
def lab():
    with SimulatedLab() as lab:
        yield lab


def _scope(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1,
        "authorization_acknowledged": True,
        "targets": [{"target": "127.0.0.1", "authorized": True}],
    }))
    return str(p)


def test_scheduled_scan_discovers_validates_retests(lab, tmp_path):
    db = str(tmp_path / "sched.db")
    ports = [p for p in (lab.ports["ssh_old"], lab.ports["http_old"],
                         lab.ports["https"]) if p]
    cfg = ScheduleConfig(enabled=True, cadence="interval", interval_hours=24,
                         auto_validate=True, scope_path=_scope(tmp_path),
                         ports=ports).validate()
    result = run_scheduled_scan(db, cfg)

    assert result["discovery"]["findings"] == 3
    assert result["validated"] == 3
    assert result["validation_errors"] == 0
    assert result["retest"]["results"] == 3
    assert result["retest"]["snapshot"] is not None

    store = Store(db)
    try:
        statuses = {f.status for f in store.list_findings()}
        assert statuses == {"confirmed"}  # auto-validated suspected -> confirmed
        assert store.get_setting(KEY_LAST_RUN) == result["finished"]
        nxt = datetime.fromisoformat(store.get_setting(KEY_NEXT_RUN))
        assert nxt > datetime.fromisoformat(result["finished"])
    finally:
        store.close()


def test_scheduled_scan_without_auto_validate(lab, tmp_path):
    db = str(tmp_path / "sched2.db")
    ports = [p for p in (lab.ports["ssh_old"], lab.ports["http_old"],
                         lab.ports["https"]) if p]
    cfg = ScheduleConfig(enabled=True, auto_validate=False,
                         scope_path=_scope(tmp_path),
                         ports=ports).validate()
    result = run_scheduled_scan(db, cfg)
    assert result["validated"] == 0
    store = Store(db)
    try:
        statuses = {f.status for f in store.list_findings()}
        # retest refreshes open findings but doesn't validate them
        assert statuses <= {"suspected", "confirmed"}
    finally:
        store.close()


# -- background thread tick logic ---------------------------------------------

class _FakeStore:
    def __init__(self, settings):
        self._s = dict(settings)

    def get_setting(self, key, default=None):
        return self._s.get(key, default)

    def set_setting(self, key, value):
        self._s[key] = value

    def close(self):
        pass


def _thread(settings, calls):
    def fake_scan(db_path, scan_cfg):
        calls.append(scan_cfg)
        return {"ok": True}
    return SchedulerThread("/nonexistent.db",
                           store_factory=lambda db: _FakeStore(settings),
                           scan_fn=fake_scan, tick_seconds=0.01)


def test_tick_runs_when_due():
    calls = []
    settings = {KEY_CONFIG: {"enabled": True, "cadence": "daily", "time": "02:00"},
                KEY_NEXT_RUN: "2020-01-01T00:00:00"}
    t = _thread(settings, calls)
    assert t.tick(datetime(2026, 10, 4, 12, 0)) == {"ok": True}
    assert len(calls) == 1
    assert calls[0].enabled is True


def test_tick_skips_when_disabled_or_not_due():
    calls = []
    t = _thread({KEY_CONFIG: {"enabled": False, "cadence": "daily"}},
                calls)
    assert t.tick(datetime(2026, 10, 4, 12, 0)) is None
    t2 = _thread({KEY_CONFIG: {"enabled": True, "cadence": "daily",
                               "time": "02:00"},
                  KEY_NEXT_RUN: "2026-10-05T02:00:00"}, calls)
    assert t2.tick(datetime(2026, 10, 4, 12, 0)) is None
    assert calls == []


def test_tick_runs_once_when_never_scheduled():
    calls = []
    t = _thread({KEY_CONFIG: {"enabled": True, "cadence": "interval",
                              "interval_hours": 24}}, calls)
    assert t.tick(datetime(2026, 10, 4, 12, 0)) == {"ok": True}
    assert len(calls) == 1


# -- API -----------------------------------------------------------------------

def _api_scope(tmp_path):
    p = tmp_path / "api_scope.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1,
        "authorization_acknowledged": True,
        "targets": [{"target": "127.0.0.1", "authorized": True}],
    }))
    return str(p)


def test_api_schedule_defaults(client):
    c, _ = client
    r = c.get("/schedule")
    assert r.status_code == 200
    body = r.json()
    assert body["config"]["enabled"] is False
    assert body["last_run"] is None
    assert body["next_run"] is None


def test_api_schedule_put_and_get(client):
    c, _ = client
    r = c.put("/schedule", json={
        "enabled": True, "cadence": "weekly", "time": "03:30",
        "weekday": 2, "interval_hours": 24, "auto_validate": True,
        "scope_path": "", "ports": None,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["config"]["cadence"] == "weekly"
    assert body["config"]["weekday"] == 2
    assert body["next_run"] is not None
    # Wednesday 03:30 must be in the future
    assert datetime.fromisoformat(body["next_run"]) > datetime.now()


def test_api_schedule_put_rejects_bad_config(client):
    c, _ = client
    r = c.put("/schedule", json={"enabled": True, "cadence": "hourly"})
    assert r.status_code == 400
    r = c.put("/schedule", json={"enabled": True, "cron": "* * * * *"})
    assert r.status_code == 400
    r = c.put("/schedule", json={"enabled": True, "time": "nope"})
    assert r.status_code == 400


def test_api_schedule_disable_clears_next_run(client):
    c, _ = client
    c.put("/schedule", json={"enabled": True, "cadence": "daily",
                             "time": "02:00"})
    assert c.get("/schedule").json()["next_run"] is not None
    r = c.put("/schedule", json={"enabled": False, "cadence": "daily",
                                 "time": "02:00"})
    assert r.status_code == 200
    assert r.json()["next_run"] is None


def test_api_run_now_sync(client, tmp_path, banner_server):
    c, _ = client
    port = banner_server
    c.put("/schedule", json={
        "enabled": False, "cadence": "daily", "time": "02:00",
        "auto_validate": True, "scope_path": _api_scope(tmp_path),
        "ports": [port],
    })
    r = c.post("/schedule/run?sync=true")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    assert body["result"]["discovery"]["findings"] >= 1
    # bookkeeping recorded even for manual triggers
    sched = c.get("/schedule").json()
    assert sched["last_run"] is not None
    assert sched["last_result"]["finished"] == sched["last_run"]


def test_api_run_now_background(client, tmp_path):
    c, tmp = client
    r = c.post("/schedule/run")
    assert r.status_code == 202
    assert r.json()["status"] == "started"
