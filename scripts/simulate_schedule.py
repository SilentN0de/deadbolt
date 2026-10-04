"""Simulate the scheduled-scan feature end to end.

Starts SimulatedLab (fake SSH/HTTP/HTTPS on 127.0.0.1), then drives the
real /schedule API through FastAPI's TestClient:

  1. PUT /schedule rejects a bad config (400) and accepts a good one.
  2. POST /schedule/run?sync=true runs discovery -> validation -> retest.
  3. GET /schedule shows last_run / last_result bookkeeping.
  4. GET /trends/summary shows the dashboard numbers.
  5. SchedulerThread.tick() with an overdue next_run fires one real scan.

Asserts every step; exits non-zero with a failure list on any mismatch.
"""

import os
import sys
import tempfile
from datetime import datetime

os.environ["SECURITY_PLATFORM_DB"] = os.path.join(
    tempfile.mkdtemp(prefix="deadbolt-sched-sim-"), "sched.db")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

import api.main as main  # noqa: E402
from scheduler import SchedulerThread  # noqa: E402
from scheduler.engine import KEY_CONFIG, KEY_NEXT_RUN  # noqa: E402
from sim.lab import SimulatedLab  # noqa: E402
from storage.db import Store  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name
          + (f" ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)


SCOPE_YAML = """\
authorization_acknowledged: false
targets:
  - target: 127.0.0.1/32
    authorized: true
"""


def main_sim() -> int:
    with SimulatedLab() as lab, tempfile.TemporaryDirectory(
        prefix="deadbolt-sched-sim-"
    ) as tmp:
        scope_path = os.path.join(tmp, "scope.yaml")
        with open(scope_path, "w", encoding="utf-8") as fh:
            fh.write(SCOPE_YAML)
        ports = [p for p in (lab.ports["ssh_old"], lab.ports["http_old"],
                             lab.ports["https"]) if p]
        print(f"sim lab up: ports={ports}\n")

        client = TestClient(main.app)

        # -- 1. schedule config ------------------------------------------------
        r = client.put("/schedule", json={"enabled": True,
                                          "cadence": "hourly"})
        check("bad cadence rejected", r.status_code == 400,
              f"got {r.status_code}")

        r = client.put("/schedule", json={
            "enabled": True, "cadence": "daily", "time": "02:00",
            "weekday": 0, "interval_hours": 24, "auto_validate": True,
            "scope_path": scope_path, "ports": ports,
        })
        check("good config accepted", r.status_code == 200,
              f"got {r.status_code}")
        body = r.json()
        check("next_run computed", body["next_run"] is not None)
        check("config echoed", body["config"]["cadence"] == "daily"
              and body["config"]["enabled"] is True)

        # -- 2. run now (sync) --------------------------------------------------
        r = client.post("/schedule/run?sync=true")
        check("sync run completed", r.status_code == 200,
              f"got {r.status_code}")
        result = r.json()["result"]
        check("discovery found 3", result["discovery"]["findings"] == 3,
              str(result["discovery"]))
        check("auto-validated 3", result["validated"] == 3,
              str(result["validated"]))
        check("retested 3", result["retest"]["results"] == 3)
        check("snapshot written", result["retest"]["snapshot"] is not None)

        # -- 3. bookkeeping ------------------------------------------------------
        r = client.get("/schedule")
        sched = r.json()
        check("last_run recorded", sched["last_run"] is not None)
        check("last_result recorded",
              sched["last_result"]["finished"] == sched["last_run"])

        # -- 4. trends (what the dashboard cards show) ---------------------------
        r = client.get("/trends/summary?days=30")
        t = r.json()
        check("trends open=3", t["open"] == 3, str(t))
        check("mttf present", t["mean_time_to_fix_seconds"] is None)

        # -- 5. background thread tick with overdue schedule ----------------------
        store = Store(os.environ["SECURITY_PLATFORM_DB"])
        try:
            store.set_setting(KEY_NEXT_RUN, "2020-01-01T00:00:00")
            before = store.get_setting("schedule.last_run")
        finally:
            store.close()
        thread = SchedulerThread(os.environ["SECURITY_PLATFORM_DB"],
                                 tick_seconds=3600)
        tick_result = thread.tick(datetime.now())
        check("overdue tick ran a scan",
              tick_result is not None
              and tick_result["discovery"]["findings"] == 3)
        store = Store(os.environ["SECURITY_PLATFORM_DB"])
        try:
            after = store.get_setting("schedule.last_run")
        finally:
            store.close()
        check("tick updated last_run", after is not None and after != before,
              f"before={before} after={after}")

        # -- 6. dashboard renders the new section ---------------------------------
        r = client.get("/")
        html = r.text
        check("dashboard has schedule UI",
              "Scheduled scans" in html and "/schedule" in html)

    print()
    if failures:
        print(f"SIMULATION FAILED: {len(failures)} check(s): {failures}")
        return 1
    print("SCHEDULE SIMULATION OK: config API, sync run, bookkeeping, "
          "trends, background tick, dashboard UI all passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main_sim())
