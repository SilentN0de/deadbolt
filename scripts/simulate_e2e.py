"""End-to-end simulation: full pipeline against the fake lab.

Starts SimulatedLab (fake SSH/HTTP/HTTPS on 127.0.0.1), then runs the real
pipeline against it: discovery -> validation -> analyst explanations ->
Splunk spool export. Loopback-only; uses a throwaway SQLite DB.

    python scripts/simulate_e2e.py

Exit 0 when every stage produced the expected results, 1 otherwise.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from common.logging_setup import configure_logging
from sim import SimulatedLab

SCOPE_YAML = """\
authorization_acknowledged: false
targets:
  - target: 127.0.0.1/32
    authorized: true
"""


def main() -> int:
    configure_logging()
    failures = []

    with SimulatedLab() as lab, tempfile.TemporaryDirectory(
        prefix="secplatform-e2e-"
    ) as tmp:
        scope_path = os.path.join(tmp, "scope.yaml")
        db_path = os.path.join(tmp, "e2e.db")
        with open(scope_path, "w", encoding="utf-8") as fh:
            fh.write(SCOPE_YAML)

        ports = [p for p in
                 (lab.ports["ssh_old"], lab.ports["http_old"], lab.ports["https"])
                 if p]
        print(f"sim lab up: ssh_old={lab.ports['ssh_old']} "
              f"http_old={lab.ports['http_old']} https={lab.ports['https']} "
              f"closed={lab.ports['closed']}")

        # -- 1. discovery -------------------------------------------------
        from agent.discovery import run_discovery
        result = run_discovery(scope_path, db_path, ports)
        findings = result["findings"]
        print(f"discovery: run {result['run_id']} -> "
              f"{result['summary']['open_ports']} open, "
              f"{len(findings)} findings")
        if result["summary"]["open_ports"] < 2:
            failures.append("discovery found fewer than 2 open sim ports")

        # -- 2. validation ------------------------------------------------
        from storage.db import Store
        from validator import validate_finding
        store = Store(db_path)
        try:
            for f in findings:
                v = validate_finding(store, f["id"], scope_path=scope_path)
                print(f"validate {f['title'][:60]!r:64s} -> {v['outcome']} "
                      f"({v['status_before']} -> {v['status_after']})")
                if v["outcome"] not in ("confirmed", "intel"):
                    failures.append(
                        f"unexpected validation outcome for {f['id']}: "
                        f"{v['outcome']}")
            # explicit TLS check against the sim https service
            if lab.https_available:
                https_f = next(
                    (f for f in findings
                     if any(e.get("detail", {}).get("port") == lab.ports["https"]
                            for e in f.get("evidence", []))),
                    None)
                if https_f:
                    v = validate_finding(
                        store, https_f["id"],
                        checks=["tls_certificate", "tcp_reprobe"],
                        scope_path=scope_path)
                    tls_res = next(
                        (r for r in v["results"]
                         if r["check"] == "tls_certificate"), None)
                    print(f"tls_certificate on sim https -> "
                          f"{tls_res['verdict']}: {tls_res['summary']}")
                    if not (tls_res["ok"]
                            and tls_res["detail"].get("self_signed")):
                        failures.append(
                            "tls_certificate did not flag the self-signed "
                            "sim cert")
        finally:
            store.close()

        # -- 3. analyst explanations --------------------------------------
        from analyst import explain_finding
        from storage.models import Finding
        store = Store(db_path)
        try:
            stored = store.list_findings()
            for f in stored:
                exp = explain_finding(f)
                print(f"explain {f.title[:50]!r:54s} -> {exp.summary[:70]}")
                if not exp.summary or not exp.what_to_do:
                    failures.append(
                        f"empty explanation for finding {f.id}")
        finally:
            store.close()

        # -- 4. splunk spool export ---------------------------------------
        os.environ["SECURITY_PLATFORM_SPLUNK_SPOOL"] = os.path.join(
            tmp, "splunk_spool")
        from exporters import splunk as splunk_exporter
        store = Store(db_path)
        try:
            events = [splunk_exporter.finding_to_event(f)
                      for f in store.list_findings()]
            res = splunk_exporter.write_spool(events)
            print(f"splunk spool: {res['events']} events -> {res['path']}")
            if res["events"] != len(findings):
                failures.append("splunk spool event count mismatch")
        finally:
            store.close()

        # -- 5. V0.4: retest + lifecycle + trends ---------------------------
        from lifecycle import IllegalTransition, transition_finding
        from retest import retest_all, retest_finding
        from trends import get_summary, get_trends

        store = Store(db_path)
        try:
            all_findings = store.list_findings()
            by_port = {}
            for f in all_findings:
                for e in f.evidence:
                    p = (e.detail or {}).get("port")
                    if p:
                        by_port[p] = f
            ssh_f = by_port.get(lab.ports["ssh_old"])
            http_f = by_port.get(lab.ports["http_old"])
            assert ssh_f and http_f, "sim ssh/http findings missing"

            # 5a. retest everything while services are up: all re-observed.
            batch = retest_all(store, scope_path=scope_path)
            print(f"retest_all: {len(batch['results'])} findings, "
                  f"snapshot at {batch['snapshot_at']}")
            for r in batch["results"]:
                if r["event"] != "re-observed":
                    failures.append(
                        f"expected re-observed for {r['finding_id']}, "
                        f"got {r['event']}")
            print("retest_all (services up): all re-observed")

            # 5b. "fix" the ssh service -> retest flips it to fixed.
            lab.disable_service("ssh_old")
            r = retest_finding(store, ssh_f.id, scope_path=scope_path)
            print(f"retest ssh after disable -> {r['event']} "
                  f"({r['old_status']} -> {r['new_status']})")
            if r["event"] != "remediated" or r["new_status"] != "fixed":
                failures.append("ssh retest after disable did not remediate")
            hist = store.get_finding(ssh_f.id).retest_history
            if not any(e.get("event") == "remediated" for e in hist):
                failures.append("remediated event missing from retest_history")

            # 5c. bring the service back -> regression to confirmed.
            lab.enable_service("ssh_old")
            r = retest_finding(store, ssh_f.id, scope_path=scope_path)
            print(f"retest ssh after re-enable -> {r['event']} "
                  f"({r['old_status']} -> {r['new_status']})")
            if r["event"] != "re-observed" or r["new_status"] != "confirmed":
                failures.append("ssh retest after re-enable did not regress "
                                "to confirmed")

            # 5d. leave the http service "fixed" for the trend assertions.
            lab.disable_service("http_old")
            r = retest_finding(store, http_f.id, scope_path=scope_path)
            if r["new_status"] != "fixed":
                failures.append("http finding did not stay fixed")
            print(f"retest http after disable -> {r['event']} "
                  f"({r['old_status']} -> {r['new_status']})")

            # 5e. operator lifecycle transitions, including one illegal.
            others = [f for f in all_findings
                      if f.id not in (ssh_f.id, http_f.id)]
            # Fall back to the ssh finding (confirmed again after 5c) when
            # the lab has no third service (e.g. openssl missing -> no https).
            other = others[0] if others else store.get_finding(ssh_f.id)
            transition_finding(store, other.id, "accepted-risk",
                               actor="operator", note="e2e demo")
            try:
                transition_finding(store, other.id, "fixed", actor="operator")
                failures.append("illegal accepted-risk -> fixed was allowed")
            except IllegalTransition as exc:
                print(f"illegal transition rejected as expected; "
                      f"allowed={exc.allowed}")
                if exc.allowed != ["confirmed"]:
                    failures.append("wrong allowed list for illegal "
                                    "transition")
            transition_finding(store, other.id, "confirmed",
                               actor="operator", note="reopened")
            if store.get_finding(other.id).status != "confirmed":
                failures.append("reopen transition failed")

            # 5f. trends: snapshot rows exist, summary math checks out.
            series = get_trends(store, days=1)["series"]
            summary = get_summary(store, days=30)
            print(f"trends: {len(series)} day(s) in series, "
                  f"open={summary['open']} fixed={summary['fixed_total']} "
                  f"mttf={summary['mean_time_to_fix_seconds']}")
            if not series:
                failures.append("trend series empty after snapshots")
            if summary["fixed_total"] != 1:
                failures.append("expected exactly 1 fixed finding")
            if summary["new_in_period"] != len(all_findings):
                failures.append("new_in_period mismatch")
            mttf = summary["mean_time_to_fix_seconds"]
            if mttf is None or mttf < 0:
                failures.append("mean_time_to_fix should be >= 0")
        finally:
            store.close()

        # -- 6. V0.4 API surface (against the same throwaway DB) ------------
        os.environ["SECURITY_PLATFORM_DB"] = db_path
        import api.main as api_main
        from fastapi.testclient import TestClient
        tc = TestClient(api_main.app)

        r = tc.post("/retest", json={})
        print(f"POST /retest -> {r.status_code}, "
              f"{len(r.json().get('results', []))} results")
        if r.status_code != 201:
            failures.append(f"POST /retest returned {r.status_code}")

        # Illegal transition through the API: 400 + allowed list.
        store = Store(db_path)
        try:
            http_id = next(
                f.id for f in store.list_findings() if f.status == "fixed")
        finally:
            store.close()
        r = tc.post(f"/findings/{http_id}/status",
                    json={"status": "false-positive"})
        print(f"POST /findings/status (illegal) -> {r.status_code}, "
              f"allowed={r.json().get('detail', {}).get('allowed')}")
        if r.status_code != 400:
            failures.append("illegal API status change was not rejected")
        elif r.json()["detail"].get("allowed") != ["confirmed"]:
            failures.append("API 400 missing/wrong allowed list")

        r = tc.get("/trends/summary")
        summ = r.json()
        print(f"GET /trends/summary -> open={summ['open']} "
              f"fixed={summ['fixed_total']}")
        if r.status_code != 200 or summ["fixed_total"] != 1:
            failures.append("GET /trends/summary mismatch")

        r = tc.get("/trends?days=1")
        if r.status_code != 200 or not r.json()["series"]:
            failures.append("GET /trends series empty")

    print()
    if failures:
        print(f"E2E FAILED ({len(failures)}):")
        for fl in failures:
            print(f"  - {fl}")
        return 1
    print("E2E OK: discovery, validation, analyst, splunk export, "
          "retest, lifecycle, trends all passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
