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

    print()
    if failures:
        print(f"E2E FAILED ({len(failures)}):")
        for fl in failures:
            print(f"  - {fl}")
        return 1
    print("E2E OK: discovery, validation, analyst, splunk export all passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
