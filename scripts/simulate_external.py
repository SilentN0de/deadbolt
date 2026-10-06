"""Simulate the external-assessment feature end to end.

Starts SimulatedLab (fake SSH/HTTP/HTTPS on 127.0.0.1), then drives the
real external-assessment API through FastAPI's TestClient, with a fake
"internet-side" worker built on the real worker client code
(external.worker), its HTTP layer routed into the TestClient:

  1. Kill switch: disabled by default; enqueue -> 403 until opted in.
  2. PUT /external/status enables it (opt-in, audit-logged).
  3. POST /external-workers registers a worker; token returned once.
  4. POST /external-assessments rejects an out-of-scope target (400).
  5. Enqueue a run (all probes) against 127.0.0.1 on the lab's ports.
  6. Fake worker polls with its token, runs the real probes, pushes
     results (DNS uses an injected fake resolver; loopback UDP is
     unavailable here, and the wire format is unit-tested).
  7. Findings land as suspected with evidence + system finding_events;
     the assessment completes; a trend snapshot is recorded.
  8. Revoke the worker -> its token dies (poll -> 401).
  9. Dashboard renders the Outside-in panel.

Asserts every step; exits non-zero with a failure list on any mismatch.
"""

import os
import sys
import tempfile

os.environ["SECURITY_PLATFORM_DB"] = os.path.join(
    tempfile.mkdtemp(prefix="deadbolt-ext-sim-"), "ext.db")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

import api.main as main  # noqa: E402
import external.worker as worker_mod  # noqa: E402
from sim.lab import SimulatedLab  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name
          + (f" ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)


SCOPE_YAML = """\
authorization_acknowledged: true
targets:
  - target: 127.0.0.1
    authorized: true
external_domains:
  - domain: example.com
    authorized: true
"""


def _fake_dns_resolver(name, qtype_name):
    if qtype_name == "MX":
        return [{"type": "MX", "preference": 10,
                 "exchange": "mail.example.com"}]
    return [{"type": "TXT", "text": "v=spf1 -all"}]


def main_sim() -> int:
    with SimulatedLab() as lab, tempfile.TemporaryDirectory(
        prefix="deadbolt-ext-sim-"
    ) as tmp:
        scope_path = os.path.join(tmp, "scope.yaml")
        with open(scope_path, "w", encoding="utf-8") as fh:
            fh.write(SCOPE_YAML)
        ports = [p for p in (lab.ports["ssh_old"], lab.ports["http_old"],
                             lab.ports["https"]) if p]
        print(f"sim lab up: ports={ports}\n")

        client = TestClient(main.app)

        # Route the real worker client's HTTP layer into the TestClient.
        def fake_request(api_url, method, path, token=None, body=None):
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            fn = {"GET": client.get, "POST": client.post,
                  "PUT": client.put, "DELETE": client.delete}[method]
            kwargs = {"headers": headers}
            if body is not None and method != "GET":
                kwargs["json"] = body
            r = fn(path, **kwargs)
            if r.status_code >= 400:
                raise worker_mod.WorkerError(
                    f"{method} {path} -> HTTP {r.status_code}",
                    status=r.status_code)
            return r.json()

        worker_mod._request = fake_request
        cfg_path = os.path.join(tmp, "worker.json")

        # -- 1. kill switch: off by default -----------------------------------
        r = client.get("/external/status")
        check("external disabled by default",
              r.status_code == 200 and r.json()["enabled"] is False)
        check("disclosure present", bool(r.json().get("disclosure")))

        reg = worker_mod.register("http://fake", "sim-worker", cfg_path)
        wid = reg["id"]
        r = client.post("/external-assessments", json={
            "worker_id": wid, "targets": ["127.0.0.1"],
            "probes": ["port_discovery"], "scope": scope_path})
        check("enqueue blocked while disabled", r.status_code == 403,
              f"got {r.status_code}")

        # -- 2. opt in ----------------------------------------------------------
        r = client.put("/external/status", json={"enabled": True})
        check("opt-in enables", r.status_code == 200
              and r.json()["enabled"] is True)

        # -- 3. registration ------------------------------------------------------
        check("token returned at registration",
              bool(worker_mod.load_config(cfg_path)["token"]))
        r = client.get("/external-workers")
        workers = r.json()
        check("worker listed without token material",
              len(workers) == 1 and "token" not in workers[0]
              and "token_hash" not in workers[0],
              str(workers))

        # -- 4. scope guard ---------------------------------------------------------
        r = client.post("/external-assessments", json={
            "worker_id": wid, "targets": ["203.0.113.99"],
            "probes": ["port_discovery"], "scope": scope_path})
        check("out-of-scope target rejected", r.status_code == 400,
              f"got {r.status_code}")
        r = client.post("/external-assessments", json={
            "worker_id": wid, "targets": ["127.0.0.1"],
            "probes": ["nope"], "scope": scope_path})
        check("unknown probe rejected", r.status_code == 400,
              f"got {r.status_code}")

        # -- 5. enqueue (all probes incl. dns via allowlisted domain) -----------------
        r = client.post("/external-assessments", json={
            "worker_id": wid, "targets": ["127.0.0.1", "example.com"],
            "probes": ["port_discovery", "banner_intel", "tls_inspection",
                       "dns_exposure", "http_security_headers"],
            "ports": ports, "scope": scope_path})
        check("assessment enqueued", r.status_code == 201,
              f"got {r.status_code}: {r.text[:200]}")
        aid = r.json()["id"]
        check("ports stored on assessment", r.json()["ports"] == ports)

        # -- 6. fake internet-side worker runs the real probes ------------------------
        pending = worker_mod.poll("http://fake", cfg_path)
        check("worker polls its assessment",
              len(pending) == 1 and pending[0]["id"] == aid,
              str([a["id"] for a in pending]))

        import external.probes as probes_mod
        orig_run_probes = probes_mod.run_probes

        def run_with_fake_dns(targets, probes, ports=None,
                              dns_resolver=None):
            return orig_run_probes(targets, probes, ports=ports,
                                   dns_resolver=_fake_dns_resolver)

        probes_mod.run_probes = run_with_fake_dns
        try:
            summaries = worker_mod.run_once("http://fake", cfg_path)
        finally:
            probes_mod.run_probes = orig_run_probes
        check("worker completed one assessment", len(summaries) == 1,
              str(summaries))
        check("ingest completed",
              summaries and summaries[0]["ingest"]["status"] == "completed")
        created = (summaries[0]["ingest"]["summary"]["findings_created"]
                   if summaries else 0)
        check("findings created from worker results", created >= 3,
              f"created={created}")

        # -- 7. findings look like normal findings --------------------------------------
        findings = client.get("/findings").json()
        ext = [f for f in findings if f["title"].startswith("External view:")]
        check("external findings stored", len(ext) >= 3, f"got {len(ext)}")
        check("all start suspected",
              all(f["status"] == "suspected" for f in ext))
        check("evidence attached",
              all(f["evidence"] for f in ext))
        check("evidence collectors namespaced",
              all(e["collector"].startswith("external.")
                  for f in ext for e in f["evidence"]))
        titles = [f["title"] for f in ext]
        check("port finding present",
              any("open port" in t for t in titles), str(titles))
        check("banner finding present",
              any("appears unmaintained" in t for t in titles))
        check("dns findings present",
              any("mail exchanger" in t or "SPF" in t for t in titles),
              str(titles))
        check("header finding present",
              any("security headers" in t for t in titles))
        if ext:
            ev = client.get(f"/findings/{ext[0]['id']}/events").json()
            check("system note event recorded",
                  any(e["event"] == "note" and e["actor"] == "system"
                      and e["detail"].get("via") == "external-assessment"
                      for e in ev))

        r = client.get(f"/external-assessments/{aid}")
        check("assessment completed",
              r.json()["status"] == "completed"
              and r.json()["summary"]["findings_created"] >= 3)

        # -- 8. revoke kills the token -----------------------------------------------
        r = client.delete(f"/external-workers/{wid}")
        check("worker revoked", r.json().get("revoked") is True)
        try:
            worker_mod.poll("http://fake", cfg_path)
            check("revoked token rejected", False, "poll succeeded")
        except worker_mod.WorkerError as exc:
            check("revoked token rejected", exc.status == 401,
                  f"status={exc.status}")

        # -- 9. dashboard ---------------------------------------------------------------
        html = client.get("/").text
        check("dashboard has Outside-in panel",
              "Outside-in" in html and "/external/status" in html
              and "shown ONCE" in html)

    print()
    if failures:
        print(f"SIMULATION FAILED: {len(failures)} check(s): {failures}")
        return 1
    print("EXTERNAL SIMULATION OK: kill switch, opt-in, registration, "
          "scope guard, worker run, ingest, revoke, dashboard all passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main_sim())
