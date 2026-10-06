# V0.5 — External Assessment: Verified Outside-In Worker

**Status:** ✅ built 2026-10-05 (Deadbolt 0.5.0) — 38 tests,
`scripts/simulate_external.py` 27/27 checks green.

**Decisions on the open questions** (sensible defaults, Tawhid can change):
1. **Worker host:** host-agnostic — `python -m external.worker` runs on any
   machine with Python 3 (stdlib only, no dependencies).
2. **Run trigger:** on-demand via dashboard/API; `enqueue_assessment()`
   takes a Store directly as a clean hook for the scheduled-scans engine.
3. **Naming:** kept "external assessment" + "Outside-in" dashboard panel.
**Why it matters:** everything Deadbolt does today (V0.1–V0.4) sees the network
from the *inside* (LAN). V0.5 answers the other half of the question: **what
does an attacker on the internet see when they look at my network?** Same
evidence-backed findings, same local storage — just a second vantage point.

## What it is

A small **worker program** that runs on a machine *outside* the assessed
network and probes only explicitly authorized targets (e.g., his own public
IP, a VPS he controls). The worker sends results back to the Deadbolt API,
which stores them as ordinary findings with full evidence.

```
┌──────────────┐  scan instructions   ┌───────────────────┐
│ Deadbolt API │ ───────────────────► │  external worker  │
│ (home box)   │ ◄─────────────────── │  (outside the net)│
└──────────────┘     results +        └───────────────────┘
                    evidence only            │
                                             ▼ probes (read-only)
                                      authorized targets only
```

## Design decisions (locked unless Tawhid changes them)

- **Off by default.** Nothing runs outside the home box until he registers a
  worker and approves a run — per `docs/privacy.md`, future integrations that
  move data off-device must be off by default, disclose exactly what leaves
  the device, and support user-controlled retention/deletion.
- **What leaves the device:** (1) the worker's target list + probe set, (2)
  the results come *back* as evidence. Raw scan data never goes anywhere
  except his API. This will be shown on a disclosure banner in the dashboard
  before the first run.
- **Read-only probes only** in V0.5: outside-in port discovery, banner intel,
  TLS cert inspection, DNS exposure (MX/TXT/SPF), HTTP headers — the same
  probe family the local validation pipeline uses, run from the other side.
  No controlled exploitation (that stays V0.3-style, bounded, on-box).
- **Worker identity + auth:** each worker registers once, gets a long random
  token (stored as a hash server-side), heartbeats in, and can be revoked in
  one click from the dashboard.

## Where the worker can run (his call)

| Option | Cost | Notes |
|---|---|---|
| Second Pi / spare box at another location | ~free | Best fit: he already owns more than one Pi 5; just needs internet |
| Cheap VPS (e.g. $4–6/mo droplet) | small | Ephemeral: spin up, run, tear down. Good for periodic spot-checks |
| Friend's machine with Tailscale | free | Worker doesn't even need a public IP — API talks over Tailscale |

## API surface (draft)

- `POST /external-workers` — register (returns token; 201, audit-logged)
- `DELETE /external-workers/{id}` — revoke (token dead immediately)
- `POST /external-assessments` — enqueue a run (targets + probe set; 400 on
  out-of-scope target; requires worker registered)
- `GET /external-assessments` / `GET /external-assessments/{id}` — queue + results
- `POST /external-results` — worker ingest (token auth); findings enter the
  same lifecycle machine (`suspected` → …) with evidence + `finding_events`

## Dashboard

"Outside-in" panel: worker list with revoke buttons, assessment queue,
disclosure banner + enable switch (opt-in), results rendered like normal
findings.

## Build plan (mirrors the V0.1–V0.4 pattern)

1. `external/` package: worker client (register, poll, run probes, push results)
2. Server: worker registry + token auth, assessment queue, result ingest →
   findings with evidence
3. Scope guard: targets must be in the operator-approved list; rate limits;
   kill switch; every step audit-logged
4. `scripts/simulate_external.py`: lab fixture with a fake "internet-side"
   worker, green-path checks
5. Dashboard panel + disclosure/opt-in flow
6. Tests (target: keep the suite green, V0.4 pattern of sim-backed tests)
7. CHANGELOG + README roadmap update

## Open questions for Tawhid — resolved in the build (changeable)

1. **Worker host:** second Pi, cheap VPS, or friend's box via Tailscale?
   → host-agnostic: any machine with Python 3.
2. **Run trigger:** on-demand only, or fold into the V0.4 scheduled-scans
   engine (e.g. weekly outside-in run)?
   → on-demand via dashboard/API now; `enqueue_assessment()` is a clean
   hook the scheduler can call later.
3. Keep the name "external assessment", or something in his pitch voice
   ("like an antivirus scan, but the internet's view")?
   → kept "external assessment" / "Outside-in" panel for now.
