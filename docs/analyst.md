# Analyst (V0.2)

The analyst turns raw findings into plain-English explanations. It is a
**local, deterministic engine** — a curated knowledge base plus an
explanation builder — not a cloud model. No finding, banner, or address
ever leaves the machine to produce an explanation.

## What an explanation contains

`GET /findings/{id}/explanation` returns:

| Field | Content |
|---|---|
| `summary` | One-line plain-English summary |
| `what_was_observed` | What discovery actually saw (handshake proof, banner, incl. version-disclosure notes) |
| `what_it_means` | What the service is, in plain language |
| `why_it_matters` | Risk context with real-world relevance |
| `what_to_do` | Prioritized remediation steps |
| `confidence` | Proven vs. inferred, and why the finding stays `suspected` |
| `evidence_refs` | `collector:excerpt_hash` pointers back to the evidence |

## Honesty rules

The engine distinguishes **proof** from **inference**:

- *Proven:* a completed TCP handshake means a service is listening on that port.
- *Inferred:* the service identity comes from the port number and any captured
  banner — it is not deep fingerprinting, and a non-standard port could be
  anything. That is why discovery findings remain `suspected` until a human
  confirms them.

A silent host ("unresponsive") is explained as *not assessed*, never as clean.

## Knowledge base

`analyst/knowledge.py` holds one entry per service the discovery agent knows
(`agent/discovery.py` `PORTS`), plus fallbacks for unknown ports and
unresponsive hosts. A test (`test_kb_covers_every_discovery_port`) fails if a
discovery port has no knowledge entry, so the two stay in sync.

## Extending

To cover a new service: add the port to `PORTS` in `agent/discovery.py` and a
matching entry to `SERVICE_KB` with `what`, `risk`, and `remediation_steps`
(highest priority first). The test suite enforces the pairing.
