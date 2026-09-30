# Controlled Validation (V0.3)

Discovery finds open ports; validation *confirms* them with safe, read-only
follow-up checks. Every validation is operator-triggered, single-finding,
scope-enforced, and audit-logged.

## The checks

| Check | What it does | Safe because |
|---|---|---|
| `tcp_reprobe` | Re-connects to the finding's host:port (recv-only banner grab) | Same as discovery: no data sent |
| `tls_certificate` | TLS handshake; reads the certificate (subject, issuer, expiry, self-signed?, TLS version) | Handshake only, no application data; never verifies (we want to *see* bad certs) |
| `banner_intel` | Offline parse of an already-captured banner; flags long-unmaintained releases | No network I/O at all |

`banner_intel` only flags versions that are indisputably past maintenance
(e.g. OpenSSH < 7.4, from December 2016). Anything else is reported as
"version disclosed — verify it is patched."

## Outcomes and status transitions

- `confirmed` — re-probe still sees the open port. `suspected` → `confirmed`.
- `false-positive` — re-probe is refused: the service is gone.
  `suspected` → `false-positive`.
- `intel` — checks ran and gathered information, but nothing changed the
  open/closed verdict (e.g. TLS-only validation).
- `inconclusive` — checks could not run cleanly (timeouts, errors).

Status only ever transitions *out of* `suspected`; human-set states like
`accepted-risk` or `fixed` are never overwritten by the validator.

## Safety rails

1. **Scope enforcement** — the finding's host must be inside the authorized
   scope file, or validation is refused (and the refusal is audited).
2. **Single finding** — no sweeps; the operator picks one finding at a time.
3. **Read-only** — no payloads, no authentication attempts, no brute force.
4. **Cooldown** — the API rejects re-validation of the same finding within
   10 seconds (prevents double-submit accidents).
5. **Audit** — every attempt, allowed or denied, lands in the immutable
   audit log with the scope hash.

## API

- `POST /findings/{id}/validate` — body `{"scope": ..., "checks": [...]}`;
  `checks` defaults to reprobe + banner intel (+ TLS for 443/8443).
- `GET /findings/{id}/validations` — validation history for a finding.

## Testing it safely: the sim lab

`sim/lab.py` spins up **fake** services on 127.0.0.1 (ephemeral ports): an
outdated OpenSSH banner, an outdated nginx header, a self-signed HTTPS
server (needs `openssl`), and a guaranteed-closed port. The test suite
validates against these — no real network involved.

For manual experiments:

```bash
python scripts/simulate_lab.py   # prints the fake service table; Ctrl-C stops
```

Then point discovery/validation at 127.0.0.1 with a scope file that
authorizes it, using the printed ports.
