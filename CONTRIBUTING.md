# Contributing

Small, focused project — a few ground rules keep it that way.

## Workflow

1. Work in small, descriptive commits (see git history for the style:
   `discovery: ...`, `api: ...`, `tests: ...`, `docs: ...`).
2. Every behavior change ships with a test. Scope-enforcement changes ship
   with a *refusal* test.
3. Update `CHANGELOG.md` for user-visible changes.
4. Never commit secrets, credentials, `*.db` files, or anything under `logs/`
   or `data/` (all gitignored).

## Safety invariants (non-negotiable)

- The agent must refuse to run without an explicit scope file listing
  authorized targets. Any change to `agent/scope.py` must keep every existing
  refusal test passing and add tests for new behavior.
- Discovery stays read-only: TCP connect + banner grab only. Proposals that
  add payloads, brute force, or lateral movement will not be merged.
- Assessment data stays local: no network calls that transmit findings,
  evidence, or telemetry anywhere.

## Code style

- Standard library first; new dependencies need a justification.
- Type hints on new public functions; docstrings explaining *why*, not *what*.
- Run `python -m pytest -q` before pushing — the suite must be green.
