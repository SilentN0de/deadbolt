# Security Policy

## Scope of this project

This platform is built **only** for assessing systems the operator owns or is
explicitly authorized to test. It is a defensive security tool.

## What's in the repository

- Read-only discovery code (TCP connect scans, banner grabs). No exploit
  code, no payloads, no brute-forcing, no lateral-movement tooling — by design,
  not by omission. Those capabilities are out of scope for this project.
- Documentation describing authorization requirements and safe use.

## What must never be committed

- API keys, passwords, SSH credentials, tokens, or private keys.
- Assessment data: `*.db` files, `logs/`, and `data/` are gitignored.
- Sensitive host information from real assessments (IPs, banners, hostnames).
- Exploit details for third-party systems.

## Reporting a vulnerability in this project

If you find a security issue in the platform itself (e.g. a scope-enforcement
bypass), please report it responsibly: do not open a public issue with
reproduction details. Contact the maintainer directly so it can be fixed before
disclosure.

## Acceptable use

- Do not point the agent at targets you do not own or lack written
  authorization to assess. Unauthorized scanning may be illegal in your
  jurisdiction.
- The scope file (`config/authorized_targets.yaml`) is the enforcement point:
  do not weaken its defaults on shared or public deployments.
- Public-IP targets require explicit `authorization_acknowledged: true` plus
  per-target `authorized: true`, and every decision is audit-logged.
