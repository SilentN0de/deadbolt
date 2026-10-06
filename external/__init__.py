"""External assessment: verified outside-in worker (V0.5).

A small worker program runs on a machine *outside* the assessed network and
probes only explicitly authorized targets (e.g. his own public IP, a VPS he
controls). Results come back to the Deadbolt API, which stores them as
ordinary findings with full evidence through the existing lifecycle machine.

Read-only probes only. This is the inspector, not the handyman: no
exploitation, no payloads, no brute force, no authentication attempts, no
persistence, no destructive actions, no lateral movement.

Layout:
  probes.py  - read-only outside-in probe implementations
  server.py  - worker registry + token auth, assessment queue, result ingest
  worker.py  - worker client: register, poll, run probes, push results
               (run anywhere with Python 3: `python -m external.worker`)
"""

from .probes import ALL_PROBES
from .server import (ExternalError, authenticate_worker,
                     enqueue_assessment, register_worker, revoke_worker)

__all__ = [
    "ALL_PROBES",
    "ExternalError",
    "authenticate_worker",
    "enqueue_assessment",
    "register_worker",
    "revoke_worker",
]
