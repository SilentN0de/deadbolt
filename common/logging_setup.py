"""Central logging + local crash-report hook.

All logs stay on this machine:
  - rotating file log  -> logs/platform.log
  - crash reports      -> logs/crashes/crash-<utc-timestamp>.json
No telemetry is ever uploaded anywhere.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import threading
import traceback
from datetime import datetime, timezone

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
CRASH_DIR = os.path.join(LOG_DIR, "crashes")

_configured = False


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure console + rotating file logging. Idempotent."""
    global _configured
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(CRASH_DIR, exist_ok=True)

    logger = logging.getLogger("deadbolt")
    if _configured:
        return logger
    logger.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"
    )

    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, "platform.log"),
        maxBytes=1_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)

    _configured = True
    return logger


def _write_crash_report(exc_type, exc_value, exc_tb) -> str:
    os.makedirs(CRASH_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = os.path.join(CRASH_DIR, f"crash-{stamp}.json")
    report = {
        "timestamp": utc_now_iso(),
        "argv": sys.argv,
        "exception_type": getattr(exc_type, "__name__", str(exc_type)),
        "exception_message": str(exc_value),
        # Local diagnostic context only; never exfiltrated.
        "traceback": traceback.format_exception(exc_type, exc_value, exc_tb),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return path


def install_crash_hook() -> None:
    """Install uncaught-exception hooks (main thread + worker threads).

    Writes a local JSON crash report. Does not upload anything.
    """

    def _excepthook(exc_type, exc_value, exc_tb):
        try:
            path = _write_crash_report(exc_type, exc_value, exc_tb)
            logging.getLogger("deadbolt").critical(
                "Uncaught exception; local crash report written to %s", path
            )
        finally:
            sys.__excepthook__(exc_type, exc_value, exc_tb)

    def _thread_excepthook(args: threading.ExceptHookArgs):
        _excepthook(args.exc_type, args.exc_value, args.exc_traceback)

    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook
