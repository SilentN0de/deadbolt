"""Automatic scheduled scans (daily / weekly / every N hours).

The scheduler is dependency-free: a small config dataclass, a next-run
calculator, a scan engine that reuses the normal pipeline
(discovery -> optional validation -> retest -> trend snapshot), and a
background thread the API starts on boot.

Times are interpreted in the server's local timezone.
"""

from .config import ScheduleConfig, ScheduleError, config_from_dict, config_to_dict
from .engine import (SchedulerThread, compute_next_run, due_now,
                     run_scheduled_scan)

__all__ = [
    "ScheduleConfig",
    "ScheduleError",
    "SchedulerThread",
    "compute_next_run",
    "config_from_dict",
    "config_to_dict",
    "due_now",
    "run_scheduled_scan",
]
