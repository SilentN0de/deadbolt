"""Schedule configuration: shape, validation, (de)serialization."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class ScheduleError(ValueError):
    """Raised when a schedule configuration is invalid."""


CADENCES = ("daily", "weekly", "interval")
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


@dataclass
class ScheduleConfig:
    """How often Deadbolt scans automatically.

    cadence="daily":   run every day at `time` (local).
    cadence="weekly":  run every `weekday` (0=Monday) at `time` (local).
    cadence="interval": run every `interval_hours` hours from the last run.
    """

    enabled: bool = False
    cadence: str = "daily"
    time: str = "02:00"          # HH:MM local, for daily/weekly
    weekday: int = 0            # 0=Monday .. 6=Sunday, for weekly
    interval_hours: float = 24  # for interval
    auto_validate: bool = True  # run read-only validation on new findings
    scope_path: str = ""        # empty -> default authorized_targets.yaml
    ports: Optional[List[int]] = None

    def validate(self) -> "ScheduleConfig":
        if self.cadence not in CADENCES:
            raise ScheduleError(
                f"cadence must be one of {CADENCES}, got {self.cadence!r}")
        if not _TIME_RE.match(self.time or ""):
            raise ScheduleError(
                f"time must be HH:MM (24h), got {self.time!r}")
        if not isinstance(self.weekday, int) or not 0 <= self.weekday <= 6:
            raise ScheduleError(
                f"weekday must be 0 (Monday) .. 6 (Sunday), got {self.weekday!r}")
        try:
            hours = float(self.interval_hours)
        except (TypeError, ValueError):
            raise ScheduleError(
                f"interval_hours must be a number, got {self.interval_hours!r}")
        if not 0.25 <= hours <= 24 * 31:
            raise ScheduleError(
                "interval_hours must be between 0.25 and 744 "
                f"(31 days), got {self.interval_hours!r}")
        self.interval_hours = hours
        if self.ports is not None:
            for p in self.ports:
                if not isinstance(p, int) or not 1 <= p <= 65535:
                    raise ScheduleError(f"invalid port in ports: {p!r}")
        if not isinstance(self.enabled, bool):
            raise ScheduleError("enabled must be true/false")
        if not isinstance(self.auto_validate, bool):
            raise ScheduleError("auto_validate must be true/false")
        return self


def config_from_dict(data: Dict[str, Any]) -> ScheduleConfig:
    """Build a validated config from API/dashboard input. Unknown keys rejected."""
    if not isinstance(data, dict):
        raise ScheduleError("schedule body must be a JSON object")
    known = set(ScheduleConfig.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ScheduleError(f"unknown schedule field(s): {sorted(unknown)}")
    cfg = ScheduleConfig(**{k: v for k, v in data.items() if k in known})
    return cfg.validate()


def config_to_dict(cfg: ScheduleConfig) -> Dict[str, Any]:
    return asdict(cfg)
