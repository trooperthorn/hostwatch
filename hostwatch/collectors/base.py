"""Collector interface.

A collector has two jobs:

detect()  decides once (and again every HOSTWATCH_REDETECT seconds) whether its
          data source exists on this host, and returns a human-readable reason
          when it does not. Missing hardware is a normal outcome, not an error.

collect() returns samples for one cycle. Collectors that compute rates (watts,
          utilization, residency) keep the previous reading internally and
          return nothing on their first call rather than a misleading value.
"""

from __future__ import annotations

import time
from pathlib import Path

from .. import tiers
from ..model import Sample
from ..windows import WindowsSeam


class Collector:
    id: str = "base"
    # The polling tier that decides how often collect() runs (see tiers.py). Most sources are device metrics.
    tier: str = tiers.DEVICE_METRICS
    # True for a cheap local source whose state changes are events (RAID, ZFS, UPS). The agent reads it
    # every few seconds for threshold events only, apart from its tier, so a failure is not held to the poll rate.
    event_watch: bool = False
    # True for a slow source that has a lightweight health probe. The agent runs probe() every few seconds on
    # a worker thread, off the event path, and raises threshold events from what it returns, so a failure
    # is not held to the slow tier. collect() still runs on the tier for the metrics.
    event_probe: bool = False
    # Seconds one collect() or probe() call may take before the agent gives up on it and reports the source
    # unavailable. The call is left to finish on its worker thread and its late answer is discarded.
    time_limit_s: float = 60.0
    # True for a configured network source that is polled every cycle even after a failure,
    # being unavailable for that cycle only. Local sysfs sources wait for re-detection.
    retry_each_cycle: bool = False
    # True for a source that reads Linux-only locations (sysfs, procfs, /run). The agent reports it
    # not present on a Windows host instead of present but unavailable.
    linux_only: bool = False

    def __init__(self, sysfs: Path | None = None, procfs: Path | None = None,
                 seam: WindowsSeam | None = None) -> None:
        # A Windows collector is built with a seam and needs no sysfs or procfs path.
        self.sysfs = sysfs
        self.procfs = procfs
        self.seam = seam

    def detect(self) -> tuple[bool, str]:
        raise NotImplementedError

    def collect(self) -> list[Sample]:
        raise NotImplementedError

    def probe(self) -> list[Sample]:
        """A cheap reading of just the health the threshold events need. The default is a full
        collect(), which suits a source that is one request. Only used when event_probe is set."""
        return self.collect()

    def is_absent(self) -> bool:
        """True only when the place this source would live was readable and shows it is not there.

        Called by the agent after detect() fails. An unreadable or missing location is unavailable,
        not absent, so the default is False and a collector must positively establish absence.
        """
        return False

    def sample(self, metric: str, value: float | None, unit: str = "", ts: float | None = None,
               **labels: str) -> Sample:
        return Sample(source=self.id, metric=metric, value=value, unit=unit,
                      labels={k: str(v) for k, v in labels.items()},
                      ts=time.time() if ts is None else ts)


def read_text(path: Path) -> str | None:
    """Read a small sysfs/procfs file, returning None on any OS error."""
    try:
        return path.read_text().strip()
    except OSError:
        return None


def read_int(path: Path) -> int | None:
    text = read_text(path)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None
