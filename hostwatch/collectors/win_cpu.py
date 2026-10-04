"""Windows CPU utilization from cumulative performance counters read through the seam.

The raw counters are cumulative, so utilization is the change between two readings. The first call
returns nothing because there is no earlier reading, and a counter that goes backwards (a wrap or a
counter reset) also returns nothing for that cycle and starts a new baseline, since a guessed value
would be worse than none. The source id and metric name match the Linux `cpu` collector.
"""

from __future__ import annotations

from ..windows import SeamError
from .base import Collector

CLASS = "Win32_PerfRawData_PerfOS_Processor"
PROPERTIES = ["Name", "PercentIdleTime", "Timestamp_Sys100NS"]
TOTAL = "_Total"


def _counter(row: dict, key: str) -> int:
    """CIM 64-bit counters may arrive from PowerShell JSON as numbers or as decimal strings."""
    value = row[key]
    if isinstance(value, bool) or value is None:
        raise ValueError(key)
    return int(value)


class WinCpuCollector(Collector):
    id = "cpu"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prev: tuple[int, int] | None = None

    def detect(self) -> tuple[bool, str]:
        if self.seam is None:
            return False, "no Windows seam"
        try:
            self._read()
        except SeamError as exc:
            return False, str(exc)
        return True, ""

    def _read(self) -> tuple[int, int]:
        rows = self.seam.cim.query(CLASS, PROPERTIES)
        for row in rows:
            if row.get("Name") == TOTAL:
                try:
                    return _counter(row, "PercentIdleTime"), _counter(row, "Timestamp_Sys100NS")
                except (KeyError, ValueError, TypeError) as exc:
                    raise SeamError(f"{CLASS} _Total row has an unusable counter: {exc}") from exc
        raise SeamError(f"{CLASS} has no {TOTAL} instance")

    def collect(self):
        idle, stamp = self._read()
        prev, self._prev = self._prev, (idle, stamp)
        if prev is None:
            return []
        d_idle, d_time = idle - prev[0], stamp - prev[1]
        if d_time <= 0 or d_idle < 0:
            return []
        pct = 100 * (1 - d_idle / d_time)
        return [self.sample("utilization_pct", round(min(100.0, max(0.0, pct)), 2), "%")]
