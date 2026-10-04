"""Windows memory and commit charge read through the seam (values reported in bytes).

The metric names `mem_total` and `mem_available` match the Linux `memory` collector, whose source id
is also used. Windows has no swap counters like /proc/meminfo, so the commit limit and the committed
bytes are reported as `commit_limit` and `commit_used` instead. A figure the host does not report is
left out rather than reported as zero.
"""

from __future__ import annotations

from ..windows import SeamError
from .base import Collector

OS_CLASS = "Win32_OperatingSystem"
OS_PROPERTIES = ["TotalVisibleMemorySize"]
MEM_CLASS = "Win32_PerfFormattedData_PerfOS_Memory"
MEM_PROPERTIES = ["AvailableBytes", "CommitLimit", "CommittedBytes"]

# metric name -> property of the formatted memory counters, already in bytes
FROM_MEM = {"mem_available": "AvailableBytes", "commit_limit": "CommitLimit", "commit_used": "CommittedBytes"}


def _number(row: dict, key: str) -> int | None:
    value = row.get(key)
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class WinMemoryCollector(Collector):
    id = "memory"

    def detect(self) -> tuple[bool, str]:
        if self.seam is None:
            return False, "no Windows seam"
        try:
            self._rows()
        except SeamError as exc:
            return False, str(exc)
        return True, ""

    def _rows(self) -> tuple[dict, dict]:
        os_rows = self.seam.cim.query(OS_CLASS, OS_PROPERTIES)
        mem_rows = self.seam.cim.query(MEM_CLASS, MEM_PROPERTIES)
        if not os_rows or not mem_rows:
            raise SeamError("memory counters returned no rows")
        return os_rows[0], mem_rows[0]

    def collect(self):
        os_row, mem_row = self._rows()
        out = []
        kib = _number(os_row, "TotalVisibleMemorySize")
        if kib is not None:
            out.append(self.sample("mem_total", kib * 1024, "B"))
        for metric, prop in FROM_MEM.items():
            value = _number(mem_row, prop)
            if value is not None:
                out.append(self.sample(metric, value, "B"))
        return out
