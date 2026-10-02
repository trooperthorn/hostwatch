"""Memory and swap from /proc/meminfo (values reported in bytes)."""

from __future__ import annotations

from .base import Collector, read_text

FIELDS = {"MemTotal": "mem_total", "MemAvailable": "mem_available",
          "SwapTotal": "swap_total", "SwapFree": "swap_free"}


class MemoryCollector(Collector):
    id = "memory"

    def detect(self):
        return (read_text(self.procfs / "meminfo") is not None, "")

    def collect(self):
        out = []
        for line in (read_text(self.procfs / "meminfo") or "").splitlines():
            key, _, rest = line.partition(":")
            if key in FIELDS:
                kib = int(rest.split()[0])
                out.append(self.sample(FIELDS[key], kib * 1024, "B"))
        return out
