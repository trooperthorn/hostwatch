"""CPU power from Intel RAPL via the powercap interface.

energy_uj is a cumulative microjoule counter that wraps at
max_energy_range_uj. Watts = delta_energy / delta_time, with wrap handled.

Since kernel 5.10, energy_uj is readable by root only (PLATYPUS, CVE-2020-8694).
scripts/rapl-access.sh grants read access to a dedicated group instead of
running this container as root. detect() reports the permission problem
explicitly so it is never mistaken for missing hardware.
"""

from __future__ import annotations

import os
import time

from .base import Collector, read_int, read_text


class RaplCollector(Collector):
    id = "rapl"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prev: dict[str, tuple[int, float]] = {}

    def _zones(self) -> list:
        base = self.sysfs / "class" / "powercap"
        if not base.is_dir():
            return []
        return sorted(p for p in base.iterdir() if p.name.startswith("intel-rapl:"))

    def detect(self) -> tuple[bool, str]:
        zones = self._zones()
        if not zones:
            return False, "no intel-rapl zones (not an Intel CPU, or powercap not exposed)"
        energy = zones[0] / "energy_uj"
        if not os.access(energy, os.R_OK):
            return False, "RAPL present but energy_uj not readable; run scripts/rapl-access.sh on the host"
        return True, f"{len(zones)} zone(s)"

    def collect(self):
        out = []
        now = time.monotonic()
        wall = time.time()
        for zone in self._zones():
            name = read_text(zone / "name") or zone.name
            energy = read_int(zone / "energy_uj")
            max_range = read_int(zone / "max_energy_range_uj")
            if energy is None:
                out.append(self.sample("watts", None, "W", ts=wall, zone=zone.name, domain=name))
                continue
            prev = self._prev.get(zone.name)
            self._prev[zone.name] = (energy, now)
            if prev is None:
                continue
            delta = energy - prev[0]
            if delta < 0 and max_range:
                delta += max_range
            dt = now - prev[1]
            if dt <= 0 or delta < 0:
                continue
            out.append(self.sample("watts", round(delta / dt / 1e6, 3), "W", ts=wall,
                                   zone=zone.name, domain=name))
        return out
