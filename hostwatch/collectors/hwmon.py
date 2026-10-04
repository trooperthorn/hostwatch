"""Temperatures, voltages, fans, and power from /sys/class/hwmon.

Raw values only. Board-specific voltage divider scaling (for example +12V on
the NCT6779D) is applied later from a per-host calibration, not guessed here.
"""

from __future__ import annotations

import re

from ..config import sensor_matches
from .base import Collector, read_int, read_text

# sysfs file prefix -> (metric, unit, divisor to reach the unit)
KINDS = {"temp": ("temp", "C", 1000), "in": ("voltage", "V", 1000),
         "fan": ("fan", "RPM", 1), "power": ("power", "W", 1_000_000)}
INPUT_RE = re.compile(r"^(temp|in|fan|power)(\d+)_input$")


class HwmonCollector(Collector):
    linux_only = True
    id = "hwmon"

    def __init__(self, sysfs, procfs, ignore=()) -> None:
        """`ignore` is a sequence of chip:sensor glob patterns whose readings are dropped."""
        super().__init__(sysfs, procfs)
        self.ignore = tuple(ignore)

    def _devices(self):
        base = self.sysfs / "class" / "hwmon"
        return sorted(base.glob("hwmon*")) if base.is_dir() else []

    def is_absent(self):
        """Absent when /sys/class/hwmon is readable and has no devices."""
        try:
            return not any((self.sysfs / "class" / "hwmon").iterdir())
        except OSError:
            return False

    def detect(self):
        devs = self._devices()
        if not devs:
            return False, "no hwmon devices"
        return True, ", ".join(read_text(d / "name") or d.name for d in devs)

    def collect(self):
        out = []
        for dev in self._devices():
            chip = read_text(dev / "name") or dev.name
            for f in sorted(dev.iterdir()):
                m = INPUT_RE.match(f.name)
                if not m:
                    continue
                prefix, idx = m.groups()
                metric, unit, div = KINDS[prefix]
                raw = read_int(f)
                label = read_text(dev / f"{prefix}{idx}_label") or f"{prefix}{idx}"
                if self.ignore and sensor_matches(self.ignore, chip, label):
                    continue
                value = None if raw is None else round(raw / div, 3)
                out.append(self.sample(metric, value, unit, chip=chip, sensor=label))
        return out
