"""Fan controller status from thermalctl.

The thermalctl service (the thermal-control-linux repo) publishes an atomic JSON status file,
by default /run/thermalctl/status.json. This collector only reads that file. Reported:
  zone_temp   degrees C per zone, label zone=<id>
  zone_load   percent per zone, label zone=<id>
  fan_duty    percent per header, unit %, labels chip=thermalctl, sensor=<header>, state, mode, reasons
  fan         rpm per header, unit RPM, the same labels

The fan rows use the chip and sensor labels so the hub summary lists each header in the Fans
group next to the hwmon fans. The state label is the controller state for the header (a
failsafe state is shown as a warning) and the reasons label joins the failsafe reasons with
commas. A value the controller could not measure is a sample with no value, never zero.

The file is unavailable when it cannot be read, is not a JSON object, or its timestamp is
older than STALE_AFTER_S, because a dead controller leaves its last file behind. It is absent
only on positive evidence: the directory that would hold the file is readable and the file is
missing, or the directory is missing from a readable parent (a host that never ran thermalctl).
"""

from __future__ import annotations

import json
import math
import os
import time
from collections.abc import Callable
from pathlib import Path

from .base import Collector

DEFAULT_STATUS = "/run/thermalctl/status.json"
STALE_AFTER_S = 60.0
CHIP = "thermalctl"


def _num(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


class ThermalctlCollector(Collector):
    id = "thermalctl"

    def __init__(self, sysfs: Path, procfs: Path, status_path: str = "",
                 clock: Callable[[], float] = time.time) -> None:
        super().__init__(sysfs, procfs)
        self.path = Path(status_path.strip() or DEFAULT_STATUS)
        self._clock = clock

    def _read(self) -> tuple[dict | None, str]:
        try:
            text = self.path.read_text()
        except OSError as exc:
            return None, f"thermalctl status {self.path} is not readable: {exc.strerror or exc}"
        try:
            doc = json.loads(text)
        except ValueError:
            return None, f"thermalctl status {self.path} is not valid JSON"
        if not isinstance(doc, dict):
            return None, f"thermalctl status {self.path} is not a JSON object"
        ts = _num(doc.get("timestamp"))
        if ts is None:
            return None, f"thermalctl status {self.path} has no numeric timestamp"
        age = self._clock() - ts
        if age > STALE_AFTER_S:
            return None, f"thermalctl status {self.path} is stale: written {age:.0f}s ago, the controller may be stopped"
        return doc, ""

    def detect(self) -> tuple[bool, str]:
        doc, reason = self._read()
        if doc is None:
            return False, reason
        return True, f"thermalctl status {self.path}"

    def is_absent(self) -> bool:
        parent = self.path.parent
        if self.path.exists():
            return False
        try:
            os.listdir(parent)
            return True
        except FileNotFoundError:
            pass
        except OSError:
            return False
        try:
            os.listdir(parent.parent)
        except OSError:
            return False
        return True

    def collect(self):
        doc, _ = self._read()
        if doc is None:
            return []
        out = []
        mode = str(doc.get("mode", ""))
        zones = doc.get("zones")
        for zid, z in sorted((zones if isinstance(zones, dict) else {}).items()):
            if not isinstance(z, dict):
                continue
            out.append(self.sample("zone_temp", _num(z.get("temperature")), "C", zone=zid))
            out.append(self.sample("zone_load", _num(z.get("load")), "%", zone=zid))
        headers = doc.get("headers")
        for hid, h in sorted((headers if isinstance(headers, dict) else {}).items()):
            if not isinstance(h, dict):
                continue
            reasons = h.get("reasons")
            labels = {"chip": CHIP, "sensor": hid, "state": str(h.get("state", "")), "mode": mode,
                      "reasons": ",".join(str(r) for r in reasons) if isinstance(reasons, list) else ""}
            out.append(self.sample("fan_duty", _num(h.get("duty")), "%", **labels))
            out.append(self.sample("fan", _num(h.get("rpm")), "RPM", **labels))
        return out
