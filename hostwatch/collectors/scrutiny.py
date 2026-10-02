"""Per-disk SMART health from a Scrutiny instance's REST API.

UNVERIFIED: the response shape of GET /api/summary is taken from Scrutiny's
web UI usage and has not been confirmed against v0.9.5 on MediaIn-SVR. Confirm
with: curl -s http://localhost:8081/api/summary | python3 -m json.tool
The parser is defensive: unknown shapes produce an unavailable source with a
reason, never invented values.

device_status (Scrutiny convention): 0 passed, 1 failed by SMART,
2 failed by Scrutiny thresholds, 3 failed by both.
"""

from __future__ import annotations

import httpx

from .base import Collector


class ScrutinyCollector(Collector):
    id = "scrutiny"

    def __init__(self, sysfs, procfs, url: str) -> None:
        super().__init__(sysfs, procfs)
        self.url = url.rstrip("/")
        self._last_error = ""

    def _fetch(self) -> dict:
        r = httpx.get(f"{self.url}/api/summary", timeout=10)
        r.raise_for_status()
        return r.json()

    def detect(self):
        if not self.url:
            return False, "HOSTWATCH_SCRUTINY_URL not set"
        try:
            summary = self._fetch()["data"]["summary"]
        except Exception as exc:  # network, HTTP, JSON, or shape error
            return False, f"Scrutiny API unusable at {self.url}: {type(exc).__name__}: {exc}"
        return True, f"{len(summary)} device(s)"

    def collect(self):
        out = []
        try:
            summary = self._fetch()["data"]["summary"]
        except Exception as exc:
            return [self.sample("api_up", 0, "", error=type(exc).__name__)]
        out.append(self.sample("api_up", 1, ""))
        for wwn, entry in summary.items():
            dev = entry.get("device", {}) or {}
            smart = entry.get("smart", {}) or {}
            labels = {"wwn": wwn, "device": str(dev.get("device_name", "")),
                      "model": str(dev.get("model_name", "")), "serial": str(dev.get("serial_number", ""))}
            status = dev.get("device_status")
            out.append(self.sample("device_status", status if isinstance(status, int) else None, "", **labels))
            for key, metric, unit in (("temp", "temp", "C"), ("power_on_hours", "power_on_hours", "h")):
                val = smart.get(key)
                out.append(self.sample(metric, val if isinstance(val, (int, float)) else None, unit, **labels))
        return out
