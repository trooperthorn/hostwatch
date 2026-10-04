"""Fan and temperature status from the Thermal Control Suite on Windows.

The Thermal Control Suite service answers one read-only pipe request, GetStatusReadOnly, on the
named pipe ThermalControlSuite.Ipc. This collector asks for it through the seam's PipeStatusReader
with a short timeout and sends nothing else: no setter, override or audit request is ever made.

Accepted payload: the ReadOnlyStatus document with schemaVersion 1. The service raises the version
only for a breaking change and adds fields within a version, so extra fields are ignored and any
other version (including a missing or non-integer one) makes the source unavailable rather than
guessing at a shape. The pipe serves property names in PascalCase and the status file in camelCase,
so keys are compared with their first letter lowered and both forms are accepted.

Reported, reusing the thermalctl metric and label names:
  zone_temp    degrees C per zone, label zone=<id>
  zone_load    percent per zone, label zone=<id>
  zone_duty    percent per zone, labels zone=<id>, reasons (the zone reasons other than Normal)
  fan_duty     percent actually applied per fan, unit %, labels chip=thermalsuite, sensor=<fan id>,
               state, mode, reasons, dry_run, firmware_controlled, config_error, applied
  fan          rpm per fan, unit RPM, the same labels
  fan_target   percent the service computed for the fan, unit %, the same labels
  failsafe     count of active fail-safe conditions, label reasons

The state label is failsafe when a fan:<id> or control reason is active or the fan is stalled,
firmware_controlled when the firmware sets the fan, dry_run in dry run, and otherwise active. A
failsafe fan is a warning in the summary, as for thermalctl. The mode label is dry_run or active.
fan_duty is only reported when the duty was really applied: in dry run, or for a firmware controlled
fan, the service reports an actual of 0 that is not a measurement, so the sample has no value and
fan_target carries the computed duty. A value the service reported as null is a sample with no value.

The source is unavailable, with a reason, on a pipe error or timeout, an unknown schema version, a
payload that is not the documented shape, a service that has not completed a control pass, or a
last pass older than STALE_AFTER_S. It is absent only when the pipe does not exist, which means the
service is not installed or not running.
"""

from __future__ import annotations

import math
from typing import Any

from ..windows import DEFAULT_PIPE_TIMEOUT_S, PipeAbsentError, SeamError
from .base import Collector

PIPE_NAME = "ThermalControlSuite.Ipc"
ACCEPTED_SCHEMA_VERSION = 1
STALE_AFTER_S = 60.0
CHIP = "thermalsuite"


def _num(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


def _flag(value: object) -> bool:
    return value is True


def _normalize(value: Any) -> Any:
    """Lower the first letter of every object key so PascalCase pipe output reads as the camelCase file."""
    if isinstance(value, dict):
        return {(k[:1].lower() + k[1:] if isinstance(k, str) else k): _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def _strings(value: object) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []


def _labels(flag: bool) -> str:
    return "true" if flag else "false"


class WinThermalSuiteCollector(Collector):
    id = "win_thermalsuite"

    def __init__(self, *args, pipe_name: str = PIPE_NAME, timeout_s: float = DEFAULT_PIPE_TIMEOUT_S,
                 **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.pipe_name = pipe_name
        self.timeout_s = timeout_s
        self._absent = False

    def _status(self) -> dict[str, Any]:
        if self.seam is None:
            raise SeamError("no Windows seam")
        raw = self.seam.pipe.read(self.pipe_name, self.timeout_s)
        doc = _normalize(raw)
        if not isinstance(doc, dict):
            raise SeamError("Thermal Control Suite status is not a JSON object")
        version = doc.get("schemaVersion")
        if isinstance(version, bool) or not isinstance(version, int):
            raise SeamError("Thermal Control Suite status has no integer schemaVersion")
        if version != ACCEPTED_SCHEMA_VERSION:
            raise SeamError(f"Thermal Control Suite status schemaVersion {version} is not supported, "
                            f"this agent accepts {ACCEPTED_SCHEMA_VERSION}")
        if not isinstance(doc.get("zones"), list) or not isinstance(doc.get("fans"), list):
            raise SeamError("Thermal Control Suite status has no zones and fans lists")
        age = _num(doc.get("passAgeSeconds"))
        if age is None:
            raise SeamError("Thermal Control Suite has not completed a control pass yet")
        if age > STALE_AFTER_S:
            raise SeamError(f"Thermal Control Suite status is stale: the last control pass was {age:.0f}s ago, "
                            "the service may be hung")
        return doc

    def detect(self) -> tuple[bool, str]:
        self._absent = False
        try:
            self._status()
        except PipeAbsentError as exc:
            self._absent = True
            return False, str(exc)
        except SeamError as exc:
            return False, str(exc)
        return True, f"Thermal Control Suite pipe {self.pipe_name}"

    def is_absent(self) -> bool:
        return self._absent

    def collect(self):
        doc = self._status()
        dry_run = _flag(doc.get("dryRun"))
        mode = "dry_run" if dry_run else "active"
        reasons = _strings(doc.get("failSafeReasons"))
        out = [self.sample("failsafe", float(len(reasons)), "count", reasons=",".join(reasons))]
        for z in doc["zones"]:
            if not isinstance(z, dict) or not isinstance(z.get("id"), str) or not z["id"]:
                continue
            zid = z["id"]
            out.append(self.sample("zone_temp", _num(z.get("tempC")), "C", zone=zid))
            out.append(self.sample("zone_load", _num(z.get("loadPercent")), "%", zone=zid))
            zone_reasons = [r for r in _strings(z.get("reasons")) if r != "Normal"]
            out.append(self.sample("zone_duty", _num(z.get("dutyPercent")), "%", zone=zid,
                                   reasons=",".join(zone_reasons)))
        for f in doc["fans"]:
            if not isinstance(f, dict) or not isinstance(f.get("id"), str) or not f["id"]:
                continue
            fid = f["id"]
            firmware = _flag(f.get("firmwareControlled"))
            applied = _flag(f.get("applied"))
            fan_reasons = [r for r in reasons if r.startswith(f"fan:{fid}:") or r.startswith("control:")]
            if fan_reasons or _flag(f.get("stalled")):
                state = "failsafe"
            elif firmware:
                state = "firmware_controlled"
            elif dry_run:
                state = "dry_run"
            else:
                state = "active"
            labels = {"chip": CHIP, "sensor": fid, "state": state, "mode": mode,
                      "reasons": ",".join(fan_reasons), "dry_run": _labels(dry_run),
                      "firmware_controlled": _labels(firmware), "config_error": _labels(_flag(f.get("configError"))),
                      "applied": _labels(applied)}
            measured = applied and not firmware
            out.append(self.sample("fan_duty", _num(f.get("actualPercent")) if measured else None, "%", **labels))
            out.append(self.sample("fan", _num(f.get("rpm")), "RPM", **labels))
            out.append(self.sample("fan_target", _num(f.get("targetPercent")), "%", **labels))
        return out
