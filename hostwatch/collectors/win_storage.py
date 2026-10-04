"""Windows physical disk, Storage Spaces and optional smartctl health read through the seam.

Two collectors live here. `WinStorageCollector` (source `win_storage`) reads the Storage
Management classes in the `root/Microsoft/Windows/Storage` namespace: `MSFT_PhysicalDisk`,
`MSFT_StorageReliabilityCounter`, `MSFT_StoragePool` and `MSFT_VirtualDisk`. `WinSmartctlCollector`
(source `win_smartctl`) runs `smartctl -j` through the seam's command runner and is absent when
smartctl is not installed.

Health metrics use the same 0 ok, 1 warning, 2 critical scale as the truenas `pool_health` metric:
  disk_health, pool_health, virtual_disk_health
    labels: id (stable identity used by threshold events), name, health and operational (the text
    Windows reported). The value is None when neither HealthStatus nor OperationalStatus is a
    recognised value, never zero.
Reliability counters are reported per disk when the host exposes them (`temp` C, `power_on_hours` h,
`wear_pct`, `read_errors_uncorrected`, `write_errors_uncorrected`) and are simply left out when it
does not. smartctl reports `smart_passed` (1 passed, 0 failed), `temp`, `power_on_hours`,
`reallocated_sectors`, `wear_pct` and `media_errors` when present in its JSON.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..windows import SeamError
from .base import Collector

NAMESPACE = "root/Microsoft/Windows/Storage"
DISK_CLASS = "MSFT_PhysicalDisk"
DISK_PROPERTIES = ["DeviceId", "FriendlyName", "SerialNumber", "MediaType", "BusType",
                   "HealthStatus", "OperationalStatus"]
COUNTER_CLASS = "MSFT_StorageReliabilityCounter"
COUNTER_PROPERTIES = ["DeviceId", "Temperature", "Wear", "PowerOnHours",
                      "ReadErrorsUncorrected", "WriteErrorsUncorrected"]
POOL_CLASS = "MSFT_StoragePool"
POOL_PROPERTIES = ["FriendlyName", "IsPrimordial", "HealthStatus", "OperationalStatus"]
VDISK_CLASS = "MSFT_VirtualDisk"
VDISK_PROPERTIES = ["FriendlyName", "HealthStatus", "OperationalStatus"]

OK, WARNING, CRITICAL = 0, 1, 2

HEALTH_TEXT = {0: "Healthy", 1: "Warning", 2: "Unhealthy", 5: "Unknown"}
HEALTH_LEVEL = {0: OK, 1: WARNING, 2: CRITICAL}
# Operational status values in the DMTF/Storage Management numbering. Values not listed here are
# ignored: they neither change the level nor appear in the label.
OPERATIONAL_TEXT = {2: "OK", 3: "Degraded", 4: "Stressed", 5: "Predictive Failure", 6: "Error",
                    7: "Non-Recoverable Error", 10: "Stopped", 11: "In Service", 12: "No Contact",
                    13: "Lost Communication"}
# Degraded is critical here because a pool or disk that lost redundancy is critical for the Linux
# md and zfs sources too. Stressed, stopped and in service (a repair or maintenance running) warn.
OPERATIONAL_LEVEL = {2: OK, 3: CRITICAL, 4: WARNING, 5: CRITICAL, 6: CRITICAL, 7: CRITICAL,
                     10: WARNING, 11: WARNING, 12: CRITICAL, 13: CRITICAL}
_TEXT_TO_HEALTH = {v.lower(): k for k, v in HEALTH_TEXT.items()}
_TEXT_TO_OPERATIONAL = {v.lower(): k for k, v in OPERATIONAL_TEXT.items()}


def _enum(value: Any, names: dict[str, int]) -> int | None:
    """CIM enums arrive from PowerShell JSON as numbers, numeric strings or the enum name."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.lstrip("-").isdigit():
            return int(text)
        return names.get(text.lower())
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def health_level(health: Any, operational: Any) -> tuple[int | None, str, str]:
    """Return (level, health text, operational text). The level is the worst of the recognised
    HealthStatus and OperationalStatus values, or None when none is recognised."""
    levels: list[int] = []
    h = _enum(health, _TEXT_TO_HEALTH)
    if h in HEALTH_LEVEL:
        levels.append(HEALTH_LEVEL[h])
    ops = []
    for item in _as_list(operational):
        o = _enum(item, _TEXT_TO_OPERATIONAL)
        if o not in OPERATIONAL_TEXT:
            continue
        ops.append(OPERATIONAL_TEXT[o])
        levels.append(OPERATIONAL_LEVEL[o])
    return (max(levels) if levels else None), HEALTH_TEXT.get(h, "Unknown"), ",".join(ops)


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


class WinStorageCollector(Collector):
    id = "win_storage"

    def detect(self) -> tuple[bool, str]:
        if self.seam is None:
            return False, "no Windows seam"
        try:
            disks = self.seam.cim.query(DISK_CLASS, DISK_PROPERTIES, NAMESPACE)
        except SeamError as exc:
            return False, str(exc)
        if not disks:
            return False, f"{DISK_CLASS} returned no physical disks"
        return True, f"{len(disks)} physical disk(s)"

    def _optional(self, class_name: str, properties: list[str]) -> list[dict[str, Any]]:
        """Rows of a class that some hosts do not expose. A failure leaves its samples out."""
        try:
            return self.seam.cim.query(class_name, properties, NAMESPACE)
        except SeamError:
            return []

    def _queried(self, class_name: str, properties: list[str]) -> tuple[list[dict[str, Any]], str]:
        try:
            return self.seam.cim.query(class_name, properties, NAMESPACE), ""
        except SeamError as exc:
            return [], str(exc)

    def _failed_query(self, metric: str, label: str, class_name: str, why: str):
        """A pool or virtual disk query that failed is an unknown health with the reason in a label,
        so a failed query is a visible warning and never reads as healthy."""
        return self.sample(metric, None, "", id=f"{class_name} query failed", health="Unknown", operational="",
                           reason=f"{class_name} query failed: {why}", **{label: ""})

    def collect(self):
        disks = self.seam.cim.query(DISK_CLASS, DISK_PROPERTIES, NAMESPACE)
        if not disks:
            raise SeamError(f"{DISK_CLASS} returned no physical disks")
        counters = {_text(r.get("DeviceId")): r for r in self._optional(COUNTER_CLASS, COUNTER_PROPERTIES)
                    if _text(r.get("DeviceId"))}
        out = []
        for row in disks:
            dev = _text(row.get("DeviceId"))
            if not dev:
                continue
            level, h_text, o_text = health_level(row.get("HealthStatus"), row.get("OperationalStatus"))
            labels = {"id": dev, "name": _text(row.get("FriendlyName")), "serial": _text(row.get("SerialNumber")),
                      "bus": _text(row.get("BusType")), "media": _text(row.get("MediaType"))}
            out.append(self.sample("disk_health", level, "", health=h_text, operational=o_text, **labels))
            counter = counters.get(dev)
            if counter is None:
                continue
            for metric, prop, unit in (("temp", "Temperature", "C"), ("wear_pct", "Wear", "%"),
                                       ("power_on_hours", "PowerOnHours", "h"),
                                       ("read_errors_uncorrected", "ReadErrorsUncorrected", ""),
                                       ("write_errors_uncorrected", "WriteErrorsUncorrected", "")):
                value = _number(counter.get(prop))
                if value is not None:
                    out.append(self.sample(metric, value, unit, **labels))
        pools, pool_err = self._queried(POOL_CLASS, POOL_PROPERTIES)
        if pool_err:
            out.append(self._failed_query("pool_health", "pool", POOL_CLASS, pool_err))
        for row in pools:
            if row.get("IsPrimordial") is True or not _text(row.get("FriendlyName")):
                continue  # the primordial pool holds every unused disk and has no meaningful health
            out.append(self._health_sample("pool_health", "pool", row))
        vdisks, vdisk_err = self._queried(VDISK_CLASS, VDISK_PROPERTIES)
        if vdisk_err:
            out.append(self._failed_query("virtual_disk_health", "virtual_disk", VDISK_CLASS, vdisk_err))
        for row in vdisks:
            if _text(row.get("FriendlyName")):
                out.append(self._health_sample("virtual_disk_health", "virtual_disk", row))
        return out

    def _health_sample(self, metric: str, label: str, row: dict[str, Any]):
        name = _text(row.get("FriendlyName"))
        level, h_text, o_text = health_level(row.get("HealthStatus"), row.get("OperationalStatus"))
        return self.sample(metric, level, "", id=name, health=h_text, operational=o_text, **{label: name})


SMARTCTL = "smartctl"
SMARTCTL_TIMEOUT_S = 20.0
MAX_DEVICES = 32
_DEVICE_NAME = re.compile(r"[A-Za-z0-9_./:\-]{1,64}")
_DEVICE_TYPE = re.compile(r"[a-z0-9,+]{1,32}")


def _json(stdout: str) -> dict[str, Any] | None:
    try:
        data = json.loads(stdout)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _dig(data: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


class WinSmartctlCollector(Collector):
    """Optional SMART health from `smartctl -j`. Absent when smartctl cannot be started."""

    id = "win_smartctl"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._not_installed = False

    def _run(self, args: list[str]):
        return self.seam.runner.run([SMARTCTL, *args], SMARTCTL_TIMEOUT_S)

    def _scan(self) -> list[tuple[str, str]]:
        data = _json(self._run(["--scan", "-j"]).stdout)
        if data is None:
            raise SeamError("smartctl --scan did not print JSON")
        found = []
        for dev in _as_list(data.get("devices")):
            if not isinstance(dev, dict):
                continue
            name, kind = _text(dev.get("name")), _text(dev.get("type"))
            if _DEVICE_NAME.fullmatch(name) and (not kind or _DEVICE_TYPE.fullmatch(kind)):
                found.append((name, kind))
        return found[:MAX_DEVICES]

    def detect(self) -> tuple[bool, str]:
        if self.seam is None:
            return False, "no Windows seam"
        try:
            devices = self._scan()
        except SeamError as exc:
            # The real runner words a start failure as "cannot run <program>"; a timeout or a bad
            # answer from an installed smartctl is unavailable, not absent.
            self._not_installed = str(exc).startswith(f"cannot run {SMARTCTL}")
            return False, "smartctl is not installed" if self._not_installed else str(exc)
        self._not_installed = False
        if not devices:
            return False, "smartctl found no devices"
        return True, f"{len(devices)} device(s)"

    def is_absent(self) -> bool:
        return self._not_installed

    def collect(self):
        out = []
        for name, kind in self._scan():
            args = ["-a", "-j"] + (["-d", kind] if kind else []) + [name]
            data = _json(self._run(args).stdout)
            # smartctl's exit status is a bit mask that also reports a failing disk, so the JSON is
            # the answer. Output that is not JSON means the disk could not be read this cycle.
            if data is None:
                continue
            out.extend(self._device_samples(name, data))
        return out

    def _device_samples(self, name: str, data: dict[str, Any]):
        labels = {"id": name, "device": name, "model": _text(data.get("model_name")),
                  "serial": _text(data.get("serial_number"))}
        passed = _dig(data, "smart_status", "passed")
        found = [self.sample("smart_passed", int(passed) if isinstance(passed, bool) else None, "", **labels)]
        nvme = _dig(data, "nvme_smart_health_information_log")
        ata = {a.get("id"): a for a in _as_list(_dig(data, "ata_smart_attributes", "table")) if isinstance(a, dict)}
        for metric, unit, value in (
                ("temp", "C", _dig(data, "temperature", "current")),
                ("power_on_hours", "h", _dig(data, "power_on_time", "hours")),
                ("reallocated_sectors", "", _dig(ata.get(5), "raw", "value")),
                ("wear_pct", "%", _dig(nvme, "percentage_used")),
                ("media_errors", "", _dig(nvme, "media_errors"))):
            number = _number(value)
            if number is not None:
                found.append(self.sample(metric, number, unit, **labels))
        return found
