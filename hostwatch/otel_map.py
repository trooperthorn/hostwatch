"""Map hostwatch collector samples and events to OpenTelemetry names, units and attributes.

The mapping follows section 3 of the Observe DATA-API-DESIGN document (resource attributes in
3.1, collector metrics in 3.2, thermal controller states in 3.3, events as logs in 3.9). It is
pure data conversion: it reads Sample, SourceStatus and Event objects and returns plain
dataclasses, and it never touches the network or the host. The OTLP encoder and the sender
consume these dataclasses.

Rules that hold for every metric:

* Units are UCUM. Utilization, load and charge values are ratios from 0 to 1, so a hostwatch
  percentage is divided by 100 here.
* A sample whose value is None is dropped, never turned into zero. The collector reported the
  source as present but unable to read it, and Observe learns that from the source status
  metrics, not from a made-up value.
* A (source, metric) pair that the table does not list maps to
  ``observe.legacy.<source>.<metric>`` with the unit converted where that is obvious, so adding
  a collector never loses data. The pair is logged once per process.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .schema import Event, Sample, SourceStatus

log = logging.getLogger("hostwatch.otel_map")

SCOPE_PREFIX = "hostwatch.collector."
EVENT_SCOPE = "hostwatch.agent"
LEGACY_PREFIX = "observe.legacy."
SERVICE_NAME = "hostwatch"

GAUGE = "gauge"
SUM = "sum"

Attr = str | int | float | bool


@dataclass(frozen=True)
class Point:
    """One OTEL data point: a gauge, or a monotonic cumulative sum."""

    scope: str
    name: str
    unit: str
    kind: str  # GAUGE or SUM
    value: float
    ts: float
    attributes: dict[str, Attr] = field(default_factory=dict)
    monotonic: bool = False


@dataclass(frozen=True)
class LogRecord:
    """One OTEL log record."""

    scope: str
    ts: float
    event_name: str
    severity_number: int
    severity_text: str
    body: str
    attributes: dict[str, Attr] = field(default_factory=dict)


@dataclass(frozen=True)
class MapContext:
    """Facts about the host that a sample does not carry."""

    ups_name: str = "ups"


def scope_name(source: str) -> str:
    return SCOPE_PREFIX + source


# -- resource attributes (3.1) -------------------------------------------------------------

def observe_platform(platform: str) -> str:
    """Agent platform ids are windows, rpi, truenas and an architecture name; Observe wants four."""
    return platform if platform in ("windows", "rpi", "truenas") else "linux"


def resource_attributes(host: str, platform: str, agent_version: str, *, machine_id: str = "",
                        arch: str = "", os_description: str = "", os_version: str = "",
                        instance_id: str = "") -> dict[str, str]:
    """Resource attributes for the agent. Empty optional values are left out, not sent blank."""
    attrs = {
        "host.name": host,
        "os.type": "windows" if platform == "windows" else "linux",
        "service.name": SERVICE_NAME,
        "service.version": agent_version,
        "observe.platform": observe_platform(platform),
    }
    for key, value in (("host.id", machine_id), ("host.arch", arch), ("os.description", os_description),
                       ("os.version", os_version), ("service.instance.id", instance_id)):
        if value:
            attrs[key] = value
    return attrs


# -- unit conversion for the fallback ------------------------------------------------------

# unit -> (UCUM unit, factor). Percent becomes a ratio, MHz becomes Hz.
LEGACY_UNITS: dict[str, tuple[str, float]] = {
    "%": ("1", 0.01), "MHz": ("Hz", 1e6), "C": ("Cel", 1.0), "B": ("By", 1.0), "W": ("W", 1.0),
    "V": ("V", 1.0), "s": ("s", 1.0), "h": ("h", 1.0), "RPM": ("{rpm}", 1.0), "count": ("{count}", 1.0),
    "": ("1", 1.0),
}

_warned: set[tuple[str, str]] = set()


def _warn_unmapped(source: str, metric: str) -> None:
    key = (source, metric)
    if key not in _warned:
        _warned.add(key)
        log.warning("no OTEL mapping for %s/%s; sending it as %s%s.%s", source, metric,
                    LEGACY_PREFIX, source, metric)


def reset_unmapped_warnings() -> None:
    """Forget which unmapped pairs were logged. Tests use this; the agent never does."""
    _warned.clear()


# -- helpers -------------------------------------------------------------------------------

def _logical_number(cpu: str) -> int | str:
    m = re.fullmatch(r"cpu(\d+)", cpu)
    return int(m.group(1)) if m else cpu


def _pt(s: Sample, name: str, unit: str, value: float, attrs: dict[str, Attr] | None = None,
        kind: str = GAUGE) -> Point:
    return Point(scope=scope_name(s.source), name=name, unit=unit, kind=kind, value=value, ts=s.ts,
                 attributes=attrs or {}, monotonic=(kind == SUM))


def _ratio(value: float) -> float:
    return round(value / 100.0, 10)


def _cpu_attrs(s: Sample) -> dict[str, Attr]:
    cpu = s.labels.get("cpu")
    return {"cpu.logical_number": _logical_number(cpu)} if cpu else {}


_ZFS_ERROR_TYPES = {"read_errors": "read", "write_errors": "write", "checksum_errors": "checksum"}


# -- the per-metric table ------------------------------------------------------------------
# Each handler takes (sample, context) and returns the points for that one sample, or None to
# send the sample through the legacy fallback. Samples that need a partner (memory and swap) are
# handled in _paired.

def _cpu_util(s, ctx):
    return [_pt(s, "system.cpu.utilization", "1", _ratio(s.value), _cpu_attrs(s))]


def _cpu_load(s, ctx):
    span = s.labels.get("span", "")
    if span not in ("1m", "5m", "15m"):
        return None
    return [_pt(s, f"system.cpu.load_average.{span}", "{thread}", s.value)]


def _cpu_freq(s, ctx):
    return [_pt(s, "system.cpu.frequency", "Hz", s.value * 1e6, _cpu_attrs(s))]


def _cpu_idle(s, ctx):
    attrs = _cpu_attrs(s)
    attrs["observe.cpu.idle_state"] = s.labels.get("state", "")
    return [_pt(s, "observe.cpu.idle_residency", "1", _ratio(s.value), attrs)]


def _mem_total(s, ctx):
    return [_pt(s, "system.memory.limit", "By", s.value)]


def _hwmon(name: str, unit: str, parented: bool):
    def handler(s, ctx):
        chip, sensor = s.labels.get("chip", ""), s.labels.get("sensor", "")
        attrs: dict[str, Attr] = {"hw.id": f"{chip}:{sensor}", "hw.name": sensor}
        if parented:
            attrs["hw.parent"] = chip
        return [_pt(s, name, unit, s.value, attrs)]
    return handler


def _rapl(s, ctx):
    attrs = {"hw.id": f"rapl:{s.labels.get('zone', '')}", "hw.type": "cpu",
             "observe.rapl.domain": s.labels.get("domain", "")}
    return [_pt(s, "hw.power", "W", s.value, attrs)]


def _rpi_temp(s, ctx):
    return [_pt(s, "hw.temperature", "Cel", s.value, {"hw.id": "soc", "hw.type": "cpu"})]


def _rpi_flag(s, ctx):
    return [_pt(s, "observe.rpi.throttled", "1", s.value, {"observe.rpi.flag": s.labels.get("flag", "")})]


def _rpi_raw(s, ctx):
    return [_pt(s, "observe.rpi.throttled_raw", "1", s.value)]


def _md_state(s, ctx):
    attrs = {"hw.id": f"md:{s.labels.get('array', '')}", "hw.type": "logical_disk",
             "hw.state": s.labels.get("state", "")}
    return [_pt(s, "hw.status", "1", s.value, attrs)]


def _md_action(s, ctx):
    attrs = {"hw.id": f"md:{s.labels.get('array', '')}", "observe.mdraid.action": s.labels.get("action", "")}
    return [_pt(s, "observe.mdraid.sync_action", "1", s.value, attrs)]


def _md_progress(s, ctx):
    return [_pt(s, "observe.mdraid.sync_progress", "1", _ratio(s.value),
                {"hw.id": f"md:{s.labels.get('array', '')}"})]


def _pool_id(s: Sample) -> str:
    return f"zpool:{s.labels.get('pool', '')}"


def _vdev_id(s: Sample) -> str:
    vdev = s.labels.get("vdev", "")
    return f"{_pool_id(s)}/{vdev}" if vdev else _pool_id(s)


def _zfs_state(s, ctx):
    attrs = {"hw.id": _pool_id(s), "hw.type": "logical_disk", "hw.state": s.labels.get("state", "")}
    return [_pt(s, "hw.status", "1", s.value, attrs)]


def _pool_health(s, ctx):
    return [_pt(s, "observe.zfs.pool.health", "1", s.value, {"hw.id": _pool_id(s)})]


def _pool_flag(state: str):
    def handler(s, ctx):
        return [_pt(s, "hw.status", "1", s.value, {"hw.id": _pool_id(s), "hw.state": state})]
    return handler


def _pool_scan_errors(s, ctx):
    return [_pt(s, "observe.zfs.pool.scan.errors", "{error}", s.value, {"hw.id": _pool_id(s)})]


def _scan_state(s, ctx):
    attrs = {"hw.id": _pool_id(s), "observe.zfs.scan_state": s.labels.get("scan_state", "")}
    return [_pt(s, "observe.zfs.pool.scan.state", "1", s.value, attrs)]


def _zfs_errors(error_type: str):
    def handler(s, ctx):
        return [_pt(s, "hw.errors", "{error}", s.value, {"hw.id": _vdev_id(s), "error.type": error_type},
                    kind=SUM)]
    return handler


def _self_healed(s, ctx):
    return [_pt(s, "observe.zfs.vdev.self_healed", "By", s.value, {"hw.id": _vdev_id(s)}, kind=SUM)]


def _truenas_disk_temp(s, ctx):
    attrs = {"hw.id": f"disk:{s.labels.get('disk', '')}", "hw.type": "physical_disk"}
    return [_pt(s, "hw.temperature", "Cel", s.value, attrs)]


def _scrutiny_up(s, ctx):
    attrs: dict[str, Attr] = {}
    if s.value == 0 and s.labels.get("error"):
        attrs["error.type"] = s.labels["error"]
    return [_pt(s, "observe.scrutiny.up", "1", s.value, attrs)]


def _scrutiny_status(s, ctx):
    attrs = {"hw.id": f"disk:{s.labels.get('wwn', '')}", "hw.type": "physical_disk",
             "observe.scrutiny.status": str(int(s.value))}
    return [_pt(s, "hw.status", "1", s.value, attrs)]


def _win_health(hw_type: str):
    def handler(s, ctx):
        attrs = {"hw.id": s.labels.get("id", ""), "hw.type": hw_type, "hw.state": s.labels.get("health", ""),
                 "observe.win.operational": s.labels.get("operational", "")}
        return [_pt(s, "hw.status", "1", s.value, attrs)]
    return handler


def _smart_ok(s, ctx):
    return [_pt(s, "hw.status", "1", s.value, {"hw.id": s.labels.get("id", ""), "hw.state": "smart_ok"})]


def _media_errors(s, ctx):
    attrs = {"hw.id": s.labels.get("id", ""), "error.type": "media"}
    return [_pt(s, "hw.errors", "{error}", s.value, attrs, kind=SUM)]


def _wear(s, ctx):
    return [_pt(s, "hw.physical_disk.endurance_utilization", "1", _ratio(s.value),
                {"hw.id": s.labels.get("id", "")})]


def _ups_id(ctx: MapContext) -> str:
    return f"ups:{ctx.ups_name}"


def _nut_charge(s, ctx):
    return [_pt(s, "hw.battery.charge", "1", _ratio(s.value), {"hw.id": _ups_id(ctx)})]


def _nut_runtime(s, ctx):
    return [_pt(s, "hw.battery.time_left", "s", s.value, {"hw.id": _ups_id(ctx)})]


def _nut_voltage(s, ctx):
    return [_pt(s, "hw.voltage", "V", s.value, {"hw.id": _ups_id(ctx), "hw.type": "power_supply"})]


def _nut_load(s, ctx):
    return [_pt(s, "observe.ups.load", "1", _ratio(s.value), {"hw.id": _ups_id(ctx)})]


def _nut_flag(s, ctx):
    return [_pt(s, "observe.ups.status", "1", s.value,
                {"hw.id": _ups_id(ctx), "observe.ups.flag": s.labels.get("flag", "")})]


def _zone_temp(s, ctx):
    zone = s.labels.get("zone", "")
    return [_pt(s, "hw.temperature", "Cel", s.value, {"hw.id": f"zone:{zone}", "observe.thermal.zone": zone})]


def _zone_ratio(name: str):
    def handler(s, ctx):
        return [_pt(s, name, "1", _ratio(s.value), {"observe.thermal.zone": s.labels.get("zone", "")})]
    return handler


def _fan_id(s: Sample) -> str:
    return f"fan:{s.labels.get('sensor', '')}"


def _fan_duty(s, ctx):
    return [_pt(s, "observe.thermal.fan.duty", "1", _ratio(s.value), {"hw.id": _fan_id(s)})]


def _fan_rpm(s, ctx):
    return [_pt(s, "hw.fan.speed", "{rpm}", s.value, {"hw.id": _fan_id(s), "observe.thermal.controlled": True})]


def _fan_target(s, ctx):
    return [_pt(s, "observe.thermal.fan.target_duty", "1", _ratio(s.value), {"hw.id": _fan_id(s)})]


def _failsafe(s, ctx):
    return [_pt(s, "observe.thermal.failsafe", "{reason}", s.value)]


HANDLERS: dict[tuple[str, str], Any] = {
    ("cpu", "utilization_pct"): _cpu_util,
    ("cpu", "load"): _cpu_load,
    ("cpu", "freq_mhz"): _cpu_freq,
    ("cpu", "idle_residency_pct"): _cpu_idle,
    ("memory", "mem_total"): _mem_total,
    ("hwmon", "temp"): _hwmon("hw.temperature", "Cel", True),
    ("hwmon", "fan"): _hwmon("hw.fan.speed", "{rpm}", True),
    ("hwmon", "voltage"): _hwmon("hw.voltage", "V", False),
    ("hwmon", "power"): _hwmon("hw.power", "W", False),
    ("rapl", "watts"): _rapl,
    ("rpi", "soc_temp"): _rpi_temp,
    ("rpi", "throttle_flag"): _rpi_flag,
    ("rpi", "throttled_raw"): _rpi_raw,
    ("mdraid", "array_state"): _md_state,
    ("mdraid", "sync_action"): _md_action,
    ("mdraid", "sync_progress_pct"): _md_progress,
    ("zfs", "pool_state"): _zfs_state,
    ("truenas", "pool_state"): _zfs_state,
    ("truenas", "pool_health"): _pool_health,
    ("truenas", "pool_healthy"): _pool_flag("healthy"),
    ("truenas", "pool_warning"): _pool_flag("warning"),
    ("truenas", "pool_scan_errors"): _pool_scan_errors,
    ("truenas", "scan_state"): _scan_state,
    ("truenas", "vdev_self_healed_bytes"): _self_healed,
    ("truenas", "disk_temp_c"): _truenas_disk_temp,
    ("scrutiny", "api_up"): _scrutiny_up,
    ("scrutiny", "device_status"): _scrutiny_status,
    ("win_storage", "disk_health"): _win_health("physical_disk"),
    ("win_storage", "pool_health"): _win_health("logical_disk"),
    ("win_storage", "virtual_disk_health"): _win_health("logical_disk"),
    ("nut", "battery_charge_pct"): _nut_charge,
    ("nut", "battery_runtime_s"): _nut_runtime,
    ("nut", "input_voltage_v"): _nut_voltage,
    ("nut", "ups_load_pct"): _nut_load,
    ("nut", "ups_status_flag"): _nut_flag,
    ("win_cpu", "utilization_pct"): _cpu_util,
    ("win_thermalsuite", "zone_duty"): _zone_ratio("observe.thermal.zone.duty"),
    ("win_thermalsuite", "fan_target"): _fan_target,
    ("win_thermalsuite", "failsafe"): _failsafe,
}
# The design table names the SMART metrics under win_storage; the collector that reads them is
# registered as win_smartctl. Both source ids map the same way.
for _src in ("win_storage", "win_smartctl"):
    HANDLERS[(_src, "smart_passed")] = _smart_ok
    HANDLERS[(_src, "media_errors")] = _media_errors
    HANDLERS[(_src, "wear_pct")] = _wear
for _src in ("thermalctl", "win_thermalsuite"):
    HANDLERS[(_src, "zone_temp")] = _zone_temp
    HANDLERS[(_src, "zone_load")] = _zone_ratio("observe.thermal.zone.load")
    HANDLERS[(_src, "fan_duty")] = _fan_duty
    HANDLERS[(_src, "fan")] = _fan_rpm
for _name, _etype in _ZFS_ERROR_TYPES.items():
    HANDLERS[("truenas", _name)] = _zfs_errors(_etype)
    HANDLERS[("truenas", f"vdev_{_name}")] = _zfs_errors(_etype)

_PAIRED = {("memory", "mem_total"), ("memory", "mem_available"), ("memory", "swap_total"),
           ("memory", "swap_free")}


def _legacy(s: Sample) -> Point:
    _warn_unmapped(s.source, s.metric)
    unit, factor = LEGACY_UNITS.get(s.unit, (s.unit or "1", 1.0))
    return _pt(s, f"{LEGACY_PREFIX}{s.source}.{s.metric}", unit, s.value * factor, dict(s.labels))


def map_sample(s: Sample, ctx: MapContext | None = None) -> list[Point]:
    """Map one sample. Memory available and swap readings need a partner and map in map_samples."""
    if s.value is None:
        return []
    handler = HANDLERS.get((s.source, s.metric))
    if handler is None:
        return [] if (s.source, s.metric) in _PAIRED else [_legacy(s)]
    points = handler(s, ctx or MapContext())
    return [_legacy(s)] if points is None else points


def _paired(samples: list[Sample]) -> list[Point]:
    """Memory and swap: usage is split into used and free, which needs both readings."""
    have = {(s.source, s.metric): s for s in samples if s.value is not None}
    out: list[Point] = []
    total, avail = have.get(("memory", "mem_total")), have.get(("memory", "mem_available"))
    if avail is not None:
        if total is not None:
            out.append(_pt(avail, "system.memory.usage", "By", total.value - avail.value,
                           {"system.memory.state": "used"}))
        out.append(_pt(avail, "system.memory.usage", "By", avail.value, {"system.memory.state": "free"}))
    swap_total, swap_free = have.get(("memory", "swap_total")), have.get(("memory", "swap_free"))
    if swap_free is not None:
        if swap_total is not None:
            out.append(_pt(swap_free, "system.paging.usage", "By", swap_total.value - swap_free.value,
                           {"system.paging.state": "used"}))
        out.append(_pt(swap_free, "system.paging.usage", "By", swap_free.value, {"system.paging.state": "free"}))
    return out


def _modes(samples: list[Sample]) -> list[Point]:
    """3.3: one observe.thermal.mode point per source and mode, value 1 for the current mode."""
    out, seen = [], set()
    for s in samples:
        mode = s.labels.get("mode", "")
        if s.source in ("thermalctl", "win_thermalsuite") and mode and (s.source, mode) not in seen:
            seen.add((s.source, mode))
            out.append(_pt(s, "observe.thermal.mode", "1", 1.0, {"observe.thermal.mode": mode}))
    return out


def map_samples(samples: Iterable[Sample], ctx: MapContext | None = None) -> list[Point]:
    samples = list(samples)
    out: list[Point] = []
    for s in samples:
        out.extend(map_sample(s, ctx))
    out.extend(_paired(samples))
    out.extend(_modes(samples))
    return out


# -- source status and heartbeat -----------------------------------------------------------

def map_source_status(statuses: Iterable[SourceStatus], ts: float) -> list[Point]:
    out = []
    for st in statuses:
        scope = scope_name(st.source)
        attrs: dict[str, Attr] = {"observe.source": st.source}
        out.append(Point(scope, "observe.source.available", "1", GAUGE, 1.0 if st.available else 0.0, ts,
                         dict(attrs)))
        out.append(Point(scope, "observe.source.present", "1", GAUGE, 1.0 if st.present else 0.0, ts,
                         dict(attrs)))
    return out


def heartbeat_point(sent_at: float) -> Point:
    return Point(EVENT_SCOPE, "observe.agent.heartbeat", "s", GAUGE, float(sent_at), sent_at, {})


# -- logs (3.9 and 3.3) --------------------------------------------------------------------

SEVERITY = {"info": (9, "INFO"), "warning": (13, "WARN"), "critical": (17, "ERROR")}
MAX_DETAIL_KEYS = 20
MAX_DETAIL_VALUE = 512
_KEY_BAD = re.compile(r"[^A-Za-z0-9_.-]")


def flatten_detail(detail: dict[str, Any]) -> dict[str, Attr]:
    """Flatten an event detail under observe.detail.*, capped in key count and value length."""
    out: dict[str, Attr] = {}
    for key in sorted(detail)[:MAX_DETAIL_KEYS]:
        value = detail[key]
        if isinstance(value, (bool, int, float)):
            attr: Attr = value
        elif isinstance(value, str):
            attr = value[:MAX_DETAIL_VALUE]
        else:
            attr = json.dumps(value, sort_keys=True, default=str)[:MAX_DETAIL_VALUE]
        out["observe.detail." + _KEY_BAD.sub("_", str(key))] = attr
    return out


def map_event(e: Event) -> LogRecord:
    """An agent event as an OTEL log. Boot classifications use observe.host.boot (section 3.9)."""
    number, text = SEVERITY.get(e.severity, SEVERITY["warning"])
    attrs: dict[str, Attr] = {"observe.source": e.source, "observe.dedup_key": e.dedup_key,
                              "observe.severity": e.severity}
    if e.boot_id:
        attrs["observe.boot_id"] = e.boot_id
    attrs.update(flatten_detail(e.detail))
    if e.source == "boot" and e.kind.startswith("boot."):
        # Section 3.9 gives boot classifications severity 9 or 13; the original severity stays an
        # attribute so a critical boot (power loss, panic) is still distinguishable.
        number, text = (9, "INFO") if e.severity == "info" else (13, "WARN")
        attrs["observe.event.kind"] = e.kind
        attrs["observe.host.clean_shutdown"] = e.kind == "boot.clean_shutdown"
        return LogRecord(EVENT_SCOPE, e.ts, "observe.host.boot", number, text, e.title, attrs)
    return LogRecord(scope_name(e.source), e.ts, f"hostwatch.{e.kind}", number, text, e.title, attrs)


def map_source_change(source: str, available: bool, reason: str, ts: float) -> LogRecord:
    body = f"{source} available" if available else f"{source} unavailable" + (f": {reason}" if reason else "")
    attrs: dict[str, Attr] = {"observe.source": source}
    if reason:
        attrs["observe.source.reason"] = reason
    return LogRecord(EVENT_SCOPE, ts, "observe.source.change", 13, "WARN", body, attrs)


def failsafe_logs(samples: Iterable[Sample]) -> list[LogRecord]:
    """3.3: one WARN log per failsafe reason on a failsafe sample. The sender decides when to send
    it, so a steady failsafe is not logged every cycle."""
    out = []
    for s in samples:
        if s.metric != "failsafe" or s.source != "win_thermalsuite":
            continue
        for reason in [r for r in s.labels.get("reasons", "").split(",") if r]:
            out.append(LogRecord(scope_name(s.source), s.ts, "observe.thermal.failsafe", 13, "WARN",
                                 f"thermal failsafe: {reason}", {"observe.thermal.reason": reason}))
    return out
