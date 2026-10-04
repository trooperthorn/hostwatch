"""Shared per-host health summary for the integration outputs.

Home Assistant, the Orion API Poller endpoints and Prometheus all need the same
view of a host. This module derives it once from what the store already holds
(`Store.latest`, `Store.sources`, `Store.events`) so the outputs cannot disagree.

Rules that follow the project contract:
  * A value that cannot be known is None and carries a reason. It is never
    reported as zero. Unknown is not a status: `status_for` returns None for it.
  * A sample older than `STALE_AFTER_S` is stale and treated as unavailable.
  * A source the hub reports unavailable, or has not heard from for
    `STALE_AFTER_S`, makes every value that depends on it unavailable.
  * A source the agent reports as not present (positively established absence, such as no md
    arrays on a ZFS host) makes its group "not present": no warning, no values, no entities.
    Unreadable is not absent; that stays unmeasured.
  * A source that reports not present after the hub has seen it present and available is
    "disappeared": critical, with the time it was last seen. Only `source forget` makes that
    absence deliberate again.
  * A host whose agent has not reported for longer than the silence window (default three agent
    intervals, HOSTWATCH_SILENT_AFTER_S) is critical, with the time of its last report as the reason.
  * A boot event classified kernel_panic, watchdog_reset or unknown_unclean, or a pstore panic or
    oops record, is an open crash condition and keeps the host critical until an operator runs
    `event ack ID` or the hold window (HOSTWATCH_CRASH_HOLD_S, default 24 hours) passes.
    clean_shutdown and agent_stopped are never critical.
  * Status codes are 0 ok, 1 warning, 2 critical, from `status_for` only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from ..config import sensor_matches

STALE_AFTER_S = 180.0
EVENT_WINDOW_S = 86400.0
SILENT_AFTER_S = 45.0
CRASH_HOLD_S = 86400.0
# Event kinds that mean the host went down badly. clean_shutdown and agent_stopped are not here.
CRASH_KINDS = frozenset({"boot.kernel_panic", "boot.watchdog_reset", "boot.unknown_unclean",
                         "boot.power_loss",
                         "pstore.kernel_panic", "pstore.kernel_oops"})

STATUS_OK, STATUS_WARNING, STATUS_CRITICAL = 0, 1, 2

# ZFS pool states (zpool-status(8)) that mean the pool has lost redundancy or cannot serve I/O.
POOL_CRITICAL_STATES = frozenset({"DEGRADED", "FAULTED", "UNAVAIL", "SUSPENDED"})

# Expected component group -> the source that feeds it. A group whose source is unavailable,
# stale or has never reported is unmeasured. Pools are optional: they are expected only once the zfs source has a row.
EXPECTED_GROUPS = {"cpu": "cpu", "memory": "memory", "power": "rapl", "temperatures": "hwmon",
                   "raid": "mdraid", "pools": "zfs", "disks": "scrutiny", "ups": "nut", "pi": "rpi"}
# Groups that are expected only when their source has a row at all. The nut source reports
# not present when NUT is unconfigured, so a host with no nut row is treated as not using NUT.
# A host that never reported zfs is likewise not expected to have pools.
OPTIONAL_GROUPS = frozenset({"ups", "pools", "pi"})

# (warning, critical) thresholds, in the unit of the value. These are defaults
# chosen for desktop and server parts, not measured limits; see UNVERIFIED.md.
CPU_TEMP_C = (80.0, 90.0)
# hwmon chips known to report a CPU temperature. The CPU limits apply only to these and to the
# chip:sensor patterns the operator lists. Any other hwmon temperature, such as an unused Super I/O
# input that floats at 100 C, is informational so it cannot raise an alarm.
CPU_TEMP_CHIPS = frozenset({"coretemp", "k10temp", "zenpower", "cpu_thermal"})
INFORMATIONAL_NOTE = "informational: no threshold applies to this sensor"
FAN_INFORMATIONAL_NOTE = ("informational: reads 0 RPM and is not listed in HOSTWATCH_HWMON_REQUIRED_FANS, "
                          "so an unused header cannot raise an alarm")
DISK_TEMP_C = (50.0, 60.0)
MEMORY_USED_PCT = (90.0, 97.0)


@dataclass
class Component:
    """One thing that has a state. `value` is None when unavailable, with `reason`.

    `state` is one of "ok", "warning", "critical" or "unknown".
    """

    name: str
    value: float | None = None
    unit: str = ""
    state: str = "unknown"
    reason: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    source: str = ""
    ts: float | None = None

    @property
    def available(self) -> bool:
        return self.value is not None

    @property
    def status(self) -> int | None:
        return status_for(self)


def status_for(component: Component) -> int | None:
    """Map a component state to the numeric status used by every integration.

    ok -> 0, warning -> 1, critical -> 2. A component whose state is unknown
    (its source is missing, stale or unreadable) returns None, because a number
    there would claim health nobody measured. Outputs publish None as
    unavailable (Home Assistant) or omit the value and status (Orion).
    """
    return {"ok": STATUS_OK, "warning": STATUS_WARNING, "critical": STATUS_CRITICAL}.get(component.state)


_POOL_RANK = {"critical": 4, "warning": 3, "unknown": 2, "ok": 1, "not_present": 0}


def _merge_pool(pool: str, parts: list[tuple[str, Component]]) -> Component:
    """Merge the zfs and truenas components of one pool into one, worst state first.

    An unmeasured part outranks ok, so an unreadable source never lets the other source
    claim a health nobody measured. The merged labels carry `source` (the contributing
    sources joined with a plus sign) and each source's own detail, prefixed by the source name.
    """
    if len(parts) == 1:
        src, c = parts[0]
        c.name = f"pool.{pool}"
        c.labels["source"] = src
        return c
    worst = max((c for _, c in parts), key=lambda c: _POOL_RANK.get(c.state, 2))
    labels = {"pool": pool, "source": "+".join(src for src, _ in parts)}
    reasons = []
    for src, c in parts:
        for k, v in c.labels.items():
            if k != "pool":
                labels[f"{src}_{k}"] = v
        if c.reason:
            reasons.append(f"{src}: {c.reason}")
    stamps = [c.ts for _, c in parts if c.ts is not None]
    return Component(f"pool.{pool}", worst.value, worst.unit, worst.state, "; ".join(reasons), labels,
                     labels["source"], max(stamps) if stamps else None)


def _level(value: float, limits: tuple[float, float]) -> str:
    return "critical" if value >= limits[1] else "warning" if value >= limits[0] else "ok"


@dataclass
class HostSummary:
    host: str
    now: float
    cpu: Component
    memory: Component
    package_power: Component
    temperatures: list[Component]
    md_arrays: list[Component]
    disks: list[Component]
    sources: dict[str, Component]
    problems: dict[str, bool | None]
    open_conditions: list[str]
    last_seen: float | None
    unmeasured: list[str] = field(default_factory=list)
    not_present: list[str] = field(default_factory=list)
    disappeared: list[str] = field(default_factory=list)
    silent: str = ""
    crashes: list[dict] = field(default_factory=list)
    ups: Component | None = None
    wall_power: Component | None = None
    pools: list[Component] = field(default_factory=list)
    pi: Component | None = None
    fans: list[Component] = field(default_factory=list)
    alert_items: list[Component] = field(default_factory=list)

    def components(self) -> list[Component]:
        extra = [c for c in (self.ups, self.wall_power, self.pi) if c is not None]
        return [self.cpu, self.memory, self.package_power, *self.temperatures, *self.fans, *self.md_arrays,
                *self.pools, *self.disks, *extra, *self.sources.values()]

    @property
    def status(self) -> int | None:
        """Worst known status over all components, None if nothing is known."""
        known = [c.status for c in self.components() if c.status is not None]
        return max(known) if known else None

    @property
    def overall_status(self) -> int:
        """Status published as the host's overall state, never better than what was measured.

        2 with the reason "no data" when nothing is known. Otherwise the worst known status,
        raised to at least 1 (warning) while any expected group is unmeasured, because a group
        nobody measured must not read as healthy.
        """
        worst = self.status
        if self.silent or self.crashes or worst is None:
            return STATUS_CRITICAL
        base = max(worst, STATUS_WARNING) if self.unmeasured else worst
        return max(base, self._group_status()[0])

    def _group_status(self, strict: bool = False) -> tuple[int, str]:
        """The worst status over every group, visible or hidden, with the reason. Warning and
        critical groups count as themselves; a partly unmeasured (unknown) group counts as a warning,
        because a group nobody fully measured must not read as healthy. `strict` leaves unknown groups out."""
        level, reasons = STATUS_OK, []
        for g in group_documents(self):
            lvl = {"critical": STATUS_CRITICAL, "warning": STATUS_WARNING,
                   "unknown": None if strict else STATUS_WARNING}.get(g["status"])
            if lvl:
                level = max(level, lvl)
                reasons.append((lvl, f"{g['label']}: {g['summary']}"))
        reasons.sort(key=lambda r: -r[0])
        return level, "; ".join(text for _, text in reasons)

    @property
    def overall_reason(self) -> str:
        if self.silent:
            return self.silent
        if self.crashes:
            return "; ".join(f"unacknowledged crash event {c['id']}: {c['kind']} at {_iso(c['ts'])}"
                             for c in self.crashes)
        if self.status is None:
            return "no data"
        if self.disappeared:
            return "sources disappeared: " + ", ".join(self.disappeared)
        if self.unmeasured:
            text = "unmeasured groups: " + ", ".join(self.unmeasured)
            bad = self._group_status(strict=True)[1]
            return f"{text}; {bad}" if bad else text
        known = [c.status for c in self.components() if c.status is not None]
        group_level, group_reason = self._group_status()
        if group_level > max(known, default=STATUS_OK):
            return group_reason
        return ""


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class StoreLike(Protocol):
    def latest(self, host: str | None = None) -> list[dict]: ...
    def sources(self) -> list[dict]: ...
    def events(self, host: str | None = None, since: float | None = None, kind: str | None = None,
               limit: int = 100, source: str | None = None, **kw: Any) -> list[dict]: ...


def _label(labels: dict[str, str]) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


def _alert_items(store: StoreLike, host: str, now: float, window_s: float,
                 open_crash_ids: set[int]) -> list[Component]:
    """TrueNAS alerts, the last boot classification and recent warning or critical events as members
    of the alerts group. Boot and pstore events are left out of the recent events: open crashes have
    their own members, acknowledged ones are excluded, and the last boot has its classification member."""
    out: list[Component] = []
    newest: dict[str, dict] = {}
    for e in store.events(host=host, kind="truenas.alert", limit=1000):
        if e.get("kind") != "truenas.alert":
            continue
        key = str((e.get("detail") or {}).get("uuid") or e["id"])
        if key not in newest or (e["ts"], e["id"]) > (newest[key]["ts"], newest[key]["id"]):
            newest[key] = e
    for e in sorted(newest.values(), key=lambda e: (e["ts"], e["id"]), reverse=True):
        detail = e.get("detail") or {}
        text = detail.get("formatted") or e.get("title") or "TrueNAS alert"
        labels = {"event": str(e["id"])}
        name = f"truenas_alert.{e['id']}"
        if detail.get("dismissed"):
            out.append(Component(name, None, "", "ok", f"informational: dismissed TrueNAS alert: {text}",
                                 labels, "truenas", e["ts"]))
        elif e.get("severity") in ("warning", "critical"):
            out.append(Component(name, None, "", e["severity"], f"TrueNAS alert: {text}",
                                 labels, "truenas", e["ts"]))
        else:
            out.append(Component(name, None, "", "ok", f"informational: TrueNAS alert: {text}",
                                 labels, "truenas", e["ts"]))
    boots = [e for e in store.events(host=host, source="boot", limit=1) if e.get("source") == "boot"]
    if boots and boots[0]["id"] not in open_crash_ids:
        b = boots[0]
        out.append(Component("boot.last", None, "", "ok",
                             f"informational: last boot classified {b['kind'].split('.', 1)[-1]} at {_iso(b['ts'])}",
                             {"event": str(b["id"])}, "boot", b["ts"]))
    for e in store.events(host=host, since=now - window_s, limit=1000):
        if (e.get("severity") not in ("warning", "critical") or e.get("source") in ("thresholds", "boot", "pstore")
                or e.get("kind") == "truenas.alert" or e.get("kind") in CRASH_KINDS):
            continue
        out.append(Component(f"event.{e['id']}", None, "", e["severity"],
                             f"{e['kind']} at {_iso(e['ts'])}: {e.get('title') or ''}".rstrip(": "),
                             {"event": str(e["id"])}, e.get("source") or "events", e["ts"]))
    return out


def build_host_summary(store: StoreLike, host: str, now: float, silent_after_s: float = SILENT_AFTER_S,
                       crash_hold_s: float = CRASH_HOLD_S, cpu_sensors: tuple[str, ...] = (),
                       required_fans: tuple[str, ...] = (), alert_window_s: float = EVENT_WINDOW_S) -> HostSummary:
    rows = [r for r in store.latest(host) if r["host"] == host]
    src_rows = {r["source"]: r for r in store.sources() if r["host"] == host}
    events = store.events(host=host, since=now - EVENT_WINDOW_S, source="thresholds", limit=1000)

    # Source availability: the reported flag plus the age of the last report.
    blocked: dict[str, str] = {}
    sources: dict[str, Component] = {}
    absent: set[str] = set()
    gone: dict[str, str] = {}
    seen_fn = getattr(store, "source_seen", None)
    seen = {r["source"]: r for r in seen_fn(host)} if seen_fn else {}
    for name, r in sorted(src_rows.items()):
        age = now - r["updated"]
        was = seen.get(name)
        if (not r.get("present", 1) and not r["available"] and age <= STALE_AFTER_S
                and was is not None and was["forgotten_at"] is None):
            when = datetime.fromtimestamp(was["last_seen"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            gone[name] = f"source {name} disappeared: last seen present and available at {when}"
            sources[name] = Component(f"source.{name}", None, "", "critical", gone[name])
        elif not r.get("present", 1) and not r["available"] and age <= STALE_AFTER_S:
            absent.add(name)
            sources[name] = Component(f"source.{name}", None, "", "not_present",
                                      f"source {name} is not present on this host")
        elif not r["available"]:
            blocked[name] = f"source {name} unavailable: {r['reason'] or 'no reason given'}"
            sources[name] = Component(f"source.{name}", None, "", "warning", blocked[name])
        elif age > STALE_AFTER_S:
            blocked[name] = f"source {name} stale: last report {age:.0f}s ago"
            sources[name] = Component(f"source.{name}", None, "", "warning", blocked[name])
        else:
            sources[name] = Component(f"source.{name}", 1.0, "", "ok")

    def pick(source: str, metric: str, **match: str) -> list[dict]:
        return [r for r in rows if r["source"] == source and r["metric"] == metric
                and all(r["labels"].get(k) == v for k, v in match.items())]

    def comp(name: str, source: str, metric_rows: list[dict], unit: str, limits=None,
             labels: dict[str, str] | None = None) -> Component:
        """Build a component from the newest of `metric_rows`, or explain why not."""
        labels = labels or {}
        c = _comp(name, source, metric_rows, unit, limits, labels)
        c.source = source
        return c

    def _comp(name: str, source: str, metric_rows: list[dict], unit: str, limits,
              labels: dict[str, str]) -> Component:
        if source in gone:
            return Component(name, None, unit, "critical", gone[source], labels)
        if source in absent:
            return Component(name, None, unit, "not_present", f"source {source} is not present on this host", labels)
        if source in blocked:
            return Component(name, None, unit, "unknown", blocked[source], labels)
        if source not in src_rows:
            return Component(name, None, unit, "unknown", f"source {source} has not reported", labels)
        if not metric_rows:
            return Component(name, None, unit, "unknown", f"no {name} sample from {source}", labels)
        r = max(metric_rows, key=lambda x: x["ts"])
        if r["value"] is None:
            return Component(name, None, unit, "unknown", f"{source} could not read {name}", labels)
        if now - r["ts"] > STALE_AFTER_S:
            return Component(name, None, unit, "unknown",
                             f"{name} sample is stale: {now - r['ts']:.0f}s old", labels)
        state = _level(r["value"], limits) if limits else "ok"
        return Component(name, float(r["value"]), unit, state, "", labels, source, r["ts"])

    cpu = comp("cpu_utilization", "cpu", pick("cpu", "utilization_pct"), "%")

    total = comp("memory_used", "memory", pick("memory", "mem_total"), "B")
    avail = comp("memory_used", "memory", pick("memory", "mem_available"), "B")
    if "memory" in gone:
        memory = Component("memory_used", None, "%", "critical", gone["memory"])
    elif total.value is None or avail.value is None:
        why = total.reason if total.value is None else avail.reason
        memory = Component("memory_used", None, "%", "unknown", why)
    elif total.value <= 0:
        memory = Component("memory_used", None, "%", "unknown", "mem_total is not positive")
    else:
        used = 100.0 * (total.value - avail.value) / total.value
        memory = Component("memory_used", round(used, 2), "%", _level(used, MEMORY_USED_PCT))

    packages = [r for r in pick("rapl", "watts") if str(r["labels"].get("domain", "")).startswith("package")]
    power = comp("package_power", "rapl", packages, "W")

    # Wall power is a hub-side reading of the host's power entity (source "wall"), not an agent
    # source. A host with no such sample has no wall power component. An unavailable reading
    # (stored as a NULL value with its reason in the labels) stays unavailable, never zero.
    wall: Component | None = None
    wall_rows = pick("wall", "wall_watts")
    if wall_rows:
        newest = max(wall_rows, key=lambda x: x["ts"])
        if newest["value"] is None:
            wall = Component("wall_power", None, "W", "unknown",
                             newest["labels"].get("reason") or "the power entity could not be read")
        elif now - newest["ts"] > STALE_AFTER_S:
            wall = Component("wall_power", None, "W", "unknown",
                             f"wall_power sample is stale: {now - newest['ts']:.0f}s old")
        else:
            wall = Component("wall_power", float(newest["value"]), "W", "ok")

    temps: list[Component] = []
    for r in pick("hwmon", "temp"):
        lab = {"chip": r["labels"].get("chip", ""), "sensor": r["labels"].get("sensor", "")}
        is_cpu = lab["chip"] in CPU_TEMP_CHIPS or sensor_matches(cpu_sensors, lab["chip"], lab["sensor"])
        c = comp(f"temp.{_label(lab)}", "hwmon", [r], "C", CPU_TEMP_C if is_cpu else None, lab)
        if not is_cpu and c.value is not None:
            c.reason = INFORMATIONAL_NOTE
        temps.append(c)
    if not temps and "hwmon" not in absent:
        temps.append(comp("temp", "hwmon", [], "C", CPU_TEMP_C))

    # Fans from hwmon. A 0 RPM reading is informational (an unused header reads 0) unless the
    # operator lists the fan in HOSTWATCH_HWMON_REQUIRED_FANS, where a stopped fan is critical.
    fans: list[Component] = []
    for r in pick("hwmon", "fan"):
        lab = {"chip": r["labels"].get("chip", ""), "sensor": r["labels"].get("sensor", "")}
        c = comp(f"fan.{_label(lab)}", "hwmon", [r], "RPM", None, lab)
        if c.value is not None and c.value <= 0:
            if sensor_matches(required_fans, lab["chip"], lab["sensor"]):
                c.state, c.reason = "critical", "required fan reads 0 RPM"
            else:
                c.reason = FAN_INFORMATIONAL_NOTE
        fans.append(c)
    # Fan controller headers from thermalctl. The state label comes from the controller: a header
    # in failsafe is a warning that carries the controller's reasons, because the fan is then being
    # driven at full speed by design and is not itself broken.
    for r in pick("thermalctl", "fan"):
        lab = {"chip": r["labels"].get("chip", "thermalctl"), "sensor": r["labels"].get("sensor", "")}
        c = comp(f"fan.{_label(lab)}", "thermalctl", [r], "RPM", None, lab)
        if c.value is not None and r["labels"].get("state") == "failsafe":
            c.state = "warning"
            c.reason = "fan controller failsafe: " + (r["labels"].get("reasons") or "no reason given")
        fans.append(c)

    md: list[Component] = []
    for arr in sorted({r["labels"].get("array", "") for r in rows if r["source"] == "mdraid"}):
        c = comp(f"md.{arr}", "mdraid", pick("mdraid", "degraded", array=arr), "count", labels={"array": arr})
        if c.value is not None:
            for metric, key, out_key in (("degraded", "level", "level"), ("array_state", "state", "array_state"),
                                         ("sync_action", "action", "sync_action")):
                found = pick("mdraid", metric, array=arr)
                if found:
                    c.labels[out_key] = str(max(found, key=lambda x: x["ts"])["labels"].get(key, ""))
            syncing = any(r["labels"].get("action") not in (None, "idle") and r["value"] is not None
                          and now - r["ts"] <= STALE_AFTER_S for r in pick("mdraid", "sync_action", array=arr))
            c.state = "critical" if c.value > 0 else "warning" if syncing else "ok"
        md.append(c)
    if "mdraid" in gone and not md:
        md.append(comp("md", "mdraid", [], "count", labels={"array": "unknown"}))

    # ZFS pool health from the kstat state text. Unknown text stays unknown, never ok.
    pools: list[Component] = []
    by_pool: dict[str, list[tuple[str, Component]]] = {}
    for pool in sorted({r["labels"].get("pool", "") for r in rows if r["source"] == "zfs"}):
        c = comp(f"pool.{pool}", "zfs", pick("zfs", "pool_state", pool=pool), "", labels={"pool": pool})
        if c.value is not None:
            text = next((r["labels"].get("state", "") for r in pick("zfs", "pool_state", pool=pool)
                         if r["ts"] == max(x["ts"] for x in pick("zfs", "pool_state", pool=pool))), "")
            c.labels["state"] = text
            if text == "ONLINE":
                c.value, c.state = 0.0, "ok"
            elif text in POOL_CRITICAL_STATES:
                c.value, c.state, c.reason = 2.0, "critical", f"pool {pool} is {text}"
            else:
                c.value, c.state, c.reason = None, "unknown", f"pool {pool} has unrecognised state {text!r}"
        by_pool.setdefault(pool, []).append(("zfs", c))
    if "zfs" in gone and not pools:
        pools.append(comp("pool", "zfs", [], ""))

    # TrueNAS API pool health (0 ok, 1 warning, 2 critical), computed by the truenas collector from
    # the pool flags and per-device error counts. A corrected checksum error is a warning here
    # even though the kstat state still reads ONLINE. Not configured (not present) adds nothing.
    if "truenas" in src_rows and "truenas" not in absent:
        names = sorted({r["labels"].get("pool", "") for r in rows if r["source"] == "truenas"
                        and r["metric"] == "pool_health"})
        for pool in names:
            c = comp(f"truenas_pool.{pool}", "truenas", pick("truenas", "pool_health", pool=pool), "",
                     labels={"pool": pool})
            if c.value is not None:
                newest = max(pick("truenas", "pool_health", pool=pool), key=lambda x: x["ts"])
                c.state = {0: "ok", 1: "warning", 2: "critical"}.get(int(c.value), "unknown")
                c.reason = newest["labels"].get("reason", "")
                c.labels["status"] = newest["labels"].get("status", "")
                if c.state == "unknown":
                    c.value, c.reason = None, f"pool {pool} has unrecognised health value {newest['value']!r}"
            by_pool.setdefault(pool, []).append(("truenas", c))
        if not names:
            pools.append(comp("truenas_pools", "truenas", [], ""))
    # One component per pool. When the kstat row and the API row both describe a pool, the worse
    # of the two wins, so an ONLINE kstat row can never hide the API warning. Both sources keep
    # their detail in the labels and the reason.
    pools = [_merge_pool(pool, parts) for pool, parts in sorted(by_pool.items())] + pools

    # Raspberry Pi throttling: under-voltage now is critical, capped or throttled now is a warning,
    # and a has-occurred bit stays a warning until a reboot clears it. SoC temperature joins the
    # temperature list. A host with no rpi row, or one where it is not present, adds nothing.
    pi: Component | None = None
    if "rpi" in src_rows and "rpi" not in absent:
        flags = {r["labels"].get("flag"): r for r in pick("rpi", "throttle_flag")}
        pi = comp("pi_throttling", "rpi", list(flags.values()), "")
        if pi.value is not None:
            if any(r["value"] is None for r in flags.values()):
                pi = Component("pi_throttling", None, "", "unknown", "rpi could not decode the throttled bitmask")
            else:
                on = {k for k, r in flags.items() if r["value"]}
                pi.labels["flags"] = ",".join(sorted(on))
                if "under_voltage_now" in on:
                    pi.value, pi.state, pi.reason = 2.0, "critical", "Raspberry Pi is under-voltage now"
                elif on & {"freq_capped_now", "throttled_now", "soft_temp_limit_now"}:
                    pi.value, pi.state = 1.0, "warning"
                    pi.reason = "Raspberry Pi is capped or throttled now: " + ", ".join(sorted(on))
                elif on:
                    pi.value, pi.state = 1.0, "warning"
                    pi.reason = ("Raspberry Pi has been under-voltage, capped or throttled since boot: "
                                 + ", ".join(sorted(on)))
                else:
                    pi.value, pi.state = 0.0, "ok"
        for r in pick("rpi", "soc_temp"):
            temps.append(comp("temp.soc", "rpi", [r], "C", CPU_TEMP_C, {"chip": "rpi", "sensor": "soc"}))

    disks: list[Component] = []
    for r in pick("scrutiny", "device_status"):
        lab = {k: r["labels"].get(k, "") for k in ("wwn", "device", "model")}
        c = comp(f"disk.{lab['wwn']}", "scrutiny", [r], "", labels=lab)
        if c.value is not None:
            c.state = "ok" if c.value == 0 else "critical"
        disks.append(c)
    if "scrutiny" in gone and not disks:
        disks.append(comp("disk", "scrutiny", [], ""))
    for r in pick("scrutiny", "temp"):
        lab = {k: r["labels"].get(k, "") for k in ("wwn", "device", "model")}
        temps.append(comp(f"disk_temp.{lab['wwn']}", "scrutiny", [r], "C", DISK_TEMP_C, lab))

    # UPS power state from the ups.status flags: on battery is a warning, low battery is critical.
    ups: Component | None = None
    if "nut" in src_rows and "nut" not in absent:
        flags = {r["labels"].get("flag"): r for r in pick("nut", "ups_status_flag")
                 if r["labels"].get("flag") in ("OL", "OB", "LB")}
        ups = comp("ups_status", "nut", [flags[f] for f in ("OL", "OB", "LB") if f in flags], "")
        if ups.value is not None:
            if any(flags[f]["value"] is None for f in ("OL", "OB", "LB") if f in flags):
                ups = Component("ups_status", None, "", "unknown", "nut did not report ups.status")
            elif flags.get("LB", {}).get("value"):
                ups.state, ups.reason = "critical", "UPS reports low battery"
            elif flags.get("OB", {}).get("value"):
                ups.state, ups.reason = "warning", "UPS is on battery"
            elif flags.get("OL", {}).get("value"):
                ups.state = "ok"
            else:
                ups = Component("ups_status", None, "", "unknown", "ups.status has none of OL, OB or LB")

    # Open conditions: the newest threshold event per rule key, kept if its state is active.
    newest: dict[str, dict] = {}
    for e in events:
        detail = e.get("detail") or {}
        key = detail.get("rule_key")
        if isinstance(key, str) and "state" in detail and (key not in newest or e["ts"] >= newest[key]["ts"]):
            newest[key] = e
    open_conditions = []
    for key, e in newest.items():
        state = e["detail"]["state"]
        if ((key.startswith("md.degraded") and state is True)
                or (key.startswith("scrutiny.") and isinstance(state, int) and not isinstance(state, bool)
                    and state > 0)
                or (key.startswith("source|") and state is False)
                or (key.startswith("ups.power") and state in ("OB", "LB"))):
            open_conditions.append(key)

    def flag(comps: list[Component], bad: tuple[str, ...]) -> bool | None:
        known = [c for c in comps if c.state != "unknown"]
        if not known:
            return None  # nothing measured: neither a problem nor all clear
        return any(c.state in bad for c in known)

    problems: dict[str, bool | None] = {
        "md_degraded": flag(md, ("critical",)),
        "disk_failing": flag(disks, ("critical",)),
        "source_unavailable": bool(blocked or gone) if src_rows else None,
        "temperature_high": flag(temps, ("warning", "critical")),
        "memory_low": None if memory.state == "unknown" else memory.state != "ok",
    }
    last_seen = max((r["updated"] for r in src_rows.values()), default=None)
    group_comps = {"cpu": [cpu], "memory": [memory], "power": [power], "temperatures": temps,
                   "raid": md, "pools": pools, "disks": disks, "ups": [ups] if ups is not None else [],
                   "pi": [pi] if pi is not None else []}
    unmeasured = []
    not_present = []
    for group, source in EXPECTED_GROUPS.items():
        if group in OPTIONAL_GROUPS and source not in src_rows:
            continue
        if source in absent:
            # Scrutiny disk temperatures can still populate temperatures when hwmon is absent.
            if group != "temperatures" or not temps:
                not_present.append(group)
            continue
        src_ok = source in sources and source not in blocked
        comps = group_comps[group]
        if not src_ok or (comps and all(c.status is None for c in comps)):
            unmeasured.append(group)

    # Silence: the newest sign of life from the agent, as a batch (agents) or a source report.
    agents_fn = getattr(store, "agents", None)
    agent_seen = [a["last_seen"] for a in agents_fn() if a["host"] == host] if agents_fn else []
    reported = max([*agent_seen, *([last_seen] if last_seen is not None else [])], default=None)
    silent = ""
    if reported is not None and now - reported > silent_after_s:
        silent = f"host silent: last report at {_iso(reported)}, {now - reported:.0f}s ago"

    # Crashes: unacknowledged crash events inside the hold window, newest first.
    crashes = [e for src in ("boot", "pstore")
               for e in store.events(host=host, since=now - crash_hold_s, source=src, limit=1000)
               if e.get("kind") in CRASH_KINDS]
    # A confirmed power loss replaces the unknown_unclean event of the same boot, even once
    # the power loss event is acknowledged, so one outage is never two open conditions.
    confirmed = {e.get("boot_id") for e in crashes if e["kind"] == "boot.power_loss" and e.get("boot_id")}
    crashes = [e for e in crashes
               if not (e["kind"] == "boot.unknown_unclean" and e.get("boot_id") in confirmed)]
    crashes.sort(key=lambda e: (e["ts"], e["id"]), reverse=True)
    acked_fn = getattr(store, "acked_event_ids", None)
    if crashes and acked_fn:
        acked = acked_fn([e["id"] for e in crashes])
        crashes = [e for e in crashes if e["id"] not in acked]
    crash_rows = [{"id": e["id"], "kind": e["kind"].split(".", 1)[1], "ts": e["ts"]} for e in crashes]
    alert_items = _alert_items(store, host, now, alert_window_s, {c["id"] for c in crash_rows})
    return HostSummary(host, now, cpu, memory, power, temps, md, disks, sources, problems,
                       sorted(open_conditions), last_seen, unmeasured, not_present, sorted(gone),
                       silent, crash_rows, ups, wall, pools, pi, fans, alert_items)


# ---------------------------------------------------------------------------------------------
# Grouped view for the dashboard. Group membership and the worst status per group are decided
# here once, so the page only draws what it is given.
# ---------------------------------------------------------------------------------------------

# (id, label, icon name in hostwatch/web/icons, sources that make an empty group worth showing).
GROUPS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("cpu", "CPU", "cpu", ("cpu",)),
    ("memory", "Memory", "cpu-2", ("memory",)),
    ("power", "Power", "bolt", ("rapl",)),
    ("temperatures", "Temperatures", "temperature", ("hwmon",)),
    ("fans", "Fans", "propeller", ()),
    ("pools", "Storage pools", "database", ("zfs", "truenas")),
    ("raid", "RAID", "stack-2", ("mdraid",)),
    ("disks", "Disks", "device-floppy", ("scrutiny",)),
    ("ups", "UPS", "battery-charging", ("nut",)),
    ("pi_power", "Pi power supply", "plug-connected", ("rpi",)),
    ("alerts", "Alerts and events", "bell", ()),
    ("sources", "Sources", "plug-connected", ()),
)
GROUP_IDS = tuple(g[0] for g in GROUPS)

STATUS_KEYS = ("good", "warning", "critical", "unknown")
_KEY_FOR_STATE = {"ok": "good", "warning": "warning", "critical": "critical"}
_KEY_TEXT = {"good": "Good", "warning": "Warning", "critical": "Critical", "unknown": "Unknown"}
_KEY_RANK = {"unknown": 0, "good": 1, "warning": 2, "critical": 3}
_HOST_KEY = {0: "good", 1: "warning", 2: "critical"}


def status_key(state: str) -> str:
    """good, warning, critical or unknown for a component state (not present reads unknown)."""
    return _KEY_FOR_STATE.get(state, "unknown")


def worst_key(keys: list[str]) -> str:
    """The worst member status. Unknown only when every member is unknown."""
    return max(keys, key=lambda k: _KEY_RANK[k]) if keys else "unknown"


def _member_label(c: Component) -> str:
    lab = c.labels
    if "sensor" in lab:
        return f"{lab.get('chip', '')} {lab['sensor']}".strip()
    for key in ("pool", "array", "device"):
        if lab.get(key):
            return lab[key]
    if c.name.startswith("source."):
        return c.name.split(".", 1)[1]
    return _FIXED_LABELS.get(c.name) or _prefix_label(c.name)


_FIXED_LABELS = {
    "cpu_utilization": "CPU", "memory_used": "Memory", "package_power": "Package", "wall_power": "Wall power",
    "pi_throttling": "Pi power supply", "ups_status": "UPS", "host_silent": "Host silent",
    "boot.last": "Last boot", "truenas_pools": "TrueNAS pools", "pool": "Pools", "md": "RAID", "disk": "Disks",
    "temp": "Temperatures",
}
_PREFIX_LABELS = {"truenas_alert": "TrueNAS alert", "crash": "Crash event", "condition": "Open condition",
                  "event": "Event", "disk": "Disk", "pool": "Pool", "md": "RAID array"}
_PI_FLAG_TEXT = {
    "under_voltage_now": "Under-voltage now", "freq_capped_now": "Frequency capped now",
    "throttled_now": "Throttled now", "soft_temp_limit_now": "Soft temperature limit active now",
    "under_voltage_occurred": "Under-voltage has occurred since boot",
    "freq_capped_occurred": "Frequency capping has occurred since boot",
    "throttled_occurred": "Throttling has occurred since boot",
    "soft_temp_limit_occurred": "The soft temperature limit has been reached since boot",
}
_ERRNO_TEXT = (("permission denied", "permission denied"), ("no such file", "not found"),
               ("not a directory", "not a directory"), ("is a directory", "is a directory"))


def _prefix_label(name: str) -> str:
    return _PREFIX_LABELS.get(name.split(".", 1)[0], name)


def _number(value: float, places: int) -> str:
    return f"{round(value, places):g}"


def _plain_error(text: str) -> str:
    """Turn an OS error such as "[Errno 13] Permission denied: '/x'" into a short phrase."""
    low = text.lower()
    for needle, phrase in _ERRNO_TEXT:
        if needle in low:
            return phrase
    return re.sub(r"^\[errno \d+\]\s*", "", low).split(": '", 1)[0].strip()


def _plain_reason(reason: str) -> str:
    """A reason with OS errors as short phrases, for example "cannot read /x (permission denied)"."""
    m = re.match(r"cannot read (\S+?):\s+(.*)$", reason)
    if m:
        return f"cannot read {m.group(1)} ({_plain_error(m.group(2))})"
    return reason


def _source_text(c: Component) -> str:
    name = c.name.split(".", 1)[1] if "." in c.name else c.name
    if c.state == "ok":
        return f"{name}: reporting"
    m = re.match(rf"source {re.escape(name)} (unavailable|stale|disappeared|is not present):?\s*(.*)$", c.reason)
    if not m:
        return f"{name}: {_plain_reason(c.reason) or 'no reading'}"
    kind, rest = m.group(1), m.group(2)
    if kind == "unavailable":
        return f"{name}: {_plain_reason(rest)}"
    if kind == "stale":
        return f"{name}: stale, {rest}"
    if kind == "disappeared":
        return f"{name}: disappeared, {rest}"
    return f"{name}: not present on this host"


def _md_text(c: Component, label: str) -> str:
    head = f"{label} {c.labels.get('level', '').upper()}".strip()
    if c.value is None:
        return f"{head}: {c.reason or 'no reading'}"
    state = "degraded" if c.value > 0 else c.labels.get("array_state", "")
    parts = [p for p in (state, c.labels.get("sync_action", "")) if p and p != "unknown"]
    return f"{head} {', '.join(parts)}".strip()


def _pi_text(c: Component) -> str:
    if c.value is None:
        return f"Pi power supply: {c.reason or 'no reading'}"
    flags = [f for f in c.labels.get("flags", "").split(",") if f]
    if not flags:
        return "Pi power supply is good"
    order = list(_PI_FLAG_TEXT)
    flags.sort(key=lambda f: order.index(f) if f in order else len(order))
    now = [f for f in flags if f.endswith("_now")]
    return _PI_FLAG_TEXT.get((now or flags)[0], (now or flags)[0])


def _member_text(c: Component, label: str) -> str:
    """One plain line for a member: no metric id, no source prefix and rounded numbers."""
    name, v = c.name, c.value
    if name.startswith("source."):
        return _source_text(c)
    if name.startswith("md.") or name == "md":
        return _md_text(c, label)
    if name == "pi_throttling":
        return _pi_text(c)
    if name == "ups_status":
        return "UPS is on line power" if c.state == "ok" else f"UPS: {c.reason or 'no reading'}"
    if v is None:
        reason = _plain_reason(c.reason)
        if name.startswith(("truenas_alert.", "boot.last", "crash.", "condition.", "event.", "host_silent")):
            return re.sub(r"^informational:\s*", "", reason) or label
        return f"{label}: {reason}" if reason else label
    if name in ("cpu_utilization", "memory_used"):
        return f"{label} {_number(v, 0)} {c.unit} used"
    if c.unit == "W":
        return f"{label} {_number(v, 1)} W"
    if c.unit == "C":
        return f"{label} {_number(v, 1)} C"
    if c.unit == "RPM":
        return f"{label} {_number(v, 0)} RPM"
    if name.startswith(("pool.", "truenas_pool.")):
        state = c.labels.get("state") or c.labels.get("status") or ""
        text = f"Pool {label} {state.lower()}".rstrip()
        return f"{text}: {c.reason}" if c.reason else text
    if name.startswith("disk."):
        return f"{label} {'healthy' if c.state == 'ok' else 'failing'}"
    return f"{label} {_number(v, 1)} {c.unit}".rstrip()


def _member(c: Component, default_source: str) -> dict[str, Any]:
    key = status_key(c.state)
    label = _member_label(c)
    return {"id": c.name, "name": c.name, "label": label, "text": _member_text(c, label), "value": c.value,
            "unit": c.unit, "labels": dict(c.labels),
            "source": c.source or c.labels.get("source") or default_source,
            "status": key, "status_text": _KEY_TEXT[key], "reason": c.reason, "ts": c.ts}


def _group_summary(members: list[dict], agg: str) -> str:
    if not members:
        return "No readings reported."
    if len(members) == 1:
        return members[0]["text"]
    counts = [f"{sum(1 for m in members if m['status'] == k)} {k}" for k in STATUS_KEYS
              if any(m["status"] == k for m in members)]
    text = ", ".join(counts)
    info = sum(1 for m in members if m["reason"].startswith("informational"))
    if info:
        text += f" ({info} informational)"
    if agg in ("warning", "critical"):
        worst = next(m for m in members if m["status"] == agg)
        text += f". {worst['text']}"
    elif agg == "unknown":
        gaps = [m for m in members if m["status"] == "unknown"]
        text += ". Not measured: " + "; ".join(m["text"] for m in gaps)
    return text


def group_key(comps: list[Component], members: list[dict]) -> str:
    """The status of a group: the worst warning or critical member, else unknown when any member is
    unknown or unavailable (a partly unmeasured group is not Good), else good. A member that is not
    present is not a measurement and is ignored."""
    worst = worst_key([m["status"] for m in members])
    if worst in ("warning", "critical"):
        return worst
    if any(c.state == "unknown" for c in comps):
        return "unknown"
    return worst


def _alert_members(s: HostSummary) -> list[Component]:
    out: list[Component] = []
    if s.silent:
        out.append(Component("host_silent", None, "", "critical", s.silent, source="agent"))
    for c in s.crashes:
        out.append(Component(f"crash.{c['id']}", None, "", "critical",
                             f"unacknowledged crash event {c['id']}: {c['kind']} at {_iso(c['ts'])}",
                             {"event": str(c["id"])}, "boot", c["ts"]))
    for key in s.open_conditions:
        out.append(Component(f"condition.{key}", None, "", "warning", f"open threshold condition {key}",
                             source="thresholds"))
    out.extend(s.alert_items)
    return out


def group_documents(s: HostSummary) -> list[dict[str, Any]]:
    """The ordered groups of one host. A group is omitted when it has no members and none of its
    sources is present on the host."""
    power = [s.package_power] + ([s.wall_power] if s.wall_power is not None else [])
    members_for: dict[str, list[Component]] = {
        "cpu": [s.cpu], "memory": [s.memory], "power": power, "temperatures": list(s.temperatures),
        "fans": list(s.fans), "pools": list(s.pools), "raid": list(s.md_arrays), "disks": list(s.disks),
        "ups": [s.ups] if s.ups is not None else [], "pi_power": [s.pi] if s.pi is not None else [],
        "alerts": _alert_members(s), "sources": list(s.sources.values()),
    }
    out = []
    for gid, label, icon, srcs in GROUPS:
        comps = members_for[gid]
        if gid != "sources":
            comps = [c for c in comps if c.state != "not_present"]
        present = any(n in s.sources and s.sources[n].state != "not_present" for n in srcs)
        if not comps and not present and gid != "alerts":
            continue
        members = [_member(c, srcs[0] if srcs else gid) for c in comps]
        if gid == "alerts" and not members:
            agg, text = "good", "No open alerts or crash events."
        else:
            agg = group_key(comps, members)
            text = _group_summary(members, agg)
        out.append({"id": gid, "label": label, "icon": icon, "status": agg,
                    "status_text": _KEY_TEXT[agg], "summary": text, "members": members})
    return out


def grouped_host_document(s: HostSummary) -> dict[str, Any]:
    status = s.overall_status
    return {"host": s.host, "status": status, "status_key": _HOST_KEY[status],
            "status_text": _KEY_TEXT[_HOST_KEY[status]], "reason": s.overall_reason,
            "last_seen": s.last_seen, "groups": group_documents(s)}


def _worst_problem(host: dict[str, Any]) -> str:
    """The one worst member of a host in plain words: critical before warning before unknown, with
    the group order breaking ties. Group summaries are never repeated here."""
    best, best_rank = None, -1
    for g in host["groups"]:
        for m in g["members"]:
            if m["status"] != "good" and _KEY_RANK[m["status"]] > best_rank:
                best, best_rank = m, _KEY_RANK[m["status"]]
    if best is None:
        return ""
    return best["text"].rstrip(".")


def grouped_document(summaries: list[HostSummary], now: float) -> dict[str, Any]:
    """All hosts worst first, then by name, with a banner naming the worst problem and counts."""
    hosts = sorted((grouped_host_document(s) for s in summaries), key=lambda h: (-h["status"], h["host"]))
    host_counts = {k: sum(1 for h in hosts if h["status_key"] == k) for k in ("good", "warning", "critical")}
    group_counts = {k: sum(1 for h in hosts for g in h["groups"] if g["status"] == k) for k in STATUS_KEYS}
    if not hosts:
        banner = {"status": 1, "status_key": "warning", "status_text": "Warning", "host": None,
                  "text": "No hosts have reported yet."}
    else:
        worst = hosts[0]
        if worst["status"] == 0:
            text = "All hosts are good."
        else:
            text = f"{worst['host']} is {worst['status_text'].lower()}"
            problem = _worst_problem(worst)
            text += f": {problem}." if problem else "."
        banner = {"status": worst["status"], "status_key": worst["status_key"],
                  "status_text": worst["status_text"], "host": worst["host"], "text": text}
    banner["counts"] = {"hosts": host_counts, "groups": group_counts}
    return {"generated": now, "banner": banner, "hosts": hosts}
