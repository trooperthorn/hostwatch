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

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

STALE_AFTER_S = 180.0
EVENT_WINDOW_S = 86400.0
SILENT_AFTER_S = 45.0
CRASH_HOLD_S = 86400.0
# Event kinds that mean the host went down badly. clean_shutdown and agent_stopped are not here.
CRASH_KINDS = frozenset({"boot.kernel_panic", "boot.watchdog_reset", "boot.unknown_unclean",
                         "boot.power_loss",
                         "pstore.kernel_panic", "pstore.kernel_oops"})

STATUS_OK, STATUS_WARNING, STATUS_CRITICAL = 0, 1, 2

# Expected component group -> the source that feeds it. A group whose source is unavailable,
# stale or has never reported is unmeasured. Pools are left out: no pool source is collected.
EXPECTED_GROUPS = {"cpu": "cpu", "memory": "memory", "power": "rapl", "temperatures": "hwmon",
                   "raid": "mdraid", "disks": "scrutiny", "ups": "nut"}
# Groups that are expected only when their source has a row at all. The nut source reports
# not present when NUT is unconfigured, so a host with no nut row is treated as not using NUT.
OPTIONAL_GROUPS = frozenset({"ups"})

# (warning, critical) thresholds, in the unit of the value. These are defaults
# chosen for desktop and server parts, not measured limits; see UNVERIFIED.md.
CPU_TEMP_C = (80.0, 90.0)
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

    def components(self) -> list[Component]:
        extra = [self.ups] if self.ups is not None else []
        return [self.cpu, self.memory, self.package_power, *self.temperatures, *self.md_arrays,
                *self.disks, *extra, *self.sources.values()]

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
        return max(worst, STATUS_WARNING) if self.unmeasured else worst

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
            return "unmeasured groups: " + ", ".join(self.unmeasured)
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


def build_host_summary(store: StoreLike, host: str, now: float, silent_after_s: float = SILENT_AFTER_S,
                       crash_hold_s: float = CRASH_HOLD_S) -> HostSummary:
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
        return Component(name, float(r["value"]), unit, state, "", labels)

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

    temps: list[Component] = []
    for r in pick("hwmon", "temp"):
        lab = {"chip": r["labels"].get("chip", ""), "sensor": r["labels"].get("sensor", "")}
        temps.append(comp(f"temp.{_label(lab)}", "hwmon", [r], "C", CPU_TEMP_C, lab))
    if not temps and "hwmon" not in absent:
        temps.append(comp("temp", "hwmon", [], "C", CPU_TEMP_C))

    md: list[Component] = []
    for arr in sorted({r["labels"].get("array", "") for r in rows if r["source"] == "mdraid"}):
        c = comp(f"md.{arr}", "mdraid", pick("mdraid", "degraded", array=arr), "count", labels={"array": arr})
        if c.value is not None:
            syncing = any(r["labels"].get("action") not in (None, "idle") and r["value"] is not None
                          and now - r["ts"] <= STALE_AFTER_S for r in pick("mdraid", "sync_action", array=arr))
            c.state = "critical" if c.value > 0 else "warning" if syncing else "ok"
        md.append(c)
    if "mdraid" in gone and not md:
        md.append(comp("md", "mdraid", [], "count", labels={"array": "unknown"}))

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
                   "raid": md, "disks": disks, "ups": [ups] if ups is not None else []}
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
    return HostSummary(host, now, cpu, memory, power, temps, md, disks, sources, problems,
                       sorted(open_conditions), last_seen, unmeasured, not_present, sorted(gone),
                       silent, crash_rows, ups)
