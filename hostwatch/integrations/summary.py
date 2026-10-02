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
  * Status codes are 0 ok, 1 warning, 2 critical, from `status_for` only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

STALE_AFTER_S = 180.0
EVENT_WINDOW_S = 86400.0

STATUS_OK, STATUS_WARNING, STATUS_CRITICAL = 0, 1, 2

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

    def components(self) -> list[Component]:
        return [self.cpu, self.memory, self.package_power, *self.temperatures, *self.md_arrays,
                *self.disks, *self.sources.values()]

    @property
    def status(self) -> int | None:
        """Worst known status over all components, None if nothing is known."""
        known = [c.status for c in self.components() if c.status is not None]
        return max(known) if known else None


class StoreLike(Protocol):
    def latest(self, host: str | None = None) -> list[dict]: ...
    def sources(self) -> list[dict]: ...
    def events(self, host: str | None = None, since: float | None = None, kind: str | None = None,
               limit: int = 100, source: str | None = None, **kw: Any) -> list[dict]: ...


def _label(labels: dict[str, str]) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


def build_host_summary(store: StoreLike, host: str, now: float) -> HostSummary:
    rows = [r for r in store.latest(host) if r["host"] == host]
    src_rows = {r["source"]: r for r in store.sources() if r["host"] == host}
    events = store.events(host=host, since=now - EVENT_WINDOW_S, source="thresholds", limit=1000)

    # Source availability: the reported flag plus the age of the last report.
    blocked: dict[str, str] = {}
    sources: dict[str, Component] = {}
    for name, r in sorted(src_rows.items()):
        age = now - r["updated"]
        if not r["available"]:
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
    if total.value is None or avail.value is None:
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
    if not temps:
        temps.append(comp("temp", "hwmon", [], "C", CPU_TEMP_C))

    md: list[Component] = []
    for arr in sorted({r["labels"].get("array", "") for r in rows if r["source"] == "mdraid"}):
        c = comp(f"md.{arr}", "mdraid", pick("mdraid", "degraded", array=arr), "count", labels={"array": arr})
        if c.value is not None:
            syncing = any(r["labels"].get("action") not in (None, "idle") and r["value"] is not None
                          and now - r["ts"] <= STALE_AFTER_S for r in pick("mdraid", "sync_action", array=arr))
            c.state = "critical" if c.value > 0 else "warning" if syncing else "ok"
        md.append(c)

    disks: list[Component] = []
    for r in pick("scrutiny", "device_status"):
        lab = {k: r["labels"].get(k, "") for k in ("wwn", "device", "model")}
        c = comp(f"disk.{lab['wwn']}", "scrutiny", [r], "", labels=lab)
        if c.value is not None:
            c.state = "ok" if c.value == 0 else "critical"
        disks.append(c)
    for r in pick("scrutiny", "temp"):
        lab = {k: r["labels"].get(k, "") for k in ("wwn", "device", "model")}
        temps.append(comp(f"disk_temp.{lab['wwn']}", "scrutiny", [r], "C", DISK_TEMP_C, lab))

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
                or (key.startswith("source|") and state is False)):
            open_conditions.append(key)

    def flag(comps: list[Component], bad: tuple[str, ...]) -> bool | None:
        known = [c for c in comps if c.state != "unknown"]
        if not known:
            return None  # nothing measured: neither a problem nor all clear
        return any(c.state in bad for c in known)

    problems: dict[str, bool | None] = {
        "md_degraded": flag(md, ("critical",)),
        "disk_failing": flag(disks, ("critical",)),
        "source_unavailable": bool(blocked) if src_rows else None,
        "temperature_high": flag(temps, ("warning", "critical")),
        "memory_low": None if memory.state == "unknown" else memory.state != "ok",
    }
    last_seen = max((r["updated"] for r in src_rows.values()), default=None)
    return HostSummary(host, now, cpu, memory, power, temps, md, disks, sources, problems,
                       sorted(open_conditions), last_seen)
