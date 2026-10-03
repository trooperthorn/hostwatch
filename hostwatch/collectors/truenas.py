"""TrueNAS pool, device, temperature and alert state from the TrueNAS JSON-RPC API, read-only.

Four read-only calls are made each cycle through `TruenasClient`: `pool.query`, `disk.query`,
`disk.temperatures` and `alert.list`. The shapes are the ones measured on TrueNAS-SVR and recorded
in docs/hosts/truenas-svr.md. If any call fails the whole source is unavailable for that cycle
with the reason, because a pool report without its disk names, or a temperature without its
serial, would be a guess.

Samples, all from the `truenas` source:
  pool_health       0 ok, 1 warning, 2 critical, labels pool, status, status_code, scan_function,
                    scan_state and reason (the disks and counts behind a non-zero value)
  pool_healthy      1 or 0 from the API `healthy` flag; pool_warning the same for `warning`
  pool_scan_errors  errors of the last scan, None when the pool has no scan record
  vdev_read_errors, vdev_write_errors, vdev_checksum_errors, vdev_self_healed_bytes
                    per leaf device, labels pool, class, group, vdev, disk and serial
  disk_temp_c       per disk from disk.temperatures, labels disk, serial, model and pool; None
                    when the API gave no temperature for a known disk

Health rules, worst wins:
  * a pool status of DEGRADED, FAULTED, UNAVAIL, SUSPENDED or REMOVED is critical
  * `healthy` true with `warning` true (TrueNAS keeps a pool healthy after a corrected error) is
    a warning, not ok
  * any non-zero read, write or checksum count on a device is at least a warning, naming the disk
  * a leaf device whose own status is not ONLINE is at least a warning
  * a scan that finished with errors, or `healthy` false on an otherwise online pool, is a warning

Alerts (including dismissed ones) are events of kind truenas.alert from `read_events`, keyed by
alert uuid and last_occurrence so a repeat of the same occurrence is the same event. The agent
drops keys it has already handed to a batch, which is how an alert is not repeated next cycle.

The agent loop is synchronous, so the collector keeps one private event loop and runs the async
client on it. This keeps one WebSocket open across cycles.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..schema import Event, SourceStatus
from .base import Collector

CRITICAL_POOL_STATES = frozenset({"DEGRADED", "FAULTED", "UNAVAIL", "SUSPENDED", "REMOVED"})
CRITICAL_LEVELS = frozenset({"ERROR", "CRITICAL", "ALERT", "EMERGENCY"})
INFO_LEVELS = frozenset({"INFO", "NOTICE"})
BAD_DEVICE_STATES = frozenset({"DEGRADED", "FAULTED", "UNAVAIL", "REMOVED", "OFFLINE"})
VDEV_CLASSES = ("data", "log", "cache", "spare", "special", "dedup")
ERROR_METRICS = (("read_errors", "vdev_read_errors"), ("write_errors", "vdev_write_errors"),
                 ("checksum_errors", "vdev_checksum_errors"))
MAX_TITLE = 200


class TruenasError(Exception):
    """A TrueNAS call failed; the message is safe to report."""


def alert_severity(level: object) -> str:
    """Map a TrueNAS alert level to info, warning or critical. An unknown level is a warning."""
    text = str(level).upper()
    if text in CRITICAL_LEVELS:
        return "critical"
    if text in INFO_LEVELS:
        return "info"
    return "warning"


def _num(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        return None
    return float(value)


def _flag(value: object) -> float | None:
    return None if not isinstance(value, bool) else (1.0 if value else 0.0)


def _leaves(vdev: dict, group: str) -> list[tuple[str, dict]]:
    children = vdev.get("children") or []
    if not children:
        return [(group, vdev)]
    return [leaf for child in children for leaf in _leaves(child, vdev.get("name") or group)]


class TruenasCollector(Collector):
    id = "truenas"
    # A configured network source is polled every cycle even after a failure.
    retry_each_cycle = True

    def __init__(self, sysfs, procfs, client=None) -> None:
        super().__init__(sysfs, procfs)
        self.client = client
        self._loop: asyncio.AbstractEventLoop | None = None
        self._alerts: list[dict] = []
        self._failure: str = ""

    # -- plumbing -----------------------------------------------------------------------------

    def _call(self, method: str) -> Any:
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
        result = self._loop.run_until_complete(self.client.call(method))
        if not result.available:
            raise TruenasError(f"{method} failed: {result.reason or 'no reason given'}")
        return result.value

    def close(self) -> None:
        if self._loop is not None:
            try:
                if self.client is not None:
                    self._loop.run_until_complete(self.client.close())
            finally:
                self._loop.close()
                self._loop = None

    # -- collector interface ------------------------------------------------------------------

    def is_absent(self):
        """Absent by configuration: no TrueNAS URL was set, so nothing is expected."""
        return self.client is None

    def detect(self):
        if self.client is None:
            return False, "HOSTWATCH_TRUENAS_URL is not set"
        try:
            pools = self._call("pool.query")
        except TruenasError as exc:
            return False, str(exc)
        if not isinstance(pools, list):
            return False, "pool.query did not return a list"
        return True, f"{len(pools)} pool(s) through the TrueNAS API"

    def collect(self):
        """Raises TruenasError when the API cannot be read, which the agent turns into unavailable."""
        try:
            pools = self._call("pool.query")
            disks = self._call("disk.query")
            temps = self._call("disk.temperatures")
            alerts = self._call("alert.list")
        except TruenasError as exc:
            self._alerts, self._failure = [], str(exc)
            raise
        if not (isinstance(pools, list) and isinstance(disks, list) and isinstance(temps, dict)
                and isinstance(alerts, list)):
            self._alerts, self._failure = [], "unexpected answer shape from TrueNAS"
            raise TruenasError(self._failure)
        self._failure = ""
        self._alerts = [a for a in alerts if isinstance(a, dict)]
        by_name = {d.get("name"): d for d in disks if isinstance(d, dict) and d.get("name")}
        out = []
        for pool in pools:
            if isinstance(pool, dict) and pool.get("name"):
                out.extend(self._pool_samples(pool, by_name))
        out.extend(self._temperature_samples(by_name, temps))
        return out

    # -- pools --------------------------------------------------------------------------------

    def _pool_samples(self, pool: dict, disks: dict[str, dict]) -> list:
        name = str(pool["name"])
        status = str(pool.get("status") or "")
        scan = pool.get("scan") if isinstance(pool.get("scan"), dict) else {}
        reasons: list[str] = []
        level = 0
        out = []

        def raise_to(new: int, why: str) -> None:
            nonlocal level
            level = max(level, new)
            reasons.append(why)

        if status in CRITICAL_POOL_STATES:
            raise_to(2, f"pool {name} is {status}")
        elif status != "ONLINE":
            raise_to(1, f"pool {name} has status {status or 'unknown'}")
        if pool.get("healthy") is False and status not in CRITICAL_POOL_STATES:
            raise_to(1, f"pool {name} is reported not healthy")
        if pool.get("healthy") is True and pool.get("warning") is True:
            raise_to(1, f"pool {name} is healthy with a warning flag (a corrected error)")
        elif pool.get("warning") is True:
            raise_to(1, f"pool {name} has a warning flag")
        scan_errors = _num(scan.get("errors")) if scan else None
        if scan_errors:
            raise_to(1, f"the last scan of pool {name} found {scan_errors:g} error(s)")

        topology = pool.get("topology") if isinstance(pool.get("topology"), dict) else {}
        for cls in VDEV_CLASSES:
            for top in topology.get(cls) or []:
                if not isinstance(top, dict):
                    continue
                for group, leaf in _leaves(top, top.get("name") or ""):
                    disk_name = str(leaf.get("disk") or leaf.get("device") or "")
                    serial = str((disks.get(disk_name) or {}).get("serial") or "")
                    stats = leaf.get("stats") if isinstance(leaf.get("stats"), dict) else {}
                    labels = {"pool": name, "class": cls, "group": str(group),
                              "vdev": str(leaf.get("name") or ""), "disk": disk_name, "serial": serial}
                    who = f"disk {disk_name or labels['vdev']}" + (f" (serial {serial})" if serial else "")
                    for key, metric in ERROR_METRICS:
                        value = _num(stats.get(key))
                        out.append(self.sample(metric, value, "count", **labels))
                        if value:
                            raise_to(1, f"{who} in pool {name} has {value:g} {key.replace('_', ' ')}")
                    out.append(self.sample("vdev_self_healed_bytes", _num(stats.get("self_healed")), "B",
                                           **labels))
                    dev_status = str(leaf.get("status") or "")
                    if dev_status in BAD_DEVICE_STATES:
                        raise_to(1, f"{who} in pool {name} is {dev_status}")

        labels = {"pool": name, "status": status, "status_code": str(pool.get("status_code") or ""),
                  "scan_function": str(scan.get("function") or ""), "scan_state": str(scan.get("state") or ""),
                  "reason": "; ".join(reasons)}
        out.append(self.sample("pool_health", float(level), "", **labels))
        out.append(self.sample("pool_healthy", _flag(pool.get("healthy")), "", pool=name))
        out.append(self.sample("pool_warning", _flag(pool.get("warning")), "", pool=name))
        out.append(self.sample("pool_scan_errors", scan_errors, "count", pool=name,
                               scan_function=labels["scan_function"], scan_state=labels["scan_state"]))
        return out

    # -- temperatures -------------------------------------------------------------------------

    def _temperature_samples(self, disks: dict[str, dict], temps: dict) -> list:
        out = []
        for name in sorted(set(disks) | set(temps)):
            info = disks.get(name) or {}
            out.append(self.sample("disk_temp_c", _num(temps.get(name)), "C", disk=str(name),
                                   serial=str(info.get("serial") or ""), model=str(info.get("model") or ""),
                                   pool=str(info.get("pool") or "")))
        return out

    # -- alerts -------------------------------------------------------------------------------

    def read_events(self) -> tuple[SourceStatus, list[Event]]:
        """The alerts from the latest collect, dismissed ones included, as events."""
        if self.client is None:
            return SourceStatus(source="truenas_alerts", available=False,
                                reason="HOSTWATCH_TRUENAS_URL is not set", present=False), []
        if self._failure:
            return SourceStatus(source="truenas_alerts", available=False, reason=self._failure), []
        events: dict[str, Event] = {}
        for alert in self._alerts:
            event = self._alert_event(alert)
            if event is not None:
                events[event.dedup_key] = event
        return SourceStatus(source="truenas_alerts", available=True), list(events.values())

    @staticmethod
    def _alert_event(alert: dict) -> Event | None:
        uuid = alert.get("uuid")
        occurred = _num(alert.get("last_occurrence"))
        if occurred is None:
            occurred = _num(alert.get("datetime"))
        if not uuid or occurred is None:
            return None
        text = " ".join(str(alert.get("formatted") or alert.get("klass") or "TrueNAS alert").split())
        level = str(alert.get("level") or "")
        return Event(
            kind="truenas.alert", severity=alert_severity(level), source="truenas", ts=occurred,
            title=text[:MAX_TITLE],
            detail={"uuid": str(uuid), "klass": alert.get("klass"), "alert_source": alert.get("source"),
                    "level": level, "dismissed": bool(alert.get("dismissed")), "formatted": text},
            dedup_key=f"truenas.alert:{uuid}:{int(occurred * 1000)}")
