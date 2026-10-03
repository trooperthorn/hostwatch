"""Shared host summary: unavailable values stay None with a reason, and status maps to 0, 1, 2."""

from __future__ import annotations

from hostwatch.integrations.summary import Component, build_host_summary, status_for

NOW = 10_000.0
H = "h1"


class FakeStore:
    def __init__(self, rows, sources, events=()):
        self._rows, self._sources, self._events = rows, sources, list(events)

    def latest(self, host=None):
        return self._rows

    def sources(self):
        return self._sources

    def events(self, **kw):
        return self._events


def row(source, metric, value, ts=NOW - 5, **labels):
    return {"host": H, "source": source, "metric": metric, "labels": labels, "value": value, "unit": "", "ts": ts}


def src(name, available=True, reason="", updated=NOW - 5):
    return {"host": H, "source": name, "available": int(available), "reason": reason, "updated": updated}


def healthy_rows():
    return [
        row("cpu", "utilization_pct", 12.5),
        row("memory", "mem_total", 8000.0), row("memory", "mem_available", 6000.0),
        row("rapl", "watts", 20.0, zone="r0", domain="package-0"),
        row("hwmon", "temp", 45.0, chip="k10temp", sensor="Tctl"),
        row("mdraid", "degraded", 0, array="md0"), row("mdraid", "sync_action", 1, array="md0", action="idle"),
        row("scrutiny", "device_status", 0, wwn="w1", device="sda", model="m"),
        row("scrutiny", "temp", 35.0, wwn="w1", device="sda", model="m"),
    ]


ALL = ["cpu", "memory", "rapl", "hwmon", "mdraid", "scrutiny"]


def build(rows, sources=None, events=()):
    sources = [src(n) for n in ALL] if sources is None else sources
    return build_host_summary(FakeStore(rows, sources, events), H, NOW)


def test_status_mapping_is_0_1_2_and_none_for_unknown():
    assert status_for(Component("a", 1.0, state="ok")) == 0
    assert status_for(Component("a", 1.0, state="warning")) == 1
    assert status_for(Component("a", 1.0, state="critical")) == 2
    assert status_for(Component("a", None, state="unknown")) is None


def test_healthy_host():
    s = build(healthy_rows())
    assert s.cpu.value == 12.5 and s.cpu.status == 0
    assert s.memory.value == 25.0 and s.memory.status == 0
    assert s.package_power.value == 20.0
    assert s.md_arrays[0].status == 0 and s.disks[0].status == 0
    assert s.status == 0
    assert s.problems == {"md_degraded": False, "disk_failing": False, "source_unavailable": False,
                          "temperature_high": False, "memory_low": False}
    assert s.open_conditions == []


def test_warning_from_temperature_and_resync():
    rows = healthy_rows()
    rows[4] = row("hwmon", "temp", 85.0, chip="k10temp", sensor="Tctl")
    rows[6] = row("mdraid", "sync_action", 1, array="md0", action="resync")
    s = build(rows)
    assert s.temperatures[0].status == 1
    assert s.md_arrays[0].status == 1
    assert s.problems["temperature_high"] is True
    assert s.status == 1


def test_critical_degraded_failing_disk_and_open_conditions():
    rows = healthy_rows()
    rows[5] = row("mdraid", "degraded", 1, array="md0")
    rows[7] = row("scrutiny", "device_status", 2, wwn="w1", device="sda", model="m")
    ev = [{"ts": NOW - 50, "detail": {"rule_key": "md.degraded|array=md0", "state": True}},
          {"ts": NOW - 60, "detail": {"rule_key": "md.degraded|array=md0", "state": False}}]
    s = build(rows, events=ev)
    assert s.md_arrays[0].status == 2 and s.disks[0].status == 2
    assert s.problems["md_degraded"] and s.problems["disk_failing"]
    assert s.open_conditions == ["md.degraded|array=md0"]
    assert s.status == 2


def test_cleared_condition_is_not_open():
    ev = [{"ts": NOW - 50, "detail": {"rule_key": "md.degraded|array=md0", "state": False}}]
    assert build(healthy_rows(), events=ev).open_conditions == []


def test_unavailable_source_gives_none_and_reason_not_zero():
    sources = [src(n) for n in ALL if n != "rapl"] + [src("rapl", False, "energy_uj is root only")]
    s = build(healthy_rows(), sources)
    assert s.package_power.value is None and s.package_power.status is None
    assert "root only" in s.package_power.reason
    assert s.sources["rapl"].status == 1
    assert s.problems["source_unavailable"] is True


def test_stale_source_and_stale_sample_are_unavailable():
    old = NOW - 1000
    sources = [src(n, updated=old) if n == "cpu" else src(n) for n in ALL]
    s = build(healthy_rows(), sources)
    assert s.cpu.value is None and "stale" in s.cpu.reason
    rows = healthy_rows()
    rows[0] = row("cpu", "utilization_pct", 99.0, ts=old)
    s2 = build(rows)
    assert s2.cpu.value is None and "stale" in s2.cpu.reason


def test_null_sample_missing_source_and_empty_host():
    rows = healthy_rows()
    rows[0] = row("cpu", "utilization_pct", None)
    s = build(rows)
    assert s.cpu.value is None and s.cpu.status is None and s.cpu.reason
    empty = build([], [])
    assert empty.cpu.value is None and "has not reported" in empty.cpu.reason
    assert empty.memory.value is None and empty.status is None
    assert empty.problems["md_degraded"] is None and empty.last_seen is None


def test_memory_unavailable_when_total_missing():
    rows = [r for r in healthy_rows() if r["metric"] != "mem_total"]
    s = build(rows)
    assert s.memory.value is None and s.memory.reason and s.problems["memory_low"] is None


def ups_rows(status):
    present = status.split()
    return [row("nut", "ups_status_flag", 1 if f in present else 0, flag=f, status=status)
            for f in ("OL", "OB", "LB")]


def test_ups_group_status_levels():
    sources = [src(n) for n in ALL] + [src("nut")]
    ok = build(healthy_rows() + ups_rows("OL"), sources)
    assert ok.ups.status == 0 and ok.overall_status == 0
    warn = build(healthy_rows() + ups_rows("OB"), sources)
    assert warn.ups.status == 1 and warn.overall_status == 1
    crit = build(healthy_rows() + ups_rows("OB LB"), sources)
    assert crit.ups.status == 2 and crit.overall_status == 2


def test_ups_unavailable_is_unmeasured_only_when_configured():
    down = [src(n) for n in ALL] + [src("nut", available=False, reason="cannot reach")]
    s = build(healthy_rows(), down)
    assert "ups" in s.unmeasured and s.ups.status is None and s.overall_status == 1
    # Unconfigured NUT reports not present and adds no warning.
    absent = [src(n) for n in ALL] + [{**src("nut", available=False), "present": 0}]
    s = build(healthy_rows(), absent)
    assert "ups" not in s.unmeasured and "ups" in s.not_present and s.overall_status == 0
    # No nut row at all adds nothing either.
    s = build(healthy_rows())
    assert "ups" not in s.unmeasured and "ups" not in s.not_present and s.ups is None
