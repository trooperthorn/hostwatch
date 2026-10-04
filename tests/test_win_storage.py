"""Windows disk, Storage Spaces and smartctl collectors: JSON fixtures and fakes only, nothing real runs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fakes_windows import FakeCimQuery, FakeCommandRunner, FakeEventLogReader, FakePipeStatusReader

from hostwatch.agent import Agent
from hostwatch.collectors import build_collectors
from hostwatch.collectors.win_storage import (
    NAMESPACE,
    WinSmartctlCollector,
    WinStorageCollector,
    health_level,
)
from hostwatch.config import Config
from hostwatch.events.thresholds import ThresholdEngine
from hostwatch.schema import Sample
from hostwatch.windows import CommandResult, SeamError, WindowsSeam

FIXTURES = Path(__file__).parent / "fixtures" / "windows"
CIM = json.loads((FIXTURES / "storage_cim.json").read_text(encoding="utf-8"))
SMART = json.loads((FIXTURES / "smartctl.json").read_text(encoding="utf-8"))


def seam_for(classes=None, results=None) -> WindowsSeam:
    return WindowsSeam(events=FakeEventLogReader({}), cim=FakeCimQuery(classes or {}),
                       pipe=FakePipeStatusReader({}), runner=FakeCommandRunner(results))


def storage(scenario: str) -> WinStorageCollector:
    return WinStorageCollector(seam=seam_for(CIM[scenario]))


def find(samples, metric, **labels):
    return [s for s in samples if s.metric == metric and all(s.labels.get(k) == v for k, v in labels.items())]


def ok(payload) -> CommandResult:
    return CommandResult(0, json.dumps(payload))


def test_healthy_disks_pools_and_counters():
    c = storage("healthy")
    assert c.detect() == (True, "2 physical disk(s)")
    samples = c.collect()
    assert {s.source for s in samples} == {"win_storage"}
    assert [s.value for s in find(samples, "disk_health")] == [0, 0]
    [temp] = find(samples, "temp", id="0")
    assert (temp.value, temp.unit, temp.labels["name"], temp.labels["serial"]) == (41, "C", "Samsung SSD 980 PRO 1TB", "S6B0NX0R")
    assert find(samples, "wear_pct", id="0")[0].value == 3
    assert find(samples, "wear_pct", id="1") == []  # a null counter is left out, never zero
    assert find(samples, "power_on_hours", id="1")[0].value == 30211  # decimal string accepted
    [pool] = find(samples, "pool_health")
    assert (pool.value, pool.labels["pool"], pool.labels["health"]) == (0, "Tank", "Healthy")  # primordial skipped
    [vd] = find(samples, "virtual_disk_health")
    assert (vd.value, vd.labels["virtual_disk"], vd.labels["operational"]) == (0, "Media", "OK")
    assert all(call[2] == NAMESPACE for call in c.seam.cim.calls)


def test_warning_disk_maps_to_level_one_with_counters():
    samples = storage("warning").collect()
    [d] = find(samples, "disk_health")
    assert (d.value, d.labels["health"]) == (1, "Warning")
    assert find(samples, "read_errors_uncorrected")[0].value == 2
    assert find(samples, "wear_pct")[0].value == 91
    assert find(samples, "pool_health") == [] and find(samples, "virtual_disk_health") == []


def test_degraded_pool_is_critical_and_in_service_virtual_disk_too():
    samples = storage("degraded_pool").collect()
    assert [s.value for s in find(samples, "disk_health")] == [0, 2]
    bad = find(samples, "disk_health", id="2")[0]
    assert bad.labels["operational"] == "Error,Lost Communication"
    [pool] = find(samples, "pool_health")
    assert (pool.value, pool.labels["operational"]) == (2, "Degraded")
    [vd] = find(samples, "virtual_disk_health")
    assert (vd.value, vd.labels["operational"]) == (2, "Degraded,In Service")
    assert find(samples, "temp") == []  # no reliability counters were returned at all


def test_missing_reliability_counters_leave_samples_out():
    c = storage("missing_counters")
    samples = c.collect()
    assert {s.metric for s in samples} == {"disk_health", "pool_health", "virtual_disk_health"}
    assert not find(samples, "temp") and not find(samples, "wear_pct")
    h0, h7 = find(samples, "disk_health", id="0")[0], find(samples, "disk_health", id="7")[0]
    assert h0.value == 0
    assert h7.value is None and h7.labels["health"] == "Unknown"  # unrecognised is unknown, never ok


def test_counter_class_failure_does_not_lose_health():
    classes = {"MSFT_PhysicalDisk": CIM["healthy"]["MSFT_PhysicalDisk"]}  # the other classes raise SeamError
    samples = WinStorageCollector(seam=seam_for(classes)).collect()
    assert [s.metric for s in samples if s.metric == "disk_health"] == ["disk_health", "disk_health"]
    assert not find(samples, "temp")


def test_seam_failure_is_unavailable_with_reason():
    c = WinStorageCollector(seam=seam_for({}))
    ok_, reason = c.detect()
    assert not ok_ and "MSFT_PhysicalDisk" in reason
    assert c.is_absent() is False
    assert WinStorageCollector().detect() == (False, "no Windows seam")
    empty = WinStorageCollector(seam=seam_for({"MSFT_PhysicalDisk": []}))
    assert empty.detect()[0] is False
    with pytest.raises(SeamError):
        c.collect()


@pytest.mark.parametrize("health,operational,expected", [
    (0, [2], 0), (1, [2], 1), (2, [2], 2), (0, [3], 2), (0, [4], 1), (0, [11], 1), (5, [0], None),
    ("Healthy", ["OK"], 0), ("Unhealthy", None, 2), ("0", "2", 0), (None, None, None), (True, [True], None),
    (0, [0xD010], 0),
])
def test_health_level_mapping(health, operational, expected):
    assert health_level(health, operational)[0] == expected


def smart_results(*devices):
    return [ok(SMART["scan"])] + [ok(d) for d in devices]


def smart_collector(*devices):
    return WinSmartctlCollector(seam=seam_for(results=smart_results(*devices)))


def test_smartctl_parses_ata_and_nvme_and_skips_unsafe_device_names():
    c = smart_collector(SMART["sata_ok"], SMART["nvme_failing"])
    c.seam.runner.results.insert(0, ok(SMART["scan"]))  # detect() scans once, collect() scans again
    assert c.detect() == (True, "2 device(s)")
    samples = c.collect()
    assert {s.source for s in samples} == {"win_smartctl"}
    assert find(samples, "smart_passed", device="/dev/sda")[0].value == 1
    assert find(samples, "reallocated_sectors", device="/dev/sda")[0].value == 8
    assert find(samples, "temp", device="/dev/sda")[0].value == 34
    assert find(samples, "smart_passed", device="/dev/nvme0")[0].value == 0
    assert find(samples, "wear_pct", device="/dev/nvme0")[0].value == 97
    assert find(samples, "media_errors", device="/dev/nvme0")[0].value == 4
    assert find(samples, "reallocated_sectors", device="/dev/nvme0") == []
    calls = [args for args, _ in c.seam.runner.calls]
    assert calls[0] == ["smartctl", "--scan", "-j"]
    assert ["smartctl", "-a", "-j", "-d", "nvme", "/dev/nvme0"] in calls
    assert not any("rm" in " ".join(a) for a in calls)  # the shell-looking name was never passed on


def test_smartctl_missing_status_is_unknown_not_passed():
    c = smart_collector(SMART["no_status"], SMART["no_status"])
    samples = c.collect()
    [s] = find(samples, "smart_passed", device="/dev/sda")
    assert s.value is None
    assert {x.metric for x in samples} == {"smart_passed"}


def test_smartctl_unreadable_disk_is_skipped_for_the_cycle():
    c = WinSmartctlCollector(seam=seam_for(results=[ok(SMART["scan"]), CommandResult(2, "not json"),
                                                    ok(SMART["nvme_failing"])]))
    samples = c.collect()
    assert {s.labels["device"] for s in samples} == {"/dev/nvme0"}


def test_smartctl_not_installed_is_absent():
    class Missing:
        def run(self, args, timeout_s):
            raise SeamError("cannot run smartctl: [WinError 2] The system cannot find the file specified")

    seam = WindowsSeam(events=FakeEventLogReader({}), cim=FakeCimQuery({}), pipe=FakePipeStatusReader({}),
                       runner=Missing())
    c = WinSmartctlCollector(seam=seam)
    assert c.detect() == (False, "smartctl is not installed")
    assert c.is_absent() is True


def test_smartctl_timeout_or_bad_output_is_unavailable_not_absent():
    class Slow:
        def run(self, args, timeout_s):
            raise SeamError("smartctl timed out after 20 seconds")

    seam = WindowsSeam(events=FakeEventLogReader({}), cim=FakeCimQuery({}), pipe=FakePipeStatusReader({}),
                       runner=Slow())
    c = WinSmartctlCollector(seam=seam)
    ok_, reason = c.detect()
    assert not ok_ and "timed out" in reason and c.is_absent() is False
    garbled = WinSmartctlCollector(seam=seam_for(results=[CommandResult(0, "garbage")]))
    assert garbled.detect()[0] is False and garbled.is_absent() is False
    assert WinSmartctlCollector().detect() == (False, "no Windows seam")


def test_registered_only_on_windows(tmp_path):
    cfg = Config(data_dir=tmp_path, sysfs=tmp_path / "sys", procfs=tmp_path / "proc")
    seam = seam_for()
    win = build_collectors(cfg, seam, platform="windows")
    assert [type(c) for c in win[-3:-1]] == [WinStorageCollector, WinSmartctlCollector]
    assert len({c.id for c in win}) == len(win)
    assert all(c.seam is seam for c in win)
    lin = build_collectors(cfg, platform="x86")
    assert not any(isinstance(c, (WinStorageCollector, WinSmartctlCollector)) for c in lin)


def storage_samples(metric, value, id_, source):
    return [Sample(source=source, metric=metric, value=value, labels={"id": id_, "health": "x"}, ts=1.0)]


def kinds(events):
    return [(e.kind, e.severity) for e in events]


def test_degraded_pool_events_are_edge_triggered():
    eng = ThresholdEngine()
    assert eng.evaluate(storage_samples("pool_health", 0, "Tank", "win_storage"), [], now=1) == []
    raised = eng.evaluate(storage_samples("pool_health", 2, "Tank", "win_storage"), [], now=2)
    assert kinds(raised) == [("winstorage.health_raised", "critical")]
    assert "Tank" in raised[0].title and raised[0].detail["rule_key"].endswith("id=Tank")
    assert eng.evaluate(storage_samples("pool_health", 2, "Tank", "win_storage"), [], now=3) == []
    assert eng.evaluate(storage_samples("pool_health", None, "Tank", "win_storage"), [], now=4) == []
    assert kinds(eng.evaluate(storage_samples("pool_health", 0, "Tank", "win_storage"), [], now=5)) == [
        ("winstorage.health_cleared", "info")]


def test_warning_then_critical_raises_twice_and_first_sight_unhealthy_raises():
    eng = ThresholdEngine()
    assert kinds(eng.evaluate(storage_samples("disk_health", 1, "3", "win_storage"), [], now=1)) == [
        ("winstorage.health_raised", "warning")]
    assert kinds(eng.evaluate(storage_samples("disk_health", 2, "3", "win_storage"), [], now=2)) == [
        ("winstorage.health_raised", "critical")]
    assert eng.evaluate(storage_samples("disk_health", 1, "3", "win_storage"), [], now=3) == []


def test_smart_failure_event_and_seed_survives_restart():
    eng = ThresholdEngine()
    events = eng.evaluate(storage_samples("smart_passed", 0, "/dev/sda", "win_smartctl"), [], now=1)
    assert kinds(events) == [("winstorage.health_raised", "critical")]
    fresh = ThresholdEngine()
    fresh.seed([e.model_dump() for e in events])
    assert fresh.evaluate(storage_samples("smart_passed", 0, "/dev/sda", "win_smartctl"), [], now=2) == []
    assert kinds(fresh.evaluate(storage_samples("smart_passed", 1, "/dev/sda", "win_smartctl"), [], now=3)) == [
        ("winstorage.health_cleared", "info")]


def test_agent_cycle_carries_samples_and_events(tmp_path):
    cfg = Config(data_dir=tmp_path, sysfs=tmp_path / "sys", procfs=tmp_path / "proc")
    seam = seam_for(CIM["degraded_pool"], results=[CommandResult(0, "x")] * 4)
    agent = Agent(cfg, seam, platform="windows")
    agent.collectors = [c for c in agent.collectors if c.id == "win_storage"]
    agent.seeded = True
    batch = agent.collect_once()
    assert any(e.kind == "winstorage.health_raised" and "Tank" in e.title for e in batch.events)
    assert next(s for s in batch.sources if s.source == "win_storage").available


def test_empty_disk_list_is_unavailable_with_a_reason_at_collect_too():
    c = WinStorageCollector(seam=seam_for({"MSFT_PhysicalDisk": []}))
    ok_, reason = c.detect()
    assert ok_ is False and "no physical disks" in reason
    with pytest.raises(SeamError, match="no physical disks"):
        c.collect()


def test_failed_pool_and_virtual_disk_queries_are_visible_unknowns_with_reasons():
    classes = {"MSFT_PhysicalDisk": CIM["healthy"]["MSFT_PhysicalDisk"]}  # pool and virtual disk raise SeamError
    samples = WinStorageCollector(seam=seam_for(classes)).collect()
    (pool,) = find(samples, "pool_health")
    (vdisk,) = find(samples, "virtual_disk_health")
    for s, cls in ((pool, "MSFT_StoragePool"), (vdisk, "MSFT_VirtualDisk")):
        assert s.value is None and s.labels["health"] == "Unknown"
        assert cls in s.labels["reason"] and "query failed" in s.labels["reason"]


def test_successful_queries_carry_no_failure_sample():
    samples = storage("healthy").collect()
    assert not [s for s in samples if "reason" in s.labels]
