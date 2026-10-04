"""Windows CPU and memory collectors: fake counter sequences only, no real CIM query is ever made."""

from __future__ import annotations

import pytest
from fakes_windows import FakeCommandRunner, FakeEventLogReader, FakePipeStatusReader

from hostwatch.collectors import build_collectors
from hostwatch.collectors.cpu import CpuCollector
from hostwatch.collectors.memory import MemoryCollector
from hostwatch.collectors.win_cpu import WinCpuCollector
from hostwatch.collectors.win_memory import WinMemoryCollector
from hostwatch.config import Config
from hostwatch.windows import SeamError, WindowsSeam


class SequenceCim:
    """Answers each class from a list of results, one per query, repeating the last one."""

    def __init__(self, classes):
        self.classes, self.calls = classes, []

    def query(self, class_name, properties=None, namespace=None):
        self.calls.append(class_name)
        if class_name not in self.classes:
            raise SeamError(f"no such class: {class_name}")
        seq = self.classes[class_name]
        result = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(result, Exception):
            raise result
        return result


def seam_for(classes) -> WindowsSeam:
    return WindowsSeam(events=FakeEventLogReader({}), cim=SequenceCim(classes),
                       pipe=FakePipeStatusReader({}), runner=FakeCommandRunner())


def cpu_rows(idle, stamp, extra=True):
    rows = [{"Name": "_Total", "PercentIdleTime": idle, "Timestamp_Sys100NS": stamp}]
    if extra:
        rows.insert(0, {"Name": "0", "PercentIdleTime": 1, "Timestamp_Sys100NS": 1})
    return rows


def cpu_collector(readings):
    seq = [cpu_rows(i, t) for i, t in readings]
    return WinCpuCollector(seam=seam_for({"Win32_PerfRawData_PerfOS_Processor": seq}))


def test_first_call_is_empty_then_utilization_follows():
    c = cpu_collector([(1000, 10_000), (1750, 20_000), (1750, 30_000)])
    assert c.collect() == []
    [s] = c.collect()
    assert (s.source, s.metric, s.unit, s.value) == ("cpu", "utilization_pct", "%", 92.5)
    [s] = c.collect()
    assert s.value == 100.0


def test_string_counters_from_powershell_json_are_accepted():
    c = cpu_collector([("1000", "10000"), ("1500", "20000")])
    c.collect()
    assert c.collect()[0].value == 95.0


def test_counter_wrap_gives_nothing_then_a_fresh_baseline():
    top = 2**64 - 100
    c = cpu_collector([(top, top), (50, 50), (150, 250)])
    assert c.collect() == []
    assert c.collect() == []  # wrapped: no guessed value
    [s] = c.collect()  # the wrap reading became the new baseline
    assert s.value == 50.0


def test_stalled_timestamp_gives_nothing():
    c = cpu_collector([(10, 100), (10, 100)])
    c.collect()
    assert c.collect() == []


def test_idle_counter_going_backwards_alone_gives_nothing():
    c = cpu_collector([(500, 100), (400, 200)])
    c.collect()
    assert c.collect() == []


def test_missing_total_or_bad_counter_is_unavailable_with_a_reason():
    seam = seam_for({"Win32_PerfRawData_PerfOS_Processor": [[{"Name": "0", "PercentIdleTime": 1,
                                                              "Timestamp_Sys100NS": 1}]]})
    ok, reason = WinCpuCollector(seam=seam).detect()
    assert not ok and "_Total" in reason
    bad = seam_for({"Win32_PerfRawData_PerfOS_Processor": [[{"Name": "_Total", "PercentIdleTime": None,
                                                             "Timestamp_Sys100NS": 5}]]})
    ok, reason = WinCpuCollector(seam=bad).detect()
    assert not ok and "unusable" in reason
    assert WinCpuCollector().detect() == (False, "no Windows seam")


def test_seam_failure_in_collect_propagates_for_the_agent_to_report():
    c = WinCpuCollector(seam=seam_for({"Win32_PerfRawData_PerfOS_Processor": [[]]}))
    with pytest.raises(SeamError):
        c.collect()


MEM_CLASSES = {
    "Win32_OperatingSystem": [[{"TotalVisibleMemorySize": 16_000_000}]],
    "Win32_PerfFormattedData_PerfOS_Memory": [[{"AvailableBytes": "8000000000", "CommitLimit": 20_000_000_000,
                                                "CommittedBytes": 9_000_000_000}]],
}


def test_memory_reports_bytes():
    c = WinMemoryCollector(seam=seam_for({k: [list(v[0])] for k, v in MEM_CLASSES.items()}))
    assert c.detect() == (True, "")
    got = {s.metric: (s.value, s.unit) for s in c.collect()}
    assert got == {"mem_total": (16_000_000 * 1024, "B"), "mem_available": (8_000_000_000, "B"),
                   "commit_limit": (20_000_000_000, "B"), "commit_used": (9_000_000_000, "B")}
    assert all(s.source == "memory" for s in c.collect())


def test_memory_omits_what_the_host_does_not_report():
    classes = {"Win32_OperatingSystem": [[{"TotalVisibleMemorySize": 100}]],
               "Win32_PerfFormattedData_PerfOS_Memory": [[{"AvailableBytes": None}]]}
    assert [s.metric for s in WinMemoryCollector(seam=seam_for(classes)).collect()] == ["mem_total"]


def test_memory_without_rows_is_unavailable():
    classes = {"Win32_OperatingSystem": [[]], "Win32_PerfFormattedData_PerfOS_Memory": [[]]}
    ok, reason = WinMemoryCollector(seam=seam_for(classes)).detect()
    assert not ok and "no rows" in reason
    assert WinMemoryCollector().detect() == (False, "no Windows seam")


def test_metric_names_and_ids_match_the_linux_collectors(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "stat").write_text("cpu  100 0 100 800 0 0 0 0\n")
    (proc / "loadavg").write_text("0.1 0.2 0.3 1/2 3\n")
    (proc / "meminfo").write_text("MemTotal: 100 kB\nMemAvailable: 50 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
    lin_cpu, lin_mem = CpuCollector(tmp_path / "sys", proc), MemoryCollector(tmp_path / "sys", proc)
    lin_cpu.collect()
    (proc / "stat").write_text("cpu  200 0 200 1600 0 0 0 0\n")
    linux_cpu = {s.metric for s in lin_cpu.collect()}
    linux_mem = {s.metric for s in lin_mem.collect()}
    win_cpu = cpu_collector([(0, 10), (5, 20)])
    win_cpu.collect()
    win_names = {s.metric for s in win_cpu.collect()}
    win_mem = WinMemoryCollector(seam=seam_for({k: [list(v[0])] for k, v in MEM_CLASSES.items()}))
    mem_names = {s.metric for s in win_mem.collect()}
    assert win_names <= linux_cpu and "utilization_pct" in win_names
    assert {"mem_total", "mem_available"} <= mem_names and {"mem_total", "mem_available"} <= linux_mem
    assert (WinCpuCollector.id, WinMemoryCollector.id) == (CpuCollector.id, MemoryCollector.id)


def test_registered_only_on_windows(tmp_path):
    cfg = Config(data_dir=tmp_path, sysfs=tmp_path / "sys", procfs=tmp_path / "proc")
    seam = seam_for({})
    win = build_collectors(cfg, seam, platform="windows")
    assert [type(c) for c in win[:2]] == [WinCpuCollector, WinMemoryCollector]
    assert len({c.id for c in win}) == len(win)
    assert all(c.seam is seam for c in win)
    for plat in ("x86", "rpi", "aarch64"):
        lin = build_collectors(cfg, platform=plat)
        assert [type(c) for c in lin[:2]] == [CpuCollector, MemoryCollector]
        assert not any(isinstance(c, (WinCpuCollector, WinMemoryCollector)) for c in lin)
