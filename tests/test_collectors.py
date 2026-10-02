from __future__ import annotations

import json
import sys

import httpx
import pytest

from hostwatch.collectors.cpu import CpuCollector
from hostwatch.collectors.hwmon import HwmonCollector
from hostwatch.collectors.mdraid import MdRaidCollector
from hostwatch.collectors.memory import MemoryCollector
from hostwatch.collectors.rapl import RaplCollector
from hostwatch.collectors.scrutiny import ScrutinyCollector


def by(samples, metric, **labels):
    return [s for s in samples if s.metric == metric and all(s.labels.get(k) == v for k, v in labels.items())]


# ---------------------------------------------------------------- RAPL
def test_rapl_absent(fs):
    sysfs, procfs, _ = fs
    ok, reason = RaplCollector(sysfs, procfs).detect()
    assert not ok and "no intel-rapl" in reason


@pytest.mark.skipif(sys.platform == "win32", reason="intel-rapl:N paths contain a colon, which Windows file names cannot hold")
def test_rapl_first_cycle_emits_nothing_then_watts(fs, monkeypatch):
    sysfs, procfs, w = fs
    z = "class/powercap/intel-rapl:0"
    w(sysfs, f"{z}/name", "package-0")
    w(sysfs, f"{z}/max_energy_range_uj", "262143328850")
    w(sysfs, f"{z}/energy_uj", "1000000")
    c = RaplCollector(sysfs, procfs)
    assert c.detect()[0]
    t = iter([100.0, 110.0])
    monkeypatch.setattr("hostwatch.collectors.rapl.time.monotonic", lambda: next(t))
    assert c.collect() == []
    w(sysfs, f"{z}/energy_uj", str(1000000 + 200_000_000))  # 200 J over 10 s
    (s,) = c.collect()
    assert s.value == 20.0 and s.unit == "W" and s.labels["domain"] == "package-0"


@pytest.mark.skipif(sys.platform == "win32", reason="intel-rapl:N paths contain a colon, which Windows file names cannot hold")
def test_rapl_counter_wrap(fs, monkeypatch):
    sysfs, procfs, w = fs
    z = "class/powercap/intel-rapl:0"
    w(sysfs, f"{z}/name", "package-0")
    w(sysfs, f"{z}/max_energy_range_uj", "1000000000")
    w(sysfs, f"{z}/energy_uj", "999000000")
    c = RaplCollector(sysfs, procfs)
    t = iter([0.0, 1.0])
    monkeypatch.setattr("hostwatch.collectors.rapl.time.monotonic", lambda: next(t))
    c.collect()
    w(sysfs, f"{z}/energy_uj", "4000000")  # wrapped: 1 J + 4 J = 5 J in 1 s
    (s,) = c.collect()
    assert s.value == 5.0


# ---------------------------------------------------------------- md RAID
def _md(w, sysfs, degraded="0", action="idle", completed="none"):
    base = "block/md127/md"
    for k, v in {"level": "raid1", "degraded": degraded, "raid_disks": "2", "mismatch_cnt": "0",
                 "array_state": "clean", "sync_action": action, "sync_completed": completed}.items():
        w(sysfs, f"{base}/{k}", v)


def test_md_healthy(fs):
    sysfs, procfs, w = fs
    _md(w, sysfs)
    c = MdRaidCollector(sysfs, procfs)
    assert c.detect() == (True, "md127")
    out = c.collect()
    assert by(out, "degraded")[0].value == 0
    assert by(out, "array_state")[0].labels["state"] == "clean"
    assert not by(out, "sync_progress_pct")


def test_md_degraded_and_checking(fs):
    sysfs, procfs, w = fs
    _md(w, sysfs, degraded="1", action="check", completed="500 / 2000")
    out = MdRaidCollector(sysfs, procfs).collect()
    assert by(out, "degraded")[0].value == 1
    assert by(out, "sync_action")[0].labels["action"] == "check"
    assert by(out, "sync_progress_pct")[0].value == 25.0


def test_md_absent(fs):
    sysfs, procfs, _ = fs
    assert MdRaidCollector(sysfs, procfs).detect() == (False, "no md arrays")


# ---------------------------------------------------------------- hwmon
def test_hwmon_units_and_labels(fs):
    sysfs, procfs, w = fs
    d = "class/hwmon/hwmon2"
    w(sysfs, f"{d}/name", "nct6779")
    w(sysfs, f"{d}/in0_input", "800")
    w(sysfs, f"{d}/in0_label", "Vcore")
    w(sysfs, f"{d}/fan2_input", "1105")
    w(sysfs, f"{d}/temp1_input", "34000")
    out = HwmonCollector(sysfs, procfs).collect()
    assert by(out, "voltage", sensor="Vcore")[0].value == 0.8
    assert by(out, "fan", sensor="fan2")[0].value == 1105
    assert by(out, "temp", chip="nct6779")[0].value == 34.0


def test_hwmon_unreadable_is_none_not_zero(fs):
    sysfs, procfs, w = fs
    w(sysfs, "class/hwmon/hwmon0/name", "x")
    w(sysfs, "class/hwmon/hwmon0/in1_input", "garbage")
    (s,) = HwmonCollector(sysfs, procfs).collect()
    assert s.value is None


# ---------------------------------------------------------------- CPU / memory
def test_cpu_utilization_and_idle_residency(fs, monkeypatch):
    sysfs, procfs, w = fs
    w(procfs, "stat", "cpu  100 0 100 800 0 0 0 0 0 0\n")
    w(procfs, "loadavg", "0.10 0.20 0.30 1/100 1")
    w(sysfs, "devices/system/cpu/cpu0/cpuidle/state3/name", "C6")
    w(sysfs, "devices/system/cpu/cpu0/cpuidle/state3/time", "0")
    c = CpuCollector(sysfs, procfs)
    t = iter([0.0, 10.0])
    monkeypatch.setattr("hostwatch.collectors.cpu.time.monotonic", lambda: next(t))
    c.collect()
    w(procfs, "stat", "cpu  150 0 150 1700 0 0 0 0 0 0\n")  # 100 busy of 1000
    w(sysfs, "devices/system/cpu/cpu0/cpuidle/state3/time", "8000000")  # 8 s of 10 s
    out = c.collect()
    assert by(out, "utilization_pct")[0].value == 10.0
    assert by(out, "idle_residency_pct", state="C6")[0].value == 80.0


def test_memory_bytes(fs):
    sysfs, procfs, w = fs
    w(procfs, "meminfo", "MemTotal:       16000000 kB\nMemAvailable:   8000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
    out = MemoryCollector(sysfs, procfs).collect()
    assert by(out, "mem_total")[0].value == 16000000 * 1024


# ---------------------------------------------------------------- Scrutiny
SUMMARY = {"success": True, "data": {"summary": {
    "0x50014ee2b5b0e1a1": {"device": {"device_name": "sdc", "model_name": "WDC WD10EFRX-68FYTN0",
                                       "serial_number": "WD-X", "device_status": 0},
                            "smart": {"temp": 31, "power_on_hours": 4696}}}}}


def _mock(monkeypatch, payload=None, exc=None):
    def fake_get(url, timeout):
        if exc:
            raise exc
        return httpx.Response(200, json=payload, request=httpx.Request("GET", url))
    monkeypatch.setattr("hostwatch.collectors.scrutiny.httpx.get", fake_get)


def test_scrutiny_parses_summary(fs, monkeypatch):
    sysfs, procfs, _ = fs
    _mock(monkeypatch, SUMMARY)
    c = ScrutinyCollector(sysfs, procfs, "http://x:8081")
    assert c.detect() == (True, "1 device(s)")
    out = c.collect()
    assert by(out, "device_status", device="sdc")[0].value == 0
    assert by(out, "power_on_hours")[0].value == 4696


def test_scrutiny_unexpected_shape_is_unavailable(fs, monkeypatch):
    sysfs, procfs, _ = fs
    _mock(monkeypatch, {"unexpected": True})
    ok, reason = ScrutinyCollector(sysfs, procfs, "http://x:8081").detect()
    assert not ok and "KeyError" in reason


def test_scrutiny_unconfigured(fs):
    sysfs, procfs, _ = fs
    assert ScrutinyCollector(sysfs, procfs, "").detect() == (False, "HOSTWATCH_SCRUTINY_URL not set")
