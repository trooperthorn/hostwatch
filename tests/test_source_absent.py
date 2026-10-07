"""Sources that are absent by design are told apart from sources that cannot be read."""

from __future__ import annotations

import os
import sys

import pytest

from hostwatch.agent import Agent
from hostwatch.collectors.hwmon import HwmonCollector
from hostwatch.collectors.mdraid import MdRaidCollector
from hostwatch.collectors.rapl import RaplCollector
from hostwatch.collectors.scrutiny import ScrutinyCollector
from hostwatch.config import Config
from hostwatch.model import SourceStatus


def test_old_style_source_status_is_present():
    assert SourceStatus(source="mdraid", available=False, reason="x").present is True
    assert SourceStatus.model_validate({"source": "cpu", "available": True}).present is True


# ---- collectors: absence only when positively established
def test_mdraid_absent_when_mdstat_lists_no_arrays(fs):
    sysfs, procfs, w = fs
    w(procfs, "mdstat", "Personalities :\nunused devices: <none>\n")
    assert MdRaidCollector(sysfs, procfs).is_absent() is True


def test_mdraid_absent_when_mdstat_missing_and_proc_readable(fs):
    sysfs, procfs, _ = fs
    assert MdRaidCollector(sysfs, procfs).is_absent() is True


def test_mdraid_with_arrays_listed_is_not_absent(fs):
    sysfs, procfs, w = fs
    w(procfs, "mdstat", "Personalities : [raid1]\nmd0 : active raid1 sda1[0] sdb1[1]\n")
    assert MdRaidCollector(sysfs, procfs).is_absent() is False


def test_mdraid_unreadable_mdstat_is_not_absent(fs, monkeypatch):
    sysfs, procfs, w = fs
    w(procfs, "mdstat", "unused devices: <none>\n")
    real = type(procfs).read_text

    def deny(self, *a, **k):
        if self.name == "mdstat":
            raise PermissionError("denied")
        return real(self, *a, **k)

    monkeypatch.setattr(type(procfs), "read_text", deny)
    assert MdRaidCollector(sysfs, procfs).is_absent() is False


def test_mdraid_missing_procfs_is_not_absent(tmp_path):
    assert MdRaidCollector(tmp_path / "sys", tmp_path / "no-proc").is_absent() is False


def test_rapl_absent_only_when_powercap_readable_and_empty(fs):
    sysfs, procfs, _ = fs
    assert RaplCollector(sysfs, procfs).is_absent() is False  # no powercap directory: unknown
    (sysfs / "class" / "powercap").mkdir(parents=True)
    assert RaplCollector(sysfs, procfs).is_absent() is True


def test_hwmon_absent_only_when_directory_readable_and_empty(fs):
    sysfs, procfs, _ = fs
    assert HwmonCollector(sysfs, procfs).is_absent() is False
    (sysfs / "class" / "hwmon").mkdir(parents=True)
    assert HwmonCollector(sysfs, procfs).is_absent() is True
    (sysfs / "class" / "hwmon" / "hwmon0").mkdir()
    assert HwmonCollector(sysfs, procfs).is_absent() is False


def test_scrutiny_absent_only_when_not_configured(fs):
    sysfs, procfs, _ = fs
    assert ScrutinyCollector(sysfs, procfs, "").is_absent() is True
    assert ScrutinyCollector(sysfs, procfs, "http://x:8080").is_absent() is False


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and a non-root user; intel-rapl:N paths hold a colon")
def test_rapl_unreadable_energy_stays_present_and_unavailable(fs):
    sysfs, procfs, w = fs
    w(sysfs, "class/powercap/intel-rapl:0/energy_uj", "1\n")
    (sysfs / "class/powercap/intel-rapl:0/energy_uj").chmod(0)
    c = RaplCollector(sysfs, procfs)
    ok, reason = c.detect()
    assert not ok and "not readable" in reason
    assert c.is_absent() is False


def test_agent_reports_present_false_only_for_established_absence(tmp_path):
    sysfs, procfs, data = tmp_path / "sys", tmp_path / "proc", tmp_path / "data"
    for d in (sysfs, procfs, data):
        d.mkdir()
    (procfs / "mdstat").write_text("Personalities :\nunused devices: <none>\n")
    (sysfs / "class" / "powercap").mkdir(parents=True)
    agent = Agent(Config(procfs=procfs, sysfs=sysfs, data_dir=data, host_name="h",
                         journal=tmp_path / "j", journal_volatile=tmp_path / "jv", pstore=tmp_path / "p",
                         scrutiny_url=""))
    agent.detect()
    assert agent.status["mdraid"].present is False and agent.status["mdraid"].available is False
    assert agent.status["rapl"].present is False
    assert agent.status["hwmon"].present is True  # /sys/class/hwmon does not exist: unknown, not absent
    assert agent.status["cpu"].present is True
