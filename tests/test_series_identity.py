"""Series identity, platform and source presence: the October audit failures hwmon-duplicate-series,
truenas-platform-never-reported, uninstalled-sources-reported-unavailable-present and
startup-false-source-change."""

from __future__ import annotations

import pytest

import hostwatch.agent as agent_module
from hostwatch import otel_map
from hostwatch.agent import Agent, detect_platform
from hostwatch.collectors.hwmon import HwmonCollector
from hostwatch.collectors.rapl import RaplCollector
from hostwatch.config import Config
from hostwatch.model import SourceStatus


def write(root, rel, content):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _chip(sysfs, n, name):
    base = f"class/hwmon/hwmon{n}"
    write(sysfs, f"{base}/name", name + "\n")
    write(sysfs, f"{base}/temp1_input", "40000\n")
    write(sysfs, f"{base}/temp1_label", "Composite\n")
    write(sysfs, f"{base}/temp2_input", "41000\n")
    write(sysfs, f"{base}/temp2_label", "Composite\n")


def _hw_ids(samples):
    return [p.attributes["hw.id"] for p in otel_map.map_samples(samples)]


def test_two_chips_with_the_same_sensor_name_are_two_series(fs):
    sysfs, procfs, _ = fs
    _chip(sysfs, 0, "nvme")
    _chip(sysfs, 1, "nvme")
    ids = _hw_ids(HwmonCollector(sysfs, procfs).collect())
    assert len(ids) == 4 and len(set(ids)) == 4  # two chips, and two inputs that share a label


def test_hwmon_series_id_is_stable_between_cycles(fs):
    sysfs, procfs, _ = fs
    _chip(sysfs, 0, "nvme")
    c = HwmonCollector(sysfs, procfs)
    assert _hw_ids(c.collect()) == _hw_ids(c.collect())


def test_an_old_style_hwmon_sample_keeps_its_chip_and_label_id():
    from hostwatch.model import Sample
    s = Sample(source="hwmon", metric="temp", value=40.0, unit="C", ts=1.0,
               labels={"chip": "coretemp", "sensor": "Package id 0"})
    assert otel_map.map_sample(s)[0].attributes["hw.id"] == "coretemp:Package id 0"


# ---- platform
@pytest.mark.real_platform
def test_truenas_kernel_reports_the_truenas_platform(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_module.sys, "platform", "linux")
    procfs = tmp_path / "proc"
    write(procfs, "version", "Linux version 6.12.15-production+truenas (root@build) (gcc 12.2.0) #1 SMP\n")
    assert detect_platform(tmp_path / "sys", procfs) == "truenas"
    attrs = otel_map.resource_attributes("nas", detect_platform(tmp_path / "sys", procfs), "1")
    assert attrs["observe.platform"] == "truenas"


@pytest.mark.real_platform
def test_a_loopback_truenas_api_reports_the_truenas_platform(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_module.sys, "platform", "linux")
    procfs = tmp_path / "proc"
    write(procfs, "version", "Linux version 6.1.0-debian\n")
    assert detect_platform(tmp_path / "sys", procfs, "wss://127.0.0.1/api/current") == "truenas"
    assert detect_platform(tmp_path / "sys", procfs, "wss://nas.example/api/current") != "truenas"


@pytest.mark.real_platform
def test_an_ordinary_linux_host_is_not_truenas(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_module.sys, "platform", "linux")
    procfs = tmp_path / "proc"
    write(procfs, "version", "Linux version 6.1.0-debian\n")
    assert detect_platform(tmp_path / "sys", procfs) != "truenas"


@pytest.mark.real_platform
def test_the_agent_sends_the_truenas_platform(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_module.sys, "platform", "linux")
    procfs, sysfs, data = tmp_path / "proc", tmp_path / "sys", tmp_path / "data"
    for d in (sysfs, data):
        d.mkdir()
    write(procfs, "version", "Linux version 6.12.15-production+truenas\n")
    agent = Agent(Config(procfs=procfs, sysfs=sysfs, data_dir=data, host_name="nas",
                         journal=tmp_path / "j", journal_volatile=tmp_path / "jv", pstore=tmp_path / "p",
                         rasdaemon_db=tmp_path / "ras.db", scrutiny_url="", truenas_url=""))
    assert agent.platform == "truenas"
    assert agent.resource["observe.platform"] == "truenas"


# ---- presence
def test_rapl_is_absent_when_sysfs_has_no_powercap_directory(fs):
    sysfs, procfs, _ = fs
    (sysfs / "class").mkdir()
    assert RaplCollector(sysfs, procfs).is_absent() is True
    assert RaplCollector(sysfs / "missing", procfs).is_absent() is False  # no /sys/class: unknown


def test_sources_the_host_does_not_have_are_sent_as_present_false(tmp_path):
    sysfs, procfs, data = tmp_path / "sys", tmp_path / "proc", tmp_path / "data"
    for d in (sysfs / "class", procfs, data):
        d.mkdir(parents=True)
    agent = Agent(Config(procfs=procfs, sysfs=sysfs, data_dir=data, host_name="h",
                         journal=tmp_path / "j", journal_volatile=tmp_path / "jv", pstore=tmp_path / "no-pstore",
                         rasdaemon_db=tmp_path / "no-ras.db", scrutiny_url=""))
    agent.detect()
    agent._collect_events()
    for source in ("rapl", "pstore", "rasdaemon"):
        assert agent.status[source].present is False and agent.status[source].available is False, source
    points = otel_map.map_source_status(agent.status.values(), 5.0)
    present = {p.attributes["observe.source"]: p.value for p in points if p.name == "observe.source.present"}
    assert present["rapl"] == present["pstore"] == present["rasdaemon"] == 0.0
    changed = {r.attributes["observe.source"] for r in agent._source_change_logs(6.0)}
    assert not changed & {"rapl", "pstore", "rasdaemon"}


def test_an_unreadable_rasdaemon_database_stays_present(tmp_path):
    from hostwatch.events.rasdaemon import RasdaemonReader
    status, _ = RasdaemonReader(tmp_path).read()  # a directory, not a file
    assert status.available is False and status.present is True


# ---- clean start
def test_a_clean_start_logs_no_source_change_for_the_journal(tmp_path):
    sysfs, procfs, data = tmp_path / "sys", tmp_path / "proc", tmp_path / "data"
    for d in (sysfs, procfs, data, tmp_path / "j"):
        d.mkdir()
    agent = Agent(Config(procfs=procfs, sysfs=sysfs, data_dir=data, host_name="h",
                         journal=tmp_path / "j", journal_volatile=tmp_path / "jv", pstore=tmp_path / "p",
                         rasdaemon_db=tmp_path / "ras.db", scrutiny_url=""))
    watcher = agent.journal_watcher
    watcher.reader = lambda directory, cursor: []
    watcher.has_files = lambda directory: True
    status, _ = agent.journal.read()
    assert status.pending is True
    agent.status["journal"] = status
    assert [r for r in agent._source_change_logs(1.0) if r.attributes["observe.source"] == "journal"] == []
    agent.journal._thread.join()
    status, _ = agent.journal.read()
    assert status.available is True and status.pending is False
    agent.status["journal"] = status
    assert [r for r in agent._source_change_logs(2.0) if r.attributes["observe.source"] == "journal"] == []


def test_a_journal_that_then_fails_is_still_logged(tmp_path):
    agent = Agent(Config(procfs=tmp_path, sysfs=tmp_path, data_dir=tmp_path, host_name="h"))
    agent.status = {"journal": SourceStatus(source="journal", available=False, reason="x", pending=True)}
    assert agent._source_change_logs(1.0) == []
    agent.status = {"journal": SourceStatus(source="journal", available=False, reason="journalctl failed")}
    [change] = agent._source_change_logs(2.0)
    assert change.attributes["observe.source.reason"] == "journalctl failed"
