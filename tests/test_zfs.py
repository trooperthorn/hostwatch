"""ZFS pool state from kstat: collector, absence, and the source status the agent reports."""

from __future__ import annotations

from hostwatch.agent import Agent
from hostwatch.collectors.zfs import ZfsCollector
from hostwatch.config import Config


def kstat(procfs, pool, state):
    d = procfs / "spl" / "kstat" / "zfs" / pool
    d.mkdir(parents=True, exist_ok=True)
    (d / "state").write_text(f"{state}\n")


def agent_samples(tmp_path, pools):
    """Run a real agent over fake trees and return its samples and source statuses."""
    sysfs, procfs, data = tmp_path / "sys", tmp_path / "proc", tmp_path / "data"
    for d in (sysfs, procfs, data):
        d.mkdir(exist_ok=True)
    for name, state in pools.items():
        kstat(procfs, name, state)
    agent = Agent(Config(procfs=procfs, sysfs=sysfs, data_dir=data, ingest_key="k", host_name="h1",
                         observe_url="http://observe.test", journal=tmp_path / "j",
                         journal_volatile=tmp_path / "jv", pstore=tmp_path / "p", scrutiny_url=""))
    samples = agent.collect_samples()
    return samples, agent.status


def test_every_pool_is_reported_with_its_state_text(tmp_path):
    samples, status = agent_samples(tmp_path, {"Apps": "ONLINE", "Stash": "DEGRADED", "odd": "WEIRD"})
    states = {s.labels["pool"]: s.labels.get("state") for s in samples if s.source == "zfs"}
    assert set(states) == {"Apps", "Stash", "odd"}
    assert status["zfs"].available is True and status["zfs"].present is True


def test_no_zfs_directory_reports_present_false(tmp_path):
    samples, status = agent_samples(tmp_path, {})
    st = status["zfs"]
    assert st.available is False and st.present is False
    assert [s for s in samples if s.source == "zfs"] == []


def test_zfs_is_a_storage_health_source_and_watched_for_events():
    c = ZfsCollector(None, None)
    assert c.tier == "storage_health" and c.event_watch is True


def test_empty_zfs_directory_is_absent(fs):
    sysfs, procfs, _ = fs
    (procfs / "spl" / "kstat" / "zfs").mkdir(parents=True)
    assert ZfsCollector(sysfs, procfs).is_absent() is True


def test_unreadable_proc_is_not_absent(tmp_path):
    missing = tmp_path / "nope"
    assert ZfsCollector(tmp_path, missing).is_absent() is False


def test_unreadable_state_file_is_unavailable_not_zero(fs, monkeypatch):
    sysfs, procfs, _ = fs
    kstat(procfs, "Apps", "ONLINE")
    real = type(procfs).read_text

    def deny(self, *a, **k):
        if self.name == "state":
            raise PermissionError("denied")
        return real(self, *a, **k)

    monkeypatch.setattr(type(procfs), "read_text", deny)
    c = ZfsCollector(sysfs, procfs)
    assert c.detect()[0] is True and c.is_absent() is False
    [smp] = c.collect()
    assert smp.value is None and smp.labels["pool"] == "Apps"
