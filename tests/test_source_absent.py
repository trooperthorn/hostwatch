"""Sources that are absent by design are told apart from sources that cannot be read."""

from __future__ import annotations

import dataclasses
import os
import sqlite3
import sys
import time

import pytest
from fastapi.testclient import TestClient
from test_ha_discovery import FakeBroker, make_config, make_publisher
from test_orion import ALL, H, cfg, key, sample
from test_prometheus import parse
from test_store_migration import make_phase1

from hostwatch.agent import Agent
from hostwatch.collectors.hwmon import HwmonCollector
from hostwatch.collectors.mdraid import MdRaidCollector
from hostwatch.collectors.rapl import RaplCollector
from hostwatch.collectors.scrutiny import ScrutinyCollector
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.integrations import orion
from hostwatch.integrations.summary import build_host_summary
from hostwatch.schema import Batch, SourceStatus
from hostwatch.store import Store


def seed_zfs_host(store, host=H, md_present=True, md_reason="no md arrays"):
    """A healthy host whose agent reports mdraid as unavailable, present or not."""
    samples = [sample("cpu", "utilization_pct", 12.5),
               sample("memory", "mem_total", 8000.0), sample("memory", "mem_available", 6000.0),
               sample("rapl", "watts", 20.0, zone="r0", domain="package-0"),
               sample("hwmon", "temp", 45.0, chip="k10temp", sensor="Tctl"),
               sample("scrutiny", "device_status", 0, wwn="w1", device="sda", model="m")]
    sources = [SourceStatus(source=n, available=True) for n in ALL if n != "mdraid"]
    sources.append(SourceStatus(source="mdraid", available=False, reason=md_reason, present=md_present))
    store.ingest_batch(Batch(agent_version="t", host=host, platform="x86", sent_at=time.time(),
                             sources=sources, samples=samples))


def test_old_style_source_status_is_present():
    assert SourceStatus(source="mdraid", available=False, reason="x").present is True
    assert SourceStatus.model_validate({"source": "cpu", "available": True}).present is True


def test_not_present_raid_is_ok_not_warning(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    config = dataclasses.replace(cfg(tmp_path), prometheus_enabled=True)
    client = TestClient(create_app(config, store))
    seed_zfs_host(store, md_present=False)
    s = build_host_summary(store, H, time.time())
    assert s.status == 0 and s.overall_status == 0 and s.unmeasured == [] and s.not_present == ["raid"]
    good = key(store, "read:metrics")
    doc = client.get(f"/api/v1/orion/hosts/{H}/summary", headers=good).json()
    assert doc["overall_status"] == 0 and doc["overall_unmeasured"] == 0 and doc["overall_not_present"] == 1
    assert doc["raid_present"] == 0 and doc["raid_status"] == 0 and doc["raid_reason"] == "not present"
    assert doc["source_mdraid_present"] == 0 and doc["source_mdraid_status"] == 0
    raid = client.get(f"/api/v1/orion/hosts/{H}/raid", headers=good).json()
    assert raid["raid_present"] == 0 and raid["raid_available"] == 0 and raid["raid_status"] == 0
    by = {(n, tuple(sorted(lbl.items()))): v for n, lbl, v in parse(client.get("/metrics", headers=good).text)}
    assert by[("hostwatch_host_status", (("host", H),))] == 0.0
    assert by[("hostwatch_source_present", (("host", H), ("source", "mdraid")))] == 0.0
    assert by[("hostwatch_source_present", (("host", H), ("source", "cpu")))] == 1.0
    # hostwatch_source_up keeps its meaning: 0 because the source is not reporting.
    assert by[("hostwatch_source_up", (("host", H), ("source", "mdraid")))] == 0.0


def test_present_but_unavailable_raid_is_still_unmeasured(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    seed_zfs_host(store, md_present=True, md_reason="could not read /proc/mdstat")
    s = build_host_summary(store, H, time.time())
    assert s.overall_status == 1 and s.unmeasured == ["raid"] and s.not_present == []
    assert orion.summary_document(s)["raid_status"] == 1


def test_stale_not_present_report_is_unmeasured(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    seed_zfs_host(store, md_present=False)
    s = build_host_summary(store, H, time.time() + 1000)
    assert "raid" not in s.not_present
    assert "raid" in s.unmeasured


def test_ha_creates_no_raid_entity_when_not_present(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    seed_zfs_host(store, md_present=False)
    broker = FakeBroker()
    pub, _ = make_publisher(make_config(tmp_path), store, broker)
    assert pub.tick() is True
    topics = list(broker.retained)
    assert not any("/md_" in t or "source_mdraid" in t for t in topics)
    assert any("source_cpu_up" in t for t in topics)


def test_ha_retires_entity_of_source_that_became_not_present(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    broker = FakeBroker()
    pub, _ = make_publisher(make_config(tmp_path), store, broker)
    store.ingest_batch(Batch(agent_version="t", host=H, platform="x86", sent_at=time.time(),
                             sources=[SourceStatus(source="cpu", available=True),
                                      SourceStatus(source="mdraid", available=True)],
                             samples=[sample("mdraid", "degraded", 0, array="md0")]))
    assert pub.tick() is True
    topic = "homeassistant/binary_sensor/hostwatch_h1/source_mdraid_up/config"
    assert broker.retained[topic] != ""
    # A source that vanishes is critical (see test_source_disappeared); only a deliberate removal retires it.
    assert store.forget_source(H, "mdraid")
    store.ingest_batch(Batch(agent_version="t", host=H, platform="x86", sent_at=time.time() + 1,
                             sources=[SourceStatus(source="cpu", available=True),
                                      SourceStatus(source="mdraid", available=False, present=False)],
                             samples=[]))
    assert pub.tick() is True
    assert broker.retained[topic] == ""


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
    agent = Agent(Config(procfs=procfs, sysfs=sysfs, data_dir=data, ingest_token="x" * 32, host_name="h",
                         journal=tmp_path / "j", journal_volatile=tmp_path / "jv", pstore=tmp_path / "p",
                         scrutiny_url=""))
    agent.detect()
    assert agent.status["mdraid"].present is False and agent.status["mdraid"].available is False
    assert agent.status["rapl"].present is False
    assert agent.status["hwmon"].present is True  # /sys/class/hwmon does not exist: unknown, not absent
    assert agent.status["cpu"].present is True


# ---- store migration
def test_migration_from_previous_version_keeps_rows(tmp_path):
    p = tmp_path / "db.sqlite"
    store = Store(p)
    seed_zfs_host(store, md_present=False)
    del store
    db = sqlite3.connect(p)
    db.execute("ALTER TABLE sources DROP COLUMN present")
    db.execute("DROP TABLE source_seen")
    db.execute("PRAGMA user_version = 5")
    db.commit()
    db.close()
    upgraded = Store(p)
    rows = {r["source"]: r for r in upgraded.sources()}
    assert len(rows) == len(ALL) and all(r["present"] == 1 for r in rows.values())
    seed_zfs_host(upgraded, md_present=False)
    assert {r["source"]: r["present"] for r in Store(p).sources()}["mdraid"] == 0


def test_phase1_database_gets_present_column_defaulting_to_present(tmp_path):
    p = tmp_path / "db.sqlite"
    make_phase1(p)
    assert Store(p).sources()[0]["present"] == 1
