"""ZFS pool state from kstat: collector, absence, and the shared summary outputs."""

from __future__ import annotations

import dataclasses
import time

from fastapi.testclient import TestClient
from test_ha_discovery import FakeBroker, make_config, make_publisher
from test_orion import H, cfg, key, sample
from test_prometheus import parse

from hostwatch.agent import Agent
from hostwatch.collectors.zfs import ZfsCollector
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.integrations import orion, ui_status
from hostwatch.integrations.summary import build_host_summary
from hostwatch.schema import Batch, SourceStatus
from hostwatch.store import Store


def kstat(procfs, pool, state):
    d = procfs / "spl" / "kstat" / "zfs" / pool
    d.mkdir(parents=True, exist_ok=True)
    (d / "state").write_text(state + "\n")


def agent_batch(tmp_path, pools, md=False):
    """Run a real agent over fake trees and return its batch."""
    sysfs, procfs, data = tmp_path / "sys", tmp_path / "proc", tmp_path / "data"
    for d in (sysfs, procfs, data):
        d.mkdir(exist_ok=True)
    for name, state in pools.items():
        kstat(procfs, name, state)
    if md:
        (procfs / "mdstat").write_text("Personalities : [raid1]\nmd0 : active raid1 sda1[0] sdb1[1]\n")
        m = sysfs / "block" / "md0" / "md"
        m.mkdir(parents=True)
        for f, v in (("degraded", "0"), ("raid_disks", "2"), ("mismatch_cnt", "0"), ("array_state", "clean"),
                     ("sync_action", "idle"), ("level", "raid1")):
            (m / f).write_text(v + "\n")
    agent = Agent(Config(procfs=procfs, sysfs=sysfs, data_dir=data, ingest_token="x" * 32, host_name=H,
                         journal=tmp_path / "j", journal_volatile=tmp_path / "jv", pstore=tmp_path / "p",
                         scrutiny_url=""))
    return agent.collect_once()


def ingest(store, batch):
    store.ingest_batch(batch.model_copy(update={"host": H, "sent_at": time.time()}))
    return build_host_summary(store, H, time.time())


def pool_by_name(s):
    return {c.labels["pool"]: c for c in s.pools}


def test_states_map_through_summary_and_orion(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    s = ingest(store, agent_batch(tmp_path, {"Apps": "ONLINE", "Stash": "DEGRADED", "Vault": "FAULTED",
                                              "tank": "UNAVAIL", "tank2": "SUSPENDED", "odd": "WEIRD"}))
    p = pool_by_name(s)
    assert [p[n].state for n in ("Apps", "Stash", "Vault", "tank", "tank2")] == \
        ["ok", "critical", "critical", "critical", "critical"]
    assert p["odd"].state == "unknown" and p["odd"].status is None and p["odd"].value is None
    assert "pools" not in s.not_present
    assert s.overall_status == 2
    doc = orion.group_document(s, "pools")
    assert doc["pools_status"] == 2 and doc["pool_apps_health"] == 0.0 and doc["pool_apps_status"] == 0
    assert doc["pool_stash_status"] == 2 and doc["pool_odd_available"] == 0
    assert "pool_odd_health" not in doc


def test_online_pool_is_ok_everywhere(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    config = dataclasses.replace(cfg(tmp_path), prometheus_enabled=True)
    client = TestClient(create_app(config, store))
    s = ingest(store, agent_batch(tmp_path, {"Apps": "ONLINE"}))
    assert [c.state for c in s.pools] == ["ok"] and "pools" not in s.unmeasured
    good = key(store, "read:metrics")
    doc = client.get(f"/api/v1/orion/hosts/{H}/pools", headers=good).json()
    assert doc["pools_available"] == 1 and doc["pools_status"] == 0
    by = {(n, tuple(sorted(lbl.items()))): v for n, lbl, v in parse(client.get("/metrics", headers=good).text)}
    assert by[("hostwatch_pool_status", (("host", H), ("pool", "Apps")))] == 0.0
    ui = ui_status.host_document(s)
    assert ui["pools"][0]["state"] == "ok" and ui["pools"][0]["name"] == "pool.Apps"


def test_degraded_pool_in_prometheus_ha_and_ui(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    config = dataclasses.replace(cfg(tmp_path), prometheus_enabled=True)
    client = TestClient(create_app(config, store))
    s = ingest(store, agent_batch(tmp_path, {"Stash": "DEGRADED"}))
    good = key(store, "read:metrics")
    by = {(n, tuple(sorted(lbl.items()))): v for n, lbl, v in parse(client.get("/metrics", headers=good).text)}
    assert by[("hostwatch_pool_status", (("host", H), ("pool", "Stash")))] == 2.0
    assert ui_status.host_document(s)["pools"][0]["state"] == "critical"
    broker = FakeBroker()
    pub, _ = make_publisher(make_config(tmp_path), store, broker)
    assert pub.tick() is True
    assert any("pool_stash" in t for t in broker.retained)


def test_no_zfs_directory_reports_present_false(tmp_path):
    batch = agent_batch(tmp_path, {})
    st = {x.source: x for x in batch.sources}["zfs"]
    assert st.available is False and st.present is False
    store = Store(tmp_path / "db.sqlite")
    s = ingest(store, batch)
    assert "pools" in s.not_present and s.pools == []
    assert orion.group_document(s, "pools")["pools_present"] == 0
    assert ui_status.host_document(s)["pools"] == []


def test_empty_zfs_directory_is_absent(fs):
    sysfs, procfs, _ = fs
    (procfs / "spl" / "kstat" / "zfs").mkdir(parents=True)
    assert ZfsCollector(sysfs, procfs).is_absent() is True


def test_unreadable_proc_is_not_absent(tmp_path):
    missing = tmp_path / "nope"
    assert ZfsCollector(tmp_path, missing).is_absent() is False


def test_unreadable_state_file_is_unavailable_not_zero(fs, monkeypatch, tmp_path):
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
    store = Store(tmp_path / "db.sqlite")
    store.ingest_batch(Batch(agent_version="t", host=H, platform="x", sent_at=time.time(),
                             sources=[SourceStatus(source="cpu", available=True),
                                      SourceStatus(source="zfs", available=True)],
                             samples=[smp]))
    s = build_host_summary(store, H, time.time())
    assert s.pools[0].value is None and s.pools[0].status is None and "pools" in s.unmeasured
    assert s.overall_status >= 1


def test_host_with_md_and_zfs_shows_both(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    s = ingest(store, agent_batch(tmp_path, {"Apps": "ONLINE"}, md=True))
    assert [c.state for c in s.md_arrays] == ["ok"] and [c.state for c in s.pools] == ["ok"]
    assert "raid" not in s.not_present and "pools" not in s.not_present
    doc = orion.summary_document(s)
    assert doc["raid_status"] == 0 and doc["pools_status"] == 0 and "md_md0_status" in doc
    ui = ui_status.host_document(s)
    assert ui["raid"][0]["state"] == "ok" and ui["pools"][0]["state"] == "ok"


def test_host_that_never_reported_zfs_does_not_expect_pools(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    store.ingest_batch(Batch(agent_version="t", host=H, platform="x", sent_at=time.time(),
                             sources=[SourceStatus(source="cpu", available=True)],
                             samples=[sample("cpu", "utilization_pct", 1.0)]))
    s = build_host_summary(store, H, time.time())
    assert "pools" not in s.unmeasured and "pools" not in s.not_present
    assert ui_status.host_document(s)["pools"][0]["value"] is None
