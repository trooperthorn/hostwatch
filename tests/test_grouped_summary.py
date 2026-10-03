"""Grouped summary: group membership, aggregate status per group, fans, and the grouped endpoint."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.integrations.summary import (GROUP_IDS, build_host_summary, group_documents, grouped_document,
                                            worst_key)
from hostwatch.schema import Batch, Sample, SourceStatus
from hostwatch.store import Store

NOW = 10_000.0
H = "h1"


class FakeStore:
    def __init__(self, rows, sources):
        self._rows, self._sources = rows, sources

    def latest(self, host=None):
        return self._rows

    def sources(self):
        return self._sources

    def events(self, **kw):
        return []


def row(source, metric, value, **labels):
    return {"host": H, "source": source, "metric": metric, "labels": labels, "value": value, "unit": "",
            "ts": NOW - 5}


def src(name, available=True, present=1, reason=""):
    return {"host": H, "source": name, "available": int(available), "present": present, "reason": reason,
            "updated": NOW - 5}


def groups_of(rows, sources, **opts):
    s = build_host_summary(FakeStore(rows, sources), H, NOW, **opts)
    return {g["id"]: g for g in group_documents(s)}, s


def mediain_rows():
    rows = [row("cpu", "utilization_pct", 10.0), row("memory", "mem_total", 8000.0),
            row("memory", "mem_available", 6000.0),
            row("rapl", "watts", 20.0, zone="r0", domain="package-0"),
            row("hwmon", "temp", 45.0, chip="coretemp", sensor="Package id 0"),
            row("hwmon", "temp", 101.0, chip="nct6779", sensor="AUXTIN0"),
            row("mdraid", "degraded", 0, array="md0"), row("mdraid", "sync_action", 1, array="md0", action="idle"),
            row("scrutiny", "device_status", 0, wwn="w1", device="sda", model="m")]
    for i, rpm in enumerate((900, 1100, 800, 700, 0), start=1):
        rows.append(row("hwmon", "fan", float(rpm), chip="nct6779", sensor=f"fan{i}"))
    sources = [src(n) for n in ("cpu", "memory", "rapl", "hwmon", "mdraid", "scrutiny")]
    sources += [src("zfs", False, 0, "no pools"), src("nut", False, 0, "not configured")]
    return rows, sources


def test_mediain_shape_groups_and_fans():
    rows, sources = mediain_rows()
    groups, _ = groups_of(rows, sources)
    assert list(groups) == ["cpu", "memory", "power", "temperatures", "fans", "raid", "disks", "alerts", "sources"]
    assert "pools" not in groups and "ups" not in groups
    assert [g for g in groups] == [g for g in GROUP_IDS if g in groups]
    fans = groups["fans"]
    assert fans["status"] == "good" and fans["icon"] == "propeller"
    fan5 = [m for m in fans["members"] if m["label"].endswith("fan5")][0]
    assert fan5["value"] == 0.0 and fan5["status"] == "good" and fan5["reason"].startswith("informational")
    assert "1 informational" in fans["summary"]
    assert groups["temperatures"]["status"] == "good"


def test_required_fan_at_zero_rpm_is_critical():
    rows, sources = mediain_rows()
    groups, s = groups_of(rows, sources, required_fans=("nct6779:fan5",))
    assert groups["fans"]["status"] == "critical"
    assert "fan5" in groups["fans"]["summary"]
    assert s.overall_status == 2
    other, _ = groups_of(rows, sources, required_fans=("nct6779:fan1",))
    assert other["fans"]["status"] == "good"


def truenas_rows():
    rows = [row("cpu", "utilization_pct", 5.0), row("memory", "mem_total", 8000.0),
            row("memory", "mem_available", 6000.0),
            row("hwmon", "temp", 40.0, chip="k10temp", sensor="Tctl"),
            row("zfs", "pool_state", 0, pool="tank", state="ONLINE"),
            row("truenas", "pool_health", 1.0, pool="tank", status="ONLINE", reason="sdm has checksum errors")]
    for i in range(3):
        rows.append(row("hwmon", "temp", 33.0 + i, chip="drivetemp", sensor="temp1"))
        rows.append(row("scrutiny", "device_status", 0, wwn=f"w{i}", device=f"sd{i}", model="m"))
    sources = [src(n) for n in ("cpu", "memory", "hwmon", "zfs", "truenas", "scrutiny")]
    sources += [src("mdraid", False, 0, "no md"), src("rapl", False, 1, "root only")]
    return rows, sources


def test_truenas_shape_pools_warning_names_disk_and_disks_good():
    rows, sources = truenas_rows()
    groups, _ = groups_of(rows, sources)
    assert groups["pools"]["status"] == "warning"
    assert "sdm" in groups["pools"]["summary"]
    assert groups["pools"]["members"][0]["source"] == "zfs+truenas"
    assert groups["disks"]["status"] == "good"
    assert "raid" not in groups and "fans" not in groups
    assert groups["power"]["status"] == "unknown"


def test_group_status_is_worst_member_in_every_group():
    for build in (mediain_rows, truenas_rows):
        rows, sources = build()
        for opts in ({}, {"required_fans": ("nct6779:fan5",)}):
            groups, _ = groups_of(rows, sources, **opts)
            for g in groups.values():
                assert g["status"] == worst_key([m["status"] for m in g["members"]]) or not g["members"]


def test_unknown_only_when_every_member_unknown():
    assert worst_key(["unknown", "good"]) == "good"
    assert worst_key(["unknown", "unknown"]) == "unknown"
    assert worst_key(["good", "warning", "critical", "unknown"]) == "critical"
    assert worst_key([]) == "unknown"


def test_group_member_carries_reading_fields():
    rows, sources = mediain_rows()
    groups, _ = groups_of(rows, sources)
    m = groups["cpu"]["members"][0]
    assert set(m) >= {"value", "unit", "labels", "source", "status", "reason", "ts"}
    assert m["source"] == "cpu" and m["ts"] == NOW - 5 and m["unit"] == "%"


# Endpoint tests.

def build_app(tmp_path):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(cfg, "correct horse battery"))
    return TestClient(create_app(cfg, store), client=("127.0.0.1", 40000)), store


def seed(store, host, degraded=0):
    now = time.time()
    samples = [Sample(source="mdraid", metric="degraded", value=degraded, labels={"array": "md0"}, ts=now),
               Sample(source="cpu", metric="utilization_pct", value=1.0, labels={}, ts=now)]
    store.ingest_batch(Batch(agent_version="t", host=host, platform="x86", sent_at=now,
                             sources=[SourceStatus(source="mdraid", available=True),
                                      SourceStatus(source="cpu", available=True)], samples=samples))


def test_grouped_endpoint_requires_auth(tmp_path):
    client, _ = build_app(tmp_path)
    assert client.get("/api/v1/hosts/summary/grouped").status_code == 401


def test_grouped_endpoint_orders_worst_first_with_banner(tmp_path):
    client, store = build_app(tmp_path)
    seed(store, "aaa-ok")
    seed(store, "bbb-bad", degraded=1)
    client.post("/api/v1/login", json={"username": "alice", "password": "correct horse battery"})
    doc = client.get("/api/v1/hosts/summary/grouped").json()
    statuses = [h["status"] for h in doc["hosts"]]
    assert statuses == sorted(statuses, reverse=True)
    assert doc["hosts"][0]["host"] == "bbb-bad" and doc["hosts"][0]["status_key"] == "critical"
    raid = [g for g in doc["hosts"][0]["groups"] if g["id"] == "raid"][0]
    assert raid["status"] == "critical" and raid["icon"] == "stack-2"
    assert doc["banner"]["host"] == "bbb-bad" and "Critical" in doc["banner"]["text"]
    assert doc["banner"]["counts"]["hosts"]["critical"] == 1
    assert doc["banner"]["counts"]["groups"]["critical"] >= 1


def test_grouped_document_empty_hub():
    doc = grouped_document([], NOW)
    assert doc["hosts"] == [] and doc["banner"]["text"] == "No hosts have reported yet."
