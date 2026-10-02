"""Unmeasured groups raise the overall status to warning, no data is critical, Orion host keys are stable."""

from __future__ import annotations

import time

from test_orion import ALL, H, key, sample, seed
from test_prometheus import make, parse

from hostwatch.integrations.orion import host_keys
from hostwatch.integrations.summary import build_host_summary
from hostwatch.schema import Batch, SourceStatus



def seed_without_raid(store, host=H):
    names = [n for n in ALL if n != "mdraid"]
    samples = [sample("cpu", "utilization_pct", 12.5),
               sample("memory", "mem_total", 8000.0), sample("memory", "mem_available", 6000.0),
               sample("rapl", "watts", 20.0, zone="r0", domain="package-0"),
               sample("hwmon", "temp", 45.0, chip="k10temp", sensor="Tctl"),
               sample("scrutiny", "device_status", 0, wwn="w1", device="sda", model="m")]
    store.ingest_batch(Batch(agent_version="t", host=host, platform="x86", sent_at=time.time(),
                             sources=[SourceStatus(source=n, available=True, reason="") for n in names],
                             samples=samples))


def test_never_reported_raid_is_warning_everywhere(tmp_path):
    client, store = make(tmp_path, True)
    seed_without_raid(store)
    s = build_host_summary(store, H, time.time())
    assert s.status == 0 and s.overall_status == 1 and s.unmeasured == ["raid"]
    good = key(store, "read:metrics")
    doc = client.get(f"/api/v1/orion/hosts/{H}/summary", headers=good).json()
    assert doc["overall_status"] == 1 and doc["overall_unmeasured"] >= 1
    assert client.get("/api/v1/orion/hosts", headers=good).json()["host_h1_status"] == 1
    samples = parse(client.get("/metrics", headers=good).text)
    by = {(n, tuple(sorted(l.items()))): v for n, l, v in samples}
    assert by[("hostwatch_host_status", (("host", H),))] == 1.0
    assert by[("hostwatch_host_unmeasured_groups", (("host", H),))] >= 1.0


def test_fully_measured_host_has_zero_unmeasured(tmp_path):
    client, store = make(tmp_path, True)
    seed(store)
    doc = client.get(f"/api/v1/orion/hosts/{H}/summary", headers=key(store, "read:metrics")).json()
    assert doc["overall_status"] == 0 and doc["overall_unmeasured"] == 0


def test_host_with_no_data_is_critical(tmp_path):
    client, store = make(tmp_path, True)
    s = build_host_summary(store, "ghost", time.time())
    assert s.overall_status == 2 and s.overall_reason == "no data"
    from hostwatch.integrations import orion, prometheus
    assert orion.summary_document(s)["overall_status"] == 2
    assert orion.summary_document(s)["overall_reason"] == "no data"
    assert 'hostwatch_host_status{host="ghost"} 2.0' in prometheus.render([s])


def test_first_host_key_is_stable_when_a_second_joins(tmp_path):
    client, store = make(tmp_path, True)
    good = key(store, "read:metrics")
    seed(store)
    before = client.get("/api/v1/orion/hosts", headers=good).json()
    store.ingest_batch(Batch(agent_version="t", host="a-first", platform="x86", sent_at=time.time(),
                             sources=[SourceStatus(source="cpu", available=True, reason="")],
                             samples=[sample("cpu", "utilization_pct", 1.0)]))
    after = client.get("/api/v1/orion/hosts", headers=good).json()
    assert after["host_count"] == 2
    assert after["host_h1_name"] == before["host_h1_name"] == H
    assert after["host_a_first_name"] == "a-first"


def test_colliding_host_slugs_get_distinct_keys():
    keys = host_keys(["Web-1", "web_1", "solo"])
    assert keys["solo"] == "solo" and keys["Web-1"] != keys["web_1"]
    assert all(k.startswith("web_1_") for k in (keys["Web-1"], keys["web_1"]))
    assert host_keys(["Web-1", "web_1"])["Web-1"] == keys["Web-1"]
