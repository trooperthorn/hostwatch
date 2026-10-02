"""Orion API Poller endpoints: flat JSON, 0/1/2 status, unavailable values omitted."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.integrations.orion import GROUPS
from hostwatch.schema import Batch, Sample, SourceStatus
from hostwatch.store import Store

H = "h1"
ALL = ["cpu", "memory", "rapl", "hwmon", "mdraid", "scrutiny"]


def cfg(tmp_path):
    return Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                  argon2_parallelism=1)


def sample(source, metric, value, **labels):
    return Sample(source=source, metric=metric, value=value, labels=labels, ts=time.time())


def seed(store, temp=45.0, unavailable=()):
    samples = [
        sample("cpu", "utilization_pct", 12.5),
        sample("memory", "mem_total", 8000.0), sample("memory", "mem_available", 6000.0),
        sample("rapl", "watts", 20.0, zone="r0", domain="package-0"),
        sample("hwmon", "temp", temp, chip="k10temp", sensor="Tctl"),
        sample("mdraid", "degraded", 0, array="md0"),
        sample("mdraid", "sync_action", 1, array="md0", action="idle"),
        sample("scrutiny", "device_status", 0, wwn="w1", device="sda", model="m"),
        sample("scrutiny", "temp", 35.0, wwn="w1", device="sda", model="m"),
    ]
    samples = [s for s in samples if s.source not in unavailable]
    sources = [SourceStatus(source=n, available=n not in unavailable,
                            reason="gone" if n in unavailable else "") for n in ALL]
    store.ingest_batch(Batch(agent_version="t", host=H, platform="x86", sent_at=time.time(),
                             sources=sources, samples=samples))


def key(store, scopes):
    return {"Authorization": "Bearer " + auth.generate_api_key(store, scopes, "test")[0]}


@pytest.fixture
def env(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    return TestClient(create_app(cfg(tmp_path), store)), store, key(store, "read:metrics")


def test_requires_key_and_scope(env):
    client, store, good = env
    seed(store)
    paths = ["/api/v1/orion/hosts", f"/api/v1/orion/hosts/{H}/summary"] + \
            [f"/api/v1/orion/hosts/{H}/{g}" for g in GROUPS]
    other = key(store, "read:events")
    for p in paths:
        assert client.get(p).status_code == 401
        assert client.get(p, headers=other).status_code == 403
        assert client.get(p, headers=good).status_code == 200


def test_unknown_host_and_group_are_404(env):
    client, store, good = env
    seed(store)
    assert client.get("/api/v1/orion/hosts/nope/summary", headers=good).status_code == 404
    assert client.get("/api/v1/orion/hosts/nope/cpu", headers=good).status_code == 404
    assert client.get(f"/api/v1/orion/hosts/{H}/bogus", headers=good).status_code == 404


def test_field_name_snapshot_and_flatness(env):
    client, store, good = env
    seed(store)
    doc = client.get(f"/api/v1/orion/hosts/{H}/summary", headers=good).json()
    assert sorted(doc) == [
        "cpu_available", "cpu_status", "cpu_utilization_pct",
        "disk_w1_device_status", "disk_w1_status", "disks_available", "disks_status",
        "host", "last_seen", "md_md0_degraded_devices", "md_md0_status",
        "memory_available", "memory_status", "memory_used_pct", "open_conditions",
        "overall_available", "overall_status", "overall_unmeasured", "package_power_w", "pools_available",
        "pools_reason", "pools_status", "power_available", "power_status",
        "problem_disk_failing", "problem_md_degraded", "problem_memory_low",
        "problem_source_unavailable", "problem_temperature_high",
        "raid_available", "raid_status",
        "source_cpu_status", "source_cpu_up", "source_hwmon_status", "source_hwmon_up",
        "source_mdraid_status", "source_mdraid_up", "source_memory_status", "source_memory_up",
        "source_rapl_status", "source_rapl_up", "source_scrutiny_status", "source_scrutiny_up",
        "sources_available", "sources_status",
        "temp_k10temp_tctl_c", "temp_k10temp_tctl_status",
        "temp_sda_w1_c", "temp_sda_w1_status", "temperatures_available", "temperatures_status",
    ]
    assert all(isinstance(v, (int, float, str)) and not isinstance(v, bool) for v in doc.values())
    assert doc["overall_status"] == 0 and doc["cpu_utilization_pct"] == 12.5
    assert doc["memory_used_pct"] == 25.0
    hosts = client.get("/api/v1/orion/hosts", headers=good).json()
    assert hosts == {"host_count": 1, "host_h1_name": H, "host_h1_status": 0}


@pytest.mark.parametrize("temp,status", [(85.0, 1), (95.0, 2)])
def test_threshold_warning_and_critical(env, temp, status):
    client, store, good = env
    seed(store, temp=temp)
    t = client.get(f"/api/v1/orion/hosts/{H}/temperatures", headers=good).json()
    assert t["temp_k10temp_tctl_c"] == temp
    assert t["temp_k10temp_tctl_status"] == status and t["temperatures_status"] == status
    assert client.get(f"/api/v1/orion/hosts/{H}/summary", headers=good).json()["overall_status"] == status


def test_unavailable_source_omits_value_not_zero(env):
    client, store, good = env
    seed(store, unavailable=("cpu",))
    cpu = client.get(f"/api/v1/orion/hosts/{H}/cpu", headers=good).json()
    assert "cpu_utilization_pct" not in cpu
    assert cpu["cpu_available"] == 0 and cpu["cpu_status"] == 1 and "gone" in cpu["cpu_reason"]
    src = client.get(f"/api/v1/orion/hosts/{H}/sources", headers=good).json()
    assert src["source_cpu_up"] == 0 and src["source_cpu_status"] == 1
    assert src["source_memory_up"] == 1 and src["source_memory_status"] == 0


def test_results_survive_recreating_the_app(tmp_path):
    path = tmp_path / "db.sqlite"
    store = Store(path)
    seed(store, temp=85.0)
    k = key(store, "read:metrics")
    url = f"/api/v1/orion/hosts/{H}/summary"
    first = TestClient(create_app(cfg(tmp_path), store)).get(url, headers=k).json()
    store2 = Store(path)
    second = TestClient(create_app(cfg(tmp_path), store2)).get(url, headers=k).json()
    assert second["overall_status"] == 1
    for d in (first, second):
        d.pop("last_seen")
    assert first == second
