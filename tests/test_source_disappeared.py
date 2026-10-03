"""A source that was present and available and then vanishes is critical, not absent by design."""

from __future__ import annotations

import dataclasses
import sqlite3
import time

from fastapi.testclient import TestClient
from test_ha_discovery import FakeBroker, make_config, make_publisher
from test_orion import ALL, H, cfg, key, sample
from test_prometheus import parse
from test_source_absent import seed_zfs_host

from hostwatch.__main__ import main
from hostwatch.events.thresholds import ThresholdEngine
from hostwatch.hub import create_app
from hostwatch.integrations.summary import build_host_summary
from hostwatch.schema import Batch, SourceStatus
from hostwatch.store import SCHEMA_VERSION, Store


def send(store, ts, md_available, md_present, engine=None, host=H):
    samples = [sample("cpu", "utilization_pct", 12.5),
               sample("memory", "mem_total", 8000.0), sample("memory", "mem_available", 6000.0),
               sample("rapl", "watts", 20.0, zone="r0", domain="package-0"),
               sample("hwmon", "temp", 45.0, chip="k10temp", sensor="Tctl"),
               sample("scrutiny", "device_status", 0, wwn="w1", device="sda", model="m")]
    if md_available:
        samples.append(sample("mdraid", "degraded", 0, array="md0"))
    sources = [SourceStatus(source=n, available=True) for n in ALL if n != "mdraid"]
    sources.append(SourceStatus(source="mdraid", available=md_available, present=md_present,
                                reason="" if md_available else "no md arrays"))
    events = engine.evaluate([], sources, now=ts) if engine is not None else []
    store.ingest_batch(Batch(agent_version="t", host=host, platform="x86", sent_at=ts, sources=sources,
                             samples=samples, events=events))


def kinds(store):
    return [e["kind"] for e in store.events(H, limit=100)]


def test_vanished_md_array_is_critical_everywhere(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    engine = ThresholdEngine()
    now = time.time()
    send(store, now - 20, True, True, engine)
    send(store, now - 10, False, False, engine)
    send(store, now - 5, False, False, engine)  # steady state: no second event
    s = build_host_summary(store, H, now)
    assert s.overall_status == 2 and s.problems["md_degraded"] is True
    assert s.disappeared == ["mdraid"] and "raid" not in s.not_present and "raid" not in s.unmeasured
    assert "last seen present and available at" in s.sources["mdraid"].reason
    assert kinds(store).count("source.disappeared") == 1
    assert "source.unavailable" not in kinds(store)

    config = dataclasses.replace(cfg(tmp_path), prometheus_enabled=True)
    client = TestClient(create_app(config, store))
    good = key(store, "read:metrics")
    doc = client.get(f"/api/v1/orion/hosts/{H}/summary", headers=good).json()
    assert doc["overall_status"] == 2 and doc["raid_status"] == 2 and doc["problem_md_degraded"] == 1
    assert doc["source_mdraid_status"] == 2 and "disappeared" in doc["source_mdraid_reason"]
    assert client.get(f"/api/v1/orion/hosts/{H}/raid", headers=good).json()["raid_status"] == 2
    by = {(n, tuple(sorted(lbl.items()))): v for n, lbl, v in parse(client.get("/metrics", headers=good).text)}
    assert by[("hostwatch_host_status", (("host", H),))] == 2.0
    assert by[("hostwatch_source_present", (("host", H), ("source", "mdraid")))] == 1.0
    assert by[("hostwatch_source_up", (("host", H), ("source", "mdraid")))] == 0.0

    broker = FakeBroker()
    pub, _ = make_publisher(make_config(tmp_path), store, broker)
    assert pub.tick() is True
    up = "homeassistant/binary_sensor/hostwatch_h1/source_mdraid_up/config"
    assert broker.retained[up] != ""  # the entity stays and shows the problem
    problem = [v for t, v in broker.retained.items() if t.endswith("problem_md_degraded/state")]
    assert problem == ["ON"]


def test_source_that_never_was_present_stays_ok(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    engine = ThresholdEngine()
    now = time.time()
    send(store, now - 5, False, False, engine)
    s = build_host_summary(store, H, now)
    assert s.overall_status == 0 and s.not_present == ["raid"] and s.disappeared == []
    assert "source.disappeared" not in kinds(store)


def test_present_but_unreadable_is_not_disappeared(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    now = time.time()
    send(store, now - 10, True, True)
    send(store, now - 5, False, True)
    s = build_host_summary(store, H, now)
    assert s.disappeared == [] and s.overall_status == 1


def test_returned_event_and_recovery(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    engine = ThresholdEngine()
    now = time.time()
    send(store, now - 30, True, True, engine)
    send(store, now - 20, False, False, engine)
    send(store, now - 10, True, True, engine)
    assert kinds(store).count("source.disappeared") == 1 and kinds(store).count("source.returned") == 1
    assert build_host_summary(store, H, now).overall_status == 0


def test_engine_seeded_from_stored_events_does_not_repeat(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    engine = ThresholdEngine()
    now = time.time()
    send(store, now - 20, True, True, engine)
    send(store, now - 10, False, False, engine)
    fresh = ThresholdEngine()
    fresh.seed(store.events(H, limit=100))
    gone = SourceStatus(source="mdraid", available=False, present=False)
    assert fresh.evaluate([], [gone], now=now) == []


def test_source_forget_returns_host_to_ok_and_is_audited(tmp_path, monkeypatch):
    monkeypatch.setenv("HOSTWATCH_DATA_DIR", str(tmp_path))
    store = Store(tmp_path / "hostwatch.db")
    now = time.time()
    send(store, now - 10, True, True)
    send(store, now - 5, False, False)
    assert build_host_summary(store, H, now).overall_status == 2
    assert main(["source", "forget", H, "mdraid"]) == 0
    s = build_host_summary(store, H, now)
    assert s.overall_status == 0 and s.not_present == ["raid"] and s.disappeared == []
    row = store.audit_rows(kind="cli")[0]
    assert row["path"] == "source forget" and row["status"] == 0
    # Seen again, then gone again: the removal is no longer deliberate.
    send(store, now + 1, True, True)
    send(store, now + 2, False, False)
    assert build_host_summary(store, H, now + 3).overall_status == 2


def test_source_forget_unknown_source_is_refused_and_audited(tmp_path, monkeypatch):
    monkeypatch.setenv("HOSTWATCH_DATA_DIR", str(tmp_path))
    store = Store(tmp_path / "hostwatch.db")
    seed_zfs_host(store, md_present=False)
    assert main(["source", "forget", H, "mdraid"]) == 1
    assert store.audit_rows(kind="cli")[0]["status"] == 1


def test_migration_from_previous_version_keeps_rows(tmp_path):
    assert SCHEMA_VERSION == 8
    p = tmp_path / "db.sqlite"
    store = Store(p)
    seed_zfs_host(store, md_present=False)
    store.add_events(H, [{"ts": 1.0, "kind": "k", "severity": "info", "source": "s", "title": "t",
                          "dedup_key": "a"}])
    del store
    db = sqlite3.connect(p)
    db.execute("DROP TABLE source_seen")
    db.execute("PRAGMA user_version = 6")
    db.commit()
    db.close()
    upgraded = Store(p)
    assert len(upgraded.sources()) == len(ALL) and len(upgraded.events(H)) == 1
    assert upgraded.source_seen() == []
    seed_zfs_host(upgraded, md_present=True)
    assert {r["source"] for r in upgraded.source_seen()} == set(ALL) - {"mdraid"}
    db = sqlite3.connect(p)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 8
    db.close()
