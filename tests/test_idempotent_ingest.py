"""Idempotent ingest, atomic batches, and event query filters with paging."""

from __future__ import annotations

import logging
import sqlite3

import httpx
from fastapi.testclient import TestClient

from hostwatch.agent import Agent
from hostwatch.config import Config
from hostwatch.events.thresholds import ThresholdEngine
from hostwatch.hub import create_app
from hostwatch.schema import Batch, Event, Sample, SourceStatus
from hostwatch.store import SCHEMA_VERSION, Store

TOKEN = "t" * 64
H = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def ev(key, ts, kind="md.degraded", source="mdraid", detail=None):
    return Event(kind=kind, severity="warning", source=source, ts=ts, title="t",
                 detail=detail or {}, dedup_key=key)


def make_batch(batch_id="b1", events=None, ts=100.0):
    return Batch(agent_version="test", host="h1", platform="x86", sent_at=ts, batch_id=batch_id,
                 sources=[SourceStatus(source="rapl", available=True)],
                 samples=[Sample(source="rapl", metric="watts", value=1.0, unit="W", ts=ts)],
                 events=events if events is not None else [ev("a", ts)])


def count(path, table):
    db = sqlite3.connect(path)
    try:
        return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        db.close()


def test_resent_batch_id_stores_once(tmp_path):
    p = tmp_path / "db.sqlite"
    store = Store(p)
    assert store.ingest_batch(make_batch()) == (1, 1, False)
    assert store.ingest_batch(make_batch()) == (0, 0, True)
    assert count(p, "samples") == 1 and count(p, "events") == 1
    # The same id from another host is a different batch.
    other = make_batch()
    other.host = "h2"
    assert store.ingest_batch(other) == (1, 1, False)


def test_hub_acknowledges_duplicate_batch(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    client = TestClient(create_app(Config(ingest_token=TOKEN, data_dir=tmp_path), store))
    body = make_batch().model_dump_json()
    first = client.post("/internal/v1/ingest", content=body, headers=H)
    second = client.post("/internal/v1/ingest", content=body, headers=H)
    assert first.json() == {"stored": 1, "events_stored": 1}
    assert second.status_code == 200 and second.json() == {"stored": 0, "events_stored": 0, "duplicate": True}


def test_batch_without_batch_id_keeps_current_behaviour(tmp_path):
    p = tmp_path / "db.sqlite"
    store = Store(p)
    store.ingest_batch(make_batch(batch_id=None))
    assert store.ingest_batch(make_batch(batch_id=None)) == (1, 0, False)  # samples repeat, event deduped
    assert count(p, "samples") == 2 and count(p, "batch_ids") == 0


def test_event_insert_failure_rolls_back_samples(tmp_path):
    p = tmp_path / "db.sqlite"
    store = Store(p)
    bad = Event.model_construct(kind="k", severity="info", source="s", ts=1.0, title="t",
                                detail={"x": object()}, dedup_key="bad")
    batch = make_batch(batch_id="roll")
    batch.events = [bad]
    try:
        store.ingest_batch(batch)
        raise AssertionError("expected the event insert to fail")
    except TypeError:
        pass
    assert count(p, "samples") == 0 and count(p, "sources") == 0
    assert count(p, "agents") == 0 and count(p, "batch_ids") == 0
    # The id was not recorded, so a corrected resend is stored.
    assert store.ingest_batch(make_batch(batch_id="roll")) == (1, 1, False)


def test_version2_database_migrates_and_keeps_rows(tmp_path):
    p = tmp_path / "db.sqlite"
    store = Store(p)
    store.ingest_batch(make_batch(batch_id=None))
    db = sqlite3.connect(p)
    db.execute("DROP TABLE batch_ids")
    db.execute("PRAGMA user_version = 2")
    db.commit()
    db.close()
    store = Store(p)
    assert count(p, "batch_ids") == 0
    assert count(p, "samples") == 1 and len(store.events("h1")) == 1
    db = sqlite3.connect(p)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 9
    db.close()
    assert store.ingest_batch(make_batch()) == (1, 0, False)
    assert store.ingest_batch(make_batch())[2] is True


def test_source_filter_and_before_paging(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    rows = [ev(f"m{i}", float(i), source="mdraid").model_dump() for i in range(1, 6)]
    rows += [ev(f"t{i}", float(i), source="thresholds").model_dump() for i in range(1, 6)]
    store.add_events("h1", rows)
    got = store.events("h1", source="thresholds")
    assert [e["dedup_key"] for e in got] == ["t5", "t4", "t3", "t2", "t1"]
    older = store.events("h1", source="thresholds", before=3.0)
    assert [e["dedup_key"] for e in older] == ["t2", "t1"]
    assert [e["dedup_key"] for e in store.events("h1", before=3.0, limit=2)] == ["t2", "m2"]


def test_before_id_keeps_rows_sharing_a_timestamp(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    store.add_events("h1", [ev(f"k{i}", 5.0).model_dump() for i in range(4)])
    seen, cursor = [], {}
    while True:
        page = store.events("h1", limit=3, **cursor)
        seen += [e["dedup_key"] for e in page]
        if len(page) < 3:
            break
        cursor = {"before": page[-1]["ts"], "before_id": page[-1]["id"]}
    assert sorted(seen) == ["k0", "k1", "k2", "k3"]


def test_malicious_source_is_a_value(tmp_path):
    p = tmp_path / "db.sqlite"
    store = Store(p)
    store.add_events("h1", [ev("a", 1.0).model_dump()])
    evil = "x' OR '1'='1"
    assert store.events("h1", source=evil) == []
    assert store.events("h1", source="'; DROP TABLE events; --") == []
    assert count(p, "events") == 1
    store.add_events("h1", [ev("b", 2.0, source=evil).model_dump()])
    assert [e["dedup_key"] for e in store.events("h1", source=evil)] == ["b"]


def test_events_endpoint_source_filter_and_cursor(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    client = TestClient(create_app(Config(ingest_token=TOKEN, data_dir=tmp_path), store))
    store.add_events("h1", [ev(f"t{i}", float(i), source="thresholds").model_dump() for i in range(1, 6)]
                     + [ev("j", 9.0, source="journal").model_dump()])
    secret, _ = store.create_api_key(["read:events"], "test")
    H = {"Authorization": f"Bearer {secret}"}
    r = client.get("/internal/v1/events", headers=H, params={"source": "thresholds", "limit": 2})
    assert [e["dedup_key"] for e in r.json()] == ["t5", "t4"]
    assert float(r.headers["x-next-before"]) == 4.0
    r2 = client.get("/internal/v1/events", headers=H, params={
        "source": "thresholds", "limit": 2, "before": r.headers["x-next-before"],
        "before_id": r.headers["x-next-before-id"]})
    assert [e["dedup_key"] for e in r2.json()] == ["t3", "t2"]
    last = client.get("/internal/v1/events", headers=H, params={"source": "thresholds", "limit": 10})
    assert "x-next-before" not in last.headers


def agent_for(tmp_path, hub_url="http://testserver", token=TOKEN):
    for d in ("sys", "proc", "data"):
        (tmp_path / d).mkdir(exist_ok=True)
    cfg = Config(sysfs=tmp_path / "sys", procfs=tmp_path / "proc", data_dir=tmp_path / "data",
                 ingest_token=token, host_name="h1", hub_url=hub_url,
                 pstore=tmp_path / "none", journal=tmp_path / "none", rasdaemon_db=tmp_path / "none.db")
    return Agent(cfg)


def test_seed_restores_open_condition_below_1000_other_events(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    hub = TestClient(create_app(Config(ingest_token=TOKEN, data_dir=tmp_path), store))
    eng = ThresholdEngine()
    degraded = eng.evaluate([Sample(source="mdraid", metric="degraded", value=1,
                                    labels={"array": "md0"}, ts=1.0)], [], now=1.0)
    assert [e.kind for e in degraded] == ["md.degraded"]
    rows = [e.model_dump() for e in degraded]
    # 1100 journal events and 1005 other threshold events, all newer than the open condition.
    rows += [ev(f"j{i}", 100.0 + i, "journal.x", "journal").model_dump() for i in range(1100)]
    rows += [ev(f"o{i}", 10.0 + i, "scrutiny.status_raised", "thresholds",
                {"rule_key": f"scrutiny:w{i}", "state": 1}).model_dump() for i in range(1005)]
    store.add_events("h1", rows)
    # An agent can use a scoped key that holds both ingest and read:events as its token.
    secret, _ = store.create_api_key(["ingest", "read:events"], "agent")
    agent = agent_for(tmp_path, token=secret)
    agent.seed_thresholds(hub)  # TestClient is an httpx.Client talking to the hub app
    after = agent.thresholds.evaluate([Sample(source="mdraid", metric="degraded", value=1,
                                              labels={"array": "md0"}, ts=2.0)], [], now=2.0)
    assert after == []  # the open condition was restored, so no repeat md.degraded
    assert len(agent.thresholds.state) >= 1006


def test_seed_logs_401_distinctly_from_unreachable(tmp_path, caplog):
    store = Store(tmp_path / "db.sqlite")
    hub = TestClient(create_app(Config(ingest_token="u" * 64, data_dir=tmp_path), store))
    agent = agent_for(tmp_path)
    with caplog.at_level(logging.WARNING, logger="hostwatch.agent"):
        agent.seed_thresholds(hub)
    assert any("401" in r.getMessage() and r.levelno == logging.ERROR for r in caplog.records)

    def refuse(request):
        raise httpx.ConnectError("refused")

    caplog.clear()
    down = httpx.Client(transport=httpx.MockTransport(refuse))
    with caplog.at_level(logging.WARNING, logger="hostwatch.agent"):
        agent.seed_thresholds(down)
    msgs = [r.getMessage() for r in caplog.records]
    assert any("unreachable" in m for m in msgs) and not any("401" in m for m in msgs)


def test_agent_sets_unique_batch_ids(tmp_path):
    agent = agent_for(tmp_path)
    agent.detect()
    a, b = agent.collect_once(), agent.collect_once()
    assert a.batch_id and b.batch_id and a.batch_id != b.batch_id
    queued = a.batch_id
    assert a.model_dump()["batch_id"] == queued  # resend serialises the same id
