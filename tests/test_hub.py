from __future__ import annotations

import time

from fastapi.testclient import TestClient

from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.schema import Batch, Event, Sample, SourceStatus
from hostwatch.store import Store

TOKEN = "t" * 64


def make(tmp_path):
    cfg = Config(ingest_token=TOKEN, data_dir=tmp_path)
    store = Store(tmp_path / "db.sqlite")
    return TestClient(create_app(cfg, store)), store


def batch(ts, value=1.0):
    return Batch(agent_version="test", host="h1", platform="x86", sent_at=ts,
                 sources=[SourceStatus(source="rapl", available=True)],
                 samples=[Sample(source="rapl", metric="watts", value=value, unit="W",
                                 labels={"domain": "package-0"}, ts=ts)])


def test_ingest_requires_token(tmp_path):
    client, _ = make(tmp_path)
    body = batch(time.time()).model_dump_json()
    assert client.post("/internal/v1/ingest", content=body).status_code == 401
    assert client.post("/internal/v1/ingest", content=body,
                       headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = client.post("/internal/v1/ingest", content=body, headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json() == {"stored": 1, "events_stored": 0}


def test_read_endpoints_require_token(tmp_path):
    client, _ = make(tmp_path)
    for path in ("/internal/v1/latest", "/internal/v1/sources", "/internal/v1/events"):
        assert client.get(path).status_code == 401


def test_latest_and_gaps(tmp_path):
    client, store = make(tmp_path)
    now = time.time()
    for ts in (now - 300, now - 285, now - 100):  # a 185 s gap
        store.ingest(batch(ts))
    h = {"Authorization": f"Bearer {TOKEN}"}
    latest = client.get("/internal/v1/latest", headers=h).json()
    assert len(latest) == 1 and latest[0]["ts"] == now - 100
    gaps = client.get("/internal/v1/gaps", headers=h,
                      params={"host": "h1", "source": "rapl", "metric": "watts", "max_gap_s": 60}).json()
    assert gaps["gap_count"] == 1


def test_null_values_count_as_gaps(tmp_path):
    _, store = make(tmp_path)
    now = time.time()
    store.ingest(batch(now - 100))
    store.ingest(batch(now - 85, value=None))
    store.ingest(batch(now - 10))
    assert len(store.gaps("h1", "rapl", "watts", now - 200, 60)) == 1


def test_rollup_then_prune(tmp_path):
    _, store = make(tmp_path)
    old = time.time() - 10 * 86400
    for v in (10.0, 20.0, 30.0):
        store.ingest(batch(old, v))
    store.maintain(raw_days=7, rollup_days=400)
    row = store._db.execute("SELECT n, vmin, vavg, vmax FROM rollup_hourly").fetchone()
    assert row == (3, 10.0, 20.0, 30.0)
    assert store._db.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 0


def test_config_rejects_short_token():
    import pytest
    with pytest.raises(ValueError):
        Config(ingest_token="short").validate()


H = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def event(ts, kind="md.degraded", key="k1"):
    return Event(kind=kind, severity="warning", source="mdraid", ts=ts, title="t",
                 detail={"array": "md127"}, dedup_key=key)


def test_batch_without_events_is_accepted(tmp_path):
    client, _ = make(tmp_path)
    body = batch(time.time()).model_dump(exclude={"events"})
    assert "events" not in body
    r = client.post("/internal/v1/ingest", json=body, headers=H)
    assert r.status_code == 200 and r.json()["events_stored"] == 0
    assert client.get("/internal/v1/events", headers=H).json() == []


def test_events_stored_and_deduplicated(tmp_path):
    client, _ = make(tmp_path)
    now = time.time()
    b = batch(now)
    b.events = [event(now, key="a"), event(now, key="a")]
    assert client.post("/internal/v1/ingest", content=b.model_dump_json(), headers=H).json()["events_stored"] == 1
    assert client.post("/internal/v1/ingest", content=b.model_dump_json(), headers=H).json()["events_stored"] == 0
    rows = client.get("/internal/v1/events", headers=H).json()
    assert len(rows) == 1 and rows[0]["detail"] == {"array": "md127"} and rows[0]["host"] == "h1"


def test_events_endpoint_filters(tmp_path):
    client, store = make(tmp_path)
    now = time.time()
    store.add_events("h1", [event(now - 100, "md.degraded", "a").model_dump(),
                            event(now - 10, "boot.panic", "b").model_dump()])
    got = client.get("/internal/v1/events", headers=H, params={"kind": "boot.panic"}).json()
    assert [e["dedup_key"] for e in got] == ["b"]
    got = client.get("/internal/v1/events", headers=H, params={"since": now - 50}).json()
    assert [e["dedup_key"] for e in got] == ["b"]
    assert len(client.get("/internal/v1/events", headers=H, params={"host": "h1", "limit": 1}).json()) == 1
    assert client.get("/internal/v1/events", headers=H, params={"host": "other"}).json() == []


def test_events_requires_token(tmp_path):
    client, _ = make(tmp_path)
    assert client.get("/internal/v1/events").status_code == 401
    assert client.get("/internal/v1/events", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_event_source_unavailable_reason_is_reported(tmp_path):
    client, _ = make(tmp_path)
    b = batch(time.time())
    b.sources.append(SourceStatus(source="events.pstore", available=False, reason="/sys/fs/pstore not mounted"))
    client.post("/internal/v1/ingest", content=b.model_dump_json(), headers=H)
    src = {s["source"]: s for s in client.get("/internal/v1/sources", headers=H).json()["sources"]}
    assert src["events.pstore"]["available"] == 0 and "not mounted" in src["events.pstore"]["reason"]


def test_nan_event_ts_is_rejected_and_nothing_acknowledged(tmp_path):
    client, store = make(tmp_path)
    now = time.time()
    b = batch(now)
    b.events = [event(now, key="a")]
    # The event ts is the last "ts" in the body; make that one NaN.
    body = b.model_dump_json()
    idx = body.rindex('"ts":')
    end = body.index(",", idx)
    body = body[:idx] + '"ts":NaN' + body[end:]
    r = client.post("/internal/v1/ingest", content=body, headers={**H, "Content-Type": "application/json"})
    assert r.status_code == 422
    assert client.get("/internal/v1/events", headers=H).json() == []


def test_store_ignores_only_the_uniqueness_conflict(tmp_path):
    import sqlite3

    import pytest
    store = Store(tmp_path / "db.sqlite")
    ev = event(time.time(), key="k").model_dump()
    assert store.add_events("h1", [ev]) == 1
    assert store.add_events("h1", [ev]) == 0
    bad = dict(ev, dedup_key="other", title=None)
    with pytest.raises(sqlite3.IntegrityError):
        store.add_events("h1", [bad])
