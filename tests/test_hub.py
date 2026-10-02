from __future__ import annotations

import time

from fastapi.testclient import TestClient

from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.schema import Batch, Sample, SourceStatus
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
    assert r.status_code == 200 and r.json() == {"stored": 1}


def test_read_endpoints_require_token(tmp_path):
    client, _ = make(tmp_path)
    for path in ("/internal/v1/latest", "/internal/v1/sources"):
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
