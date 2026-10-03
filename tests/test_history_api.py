"""History endpoint: raw samples for short ranges, hourly rollups for long ones."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.schema import Batch, Sample, SourceStatus
from hostwatch.store import Store

TOKEN = "t" * 64
URL = "/api/v1/hosts/h1/history"
Q = {"source": "rapl", "metric": "watts"}


def make(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    client = TestClient(create_app(Config(ingest_token=TOKEN, data_dir=tmp_path), store))
    secret, _ = store.create_api_key(["read:metrics"], "test")
    return client, store, {"Authorization": f"Bearer {secret}"}


def batch(ts, value):
    return Batch(agent_version="t", host="h1", platform="x86", sent_at=ts,
                 sources=[SourceStatus(source="rapl", available=True)],
                 samples=[Sample(source="rapl", metric="watts", value=value, unit="W",
                                 labels={"domain": "package-0"}, ts=ts)])


def test_short_range_reads_raw_samples(tmp_path):
    client, store, hdr = make(tmp_path)
    now = time.time()
    for i, v in enumerate((10.0, 20.0, 30.0)):
        store.ingest(batch(now - 300 + i, v))
    r = client.get(URL, params={**Q, "since": now - 600, "until": now, "step": 600}, headers=hdr)
    assert r.status_code == 200
    body = r.json()
    assert body["resolution"] == "raw" and body["unit"] == "W"
    pts = [p for s in body["series"] for p in s["points"]]
    assert sum(p["n"] for p in pts) == 3
    assert min(p["min"] for p in pts) == 10.0 and max(p["max"] for p in pts) == 30.0
    assert body["series"][0]["labels"] == {"domain": "package-0"}


def test_long_range_reads_rollups_after_raw_is_pruned(tmp_path):
    client, store, hdr = make(tmp_path)
    old = time.time() - 10 * 86400
    for i, v in enumerate((10.0, 20.0, 30.0)):
        store.ingest(batch(old + i, v))
    store.maintain(raw_days=7, rollup_days=400)
    now = time.time()
    r = client.get(URL, params={**Q, "since": now - 20 * 86400, "until": now, "step": 86400}, headers=hdr)
    assert r.status_code == 200
    body = r.json()
    assert body["resolution"] == "rollup" and body["step"] % 3600 == 0
    pts = [p for s in body["series"] for p in s["points"]]
    assert len(pts) == 1
    assert (pts[0]["n"], pts[0]["min"], pts[0]["avg"], pts[0]["max"]) == (3, 10.0, 20.0, 30.0)
    # The same data is invisible to a short range, which reads only raw samples.
    r = client.get(URL, params={**Q, "since": now - 11 * 86400, "until": now - 9 * 86400, "step": 3600}, headers=hdr)
    assert r.json()["resolution"] == "raw" and r.json()["series"] == []


def test_unknown_metric_is_empty(tmp_path):
    client, store, hdr = make(tmp_path)
    now = time.time()
    store.ingest(batch(now - 10, 5.0))
    for since in (now - 600, now - 10 * 86400):
        r = client.get(URL, params={"source": "rapl", "metric": "nope", "since": since, "until": now}, headers=hdr)
        assert r.status_code == 200
        assert r.json()["series"] == []


def test_limits_are_enforced_with_uniform_errors(tmp_path):
    client, _, hdr = make(tmp_path)
    now = time.time()
    cases = [
        {"since": now - 86400, "until": now, "step": 1},          # too many points
        {"since": now - 400 * 86400, "until": now, "step": 86400},  # range too long
        {"since": now, "until": now - 10},                        # reversed
        {"since": now - 60, "until": now, "step": 0},             # bad step
        {"until": now},                                           # since missing
    ]
    for params in cases:
        r = client.get(URL, params={**Q, **params}, headers=hdr)
        assert r.status_code == 422, params
        assert "detail" in r.json()


def test_requires_auth_and_scope(tmp_path):
    client, store, _ = make(tmp_path)
    params = {**Q, "since": time.time() - 60}
    assert client.get(URL, params=params).status_code == 401
    secret, _ = store.create_api_key(["read:events"], "other")
    assert client.get(URL, params=params, headers={"Authorization": f"Bearer {secret}"}).status_code == 403
