"""History charts: the page feeds an SVG chart from the history and gaps endpoints."""

from __future__ import annotations

import re
import time
from importlib.resources import files

from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.schema import Batch, Sample
from hostwatch.store import Store

ASSETS = ("index.html", "app.css", "app.js")


def build(tmp_path):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(cfg, "correct horse battery"))
    client = TestClient(create_app(cfg, store), client=("127.0.0.1", 40000))
    client.post("/api/v1/login", json={"username": "alice", "password": "correct horse battery"})
    return client, store


def text(name):
    return files("hostwatch").joinpath("web", name).read_text(encoding="utf-8")


def test_static_assets_present_and_wired():
    for name in ASSETS:
        assert files("hostwatch").joinpath("web", name).is_file()
    html, js = text("index.html"), text("app.js")
    for ident in ("tab-history", "history-panel", "h-series", "h-range", "history-chart", "history-table",
                  "history-gaps"):
        assert f'id="{ident}"' in html
    assert re.search(r"<th scope=\"col\"[^>]*>Average</th>", html)
    assert "<caption" in html
    assert "createElementNS" in js and "/history?" in js and "/internal/v1/gaps?" in js


def test_chart_script_sets_text_only():
    js = text("app.js")
    assert "innerHTML" not in js and "outerHTML" not in js
    assert "setAttribute(\"style\"" not in js and ".style." not in js


def test_range_options_cover_raw_and_rollup():
    html = text("index.html")
    spans = [int(v) for v in re.findall(r'<option value="(\d+)"', html)]
    assert any(s <= 86400 for s in spans) and any(s > 7 * 86400 for s in spans)


def test_no_third_party_origins_in_shipped_files():
    for name in ASSETS:
        body = text(name)
        for url in re.findall(r"https?://[^\s\"')]+", body):
            # The SVG namespace is an identifier, not a request.
            assert url == "http://www.w3.org/2000/svg", (name, url)
        assert "//cdn" not in body and "@import" not in body
    html = text("index.html")
    assert not re.search(r"(?:src|href)\s*=\s*\"(?!/static/|#)", html)


def test_history_and_gaps_endpoints_feed_the_chart(tmp_path):
    client, store = build(tmp_path)
    now = time.time()
    samples = [Sample(source="cpu", metric="load", value=float(i), unit="x", ts=now - 3600 + i * 60)
               for i in range(10)]
    samples.append(Sample(source="cpu", metric="load", value=1.0, unit="x", ts=now - 600))
    store.ingest_batch(Batch(agent_version="t", host="h1", platform="x86", sent_at=now, sources=[],
                             samples=samples, events=[]))
    latest = client.get("/internal/v1/latest").json()
    assert {"host", "source", "metric"} <= set(latest[0])
    r = client.get("/api/v1/hosts/h1/history", params={"source": "cpu", "metric": "load",
                                                       "since": now - 7200, "until": now})
    assert r.status_code == 200 and r.json()["series"][0]["points"]
    g = client.get("/internal/v1/gaps", params={"host": "h1", "source": "cpu", "metric": "load",
                                                "hours": 2, "max_gap_s": 120})
    assert g.status_code == 200 and g.json()["gap_count"] == 1
