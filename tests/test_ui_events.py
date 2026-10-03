"""Event timeline: the page only passes filters to the events endpoint and renders rows as text."""

from __future__ import annotations

import re
import time
from importlib.resources import files

from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.schema import Batch, Event
from hostwatch.store import Store

EVIL = "<img src=x onerror=alert(1)>"


def build(tmp_path):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(cfg, "correct horse battery"))
    client = TestClient(create_app(cfg, store), client=("127.0.0.1", 40000))
    client.post("/api/v1/login", json={"username": "alice", "password": "correct horse battery"})
    return client, store


def add(store, host, n, source="journal", kind="k.one", base=None):
    now = time.time() if base is None else base
    events = [Event(kind=kind, severity="warning", source=source, ts=now - i, title=f"t{i}",
                    dedup_key=f"{host}-{source}-{kind}-{i}") for i in range(n)]
    store.ingest_batch(Batch(agent_version="t", host=host, platform="x86", sent_at=now, sources=[],
                             samples=[], events=events))


def test_filters_accepted(tmp_path):
    client, store = build(tmp_path)
    add(store, "h1", 2)
    add(store, "h2", 3, source="pstore", kind="k.two")
    r = client.get("/internal/v1/events", params={"host": "h2", "source": "pstore", "kind": "k.two",
                                                  "since": time.time() - 3600})
    assert r.status_code == 200 and len(r.json()) == 3
    assert {e["host"] for e in r.json()} == {"h2"}
    assert client.get("/internal/v1/events", params={"host": "h1", "source": "pstore"}).json() == []
    assert client.get("/internal/v1/events", params={"since": time.time() + 3600}).json() == []


def test_paging_cursor_walks_all_rows(tmp_path):
    client, store = build(tmp_path)
    add(store, "h1", 5, base=1_000_000.0)
    seen, params = [], {"limit": 2}
    while True:
        r = client.get("/internal/v1/events", params=params)
        seen += [e["id"] for e in r.json()]
        if "x-next-before" not in r.headers:
            break
        params = {"limit": 2, "before": r.headers["x-next-before"], "before_id": r.headers["x-next-before-id"]}
    assert len(seen) == 5 == len(set(seen))


def test_host_with_markup_is_data(tmp_path):
    client, store = build(tmp_path)
    add(store, EVIL, 1)
    r = client.get("/internal/v1/events", params={"host": EVIL})
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()[0]["host"] == EVIL


def test_timeline_markup_has_headers_and_labels():
    html = files("hostwatch").joinpath("web", "index.html").read_text(encoding="utf-8")
    for name in ("Time", "Host", "Source", "Kind", "Severity", "Title"):
        assert f'<th scope="col">{name}</th>' in html
    assert "<caption>" in html
    for fid in ("f-host", "f-source", "f-kind", "f-since"):
        assert f'<label for="{fid}">' in html and f'id="{fid}"' in html


def test_timeline_script_uses_text_and_cursor_headers():
    js = files("hostwatch").joinpath("web", "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js
    assert "X-Next-Before-Id" in js and "ArrowDown" in js
    assert re.search(r'el\("td", e\.host[,)]', js) and re.search(r'el\("td", e\.title[,)]', js)
