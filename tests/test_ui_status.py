"""Status tiles: the endpoint the page reads is worst first with text, and app.js only renders it."""

from __future__ import annotations

import re
import time
from importlib.resources import files

from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.schema import Batch, Sample, SourceStatus
from hostwatch.store import Store

ALL = ["cpu", "memory", "rapl", "hwmon", "mdraid", "scrutiny"]


def build(tmp_path):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(cfg, "correct horse battery"))
    return TestClient(create_app(cfg, store), client=("127.0.0.1", 40000)), store


def seed(store, host, degraded=0, missing=()):
    now = time.time()

    def s(source, metric, value, **labels):
        return Sample(source=source, metric=metric, value=value, labels=labels, ts=now)

    samples = [s("cpu", "utilization_pct", 10.0), s("memory", "mem_total", 8000.0),
               s("memory", "mem_available", 6000.0), s("rapl", "watts", 20.0, zone="r0", domain="package-0"),
               s("hwmon", "temp", 45.0, chip="k10temp", sensor="Tctl"),
               s("mdraid", "degraded", degraded, array="md0"),
               s("mdraid", "sync_action", 1, array="md0", action="idle"),
               s("scrutiny", "device_status", 0, wwn="w1", device="sda", model="m")]
    samples = [x for x in samples if x.source not in missing]
    sources = [SourceStatus(source=n, available=n not in missing, reason="gone" if n in missing else "")
               for n in ALL]
    store.ingest_batch(Batch(agent_version="t", host=host, platform="x86", sent_at=now,
                             sources=sources, samples=samples))


def login(client):
    client.post("/api/v1/login", json={"username": "alice", "password": "correct horse battery"})


def test_requires_login(tmp_path):
    client, _ = build(tmp_path)
    assert client.get("/api/v1/ui/status").status_code == 401


def test_hosts_worst_first_with_text(tmp_path):
    client, store = build(tmp_path)
    seed(store, "aaa-ok")
    seed(store, "bbb-bad", degraded=1)
    seed(store, "ccc-warn", missing=("hwmon",))
    login(client)
    doc = client.get("/api/v1/ui/status").json()
    assert [h["host"] for h in doc["hosts"]] == ["bbb-bad", "ccc-warn", "aaa-ok"]
    assert [h["status"] for h in doc["hosts"]] == [2, 1, 0]
    statuses = [h["status"] for h in doc["hosts"]]
    assert statuses == sorted(statuses, reverse=True)
    assert [h["status_text"] for h in doc["hosts"]] == [{0: "OK", 1: "Warning", 2: "Critical"}[x] for x in statuses]
    assert doc["banner"]["host"] == "bbb-bad" and "Critical" in doc["banner"]["text"]
    assert doc["banner"]["status"] == 2 and doc["refresh_s"] > 0
    worst = doc["hosts"][0]
    assert worst["raid"][0]["state_text"] == "Critical"
    assert worst["pools"][0]["state"] == "unknown" and worst["pools"][0]["value"] is None
    assert {c["name"] for c in worst["sources"]} == set(ALL)


def test_not_present_source_is_listed_as_such(tmp_path):
    client, store = build(tmp_path)
    store.ingest_batch(Batch(agent_version="t", host="h1", platform="x86", sent_at=time.time(), samples=[],
                             sources=[SourceStatus(source="mdraid", available=False, present=False,
                                                   reason="no md arrays")]))
    login(client)
    host = client.get("/api/v1/ui/status").json()["hosts"][0]
    md = [c for c in host["sources"] if c["name"] == "mdraid"][0]
    assert md["state"] == "not_present" and md["state_text"] == "Not present"
    assert "raid" in host["not_present"]


def test_empty_hub_banner(tmp_path):
    client, _ = build(tmp_path)
    login(client)
    doc = client.get("/api/v1/ui/status").json()
    assert doc["hosts"] == [] and doc["banner"]["text"]


def js():
    return files("hostwatch").joinpath("web", "app.js").read_text(encoding="utf-8")


def test_app_js_renders_with_textcontent_only():
    src = js()
    assert "/api/v1/hosts/summary/grouped" in src and "textContent" in src
    assert "innerHTML" not in src and "insertAdjacentHTML" not in src
    assert "setTimeout(refresh" in src


def test_app_js_holds_no_threshold_logic():
    src = js()
    # Only the cookie reader may compare against a number (a string index); no data value may.
    assert not re.search(r"(?:value|status|generated|last_seen)\s*[<>]=?", src), "value comparison in app.js"
    assert not re.search(r"[<>]=?\s*(?:\d+\.\d|[1-9]\d)", src), "numeric limit in app.js"
    assert ".sort(" not in src
    for word in ("threshold", "critical_at", "warn_at"):
        assert word not in src
    assert "h.status_text" in src and "g.status_text" in src and "m.status_text" in src


def test_index_has_banner_and_hosts():
    html = files("hostwatch").joinpath("web", "index.html").read_text(encoding="utf-8")
    assert 'id="banner"' in html and 'id="hosts"' in html and 'aria-live="polite"' in html
