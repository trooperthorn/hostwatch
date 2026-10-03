"""Simple, Expanded and Expert views: the page consumes the grouped endpoint, ships only same-origin
icons, and holds no grouping or threshold logic."""

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

STATUS_ICONS = {"good": "circle-check", "warning": "alert-triangle", "critical": "circle-x",
                "unknown": "circle-minus"}
GROUP_ICONS = ("cpu", "cpu-2", "bolt", "temperature", "propeller", "database", "stack-2", "device-floppy",
               "battery-charging", "plug-connected", "bell", "server")
UI_ICONS = ("arrow-up", "arrow-down", "grip-vertical", "adjustments")


def web(name):
    return files("hostwatch").joinpath("web", name).read_text(encoding="utf-8")


def build(tmp_path):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(cfg, "correct horse battery"))
    return TestClient(create_app(cfg, store), client=("127.0.0.1", 40000)), store


def seed(store, host, degraded=0):
    now = time.time()

    def s(source, metric, value, **labels):
        return Sample(source=source, metric=metric, value=value, labels=labels, ts=now)

    samples = [s("cpu", "utilization_pct", 10.0), s("memory", "mem_total", 8000.0),
               s("memory", "mem_available", 6000.0), s("rapl", "watts", 20.0, zone="r0", domain="package-0"),
               s("hwmon", "temp", 45.0, chip="k10temp", sensor="Tctl"),
               s("hwmon", "fan", 0.0, chip="nct6779", sensor="fan5"),
               s("mdraid", "degraded", degraded, array="md0"),
               s("mdraid", "sync_action", 1, array="md0", action="idle")]
    sources = [SourceStatus(source=n, available=True) for n in ("cpu", "memory", "rapl", "hwmon", "mdraid")]
    store.ingest_batch(Batch(agent_version="t", host=host, platform="x86", sent_at=now,
                             sources=sources, samples=samples))


def login(client):
    r = client.post("/api/v1/login", json={"username": "alice", "password": "correct horse battery"})
    return {"X-CSRF-Token": r.json()["csrf_token"]}


def test_session_renders_grouped_data_the_page_consumes(tmp_path):
    client, store = build(tmp_path)
    seed(store, "aaa-ok")
    seed(store, "bbb-bad", degraded=1)
    login(client)
    doc = client.get("/api/v1/hosts/summary/grouped").json()
    assert [h["host"] for h in doc["hosts"]] == ["bbb-bad", "aaa-ok"]
    assert doc["banner"]["status_key"] == "critical" and doc["banner"]["counts"]["hosts"]["critical"] == 1
    js = web("app.js")
    for field in ("b.counts","status_key", "status_text", "g.icon", "g.summary", "m.reason", "m.ts",
                  "m.labels", "m.source", "m.unit", "h.groups"):
        assert field in js, field
    host = doc["hosts"][0]
    group = host["groups"][0]
    for key in ("id", "label", "icon", "status", "status_text", "summary", "members"):
        assert key in group
    for key in ("label", "value", "unit", "labels", "source", "status", "status_text", "reason", "ts"):
        assert key in group["members"][0]
    fans = [g for g in host["groups"] if g["id"] == "fans"][0]
    assert fans["members"][0]["value"] == 0.0 and fans["members"][0]["status"] != "critical"
    page = client.get("/")
    assert page.status_code == 200 and 'id="view-simple"' in page.text and 'id="view-expert"' in page.text


def test_view_choice_is_saved_through_preferences(tmp_path):
    client, _ = build(tmp_path)
    csrf = login(client)
    body = {"view": "simple"}
    assert client.put("/api/v1/me/preferences", json=body).status_code == 403
    assert client.put("/api/v1/me/preferences", json=body, headers=csrf).status_code == 200
    got = client.get("/api/v1/me/preferences").json()
    assert got["view"] == "simple"
    assert all(g["label"] and g["icon"] for g in got["groups"])
    js = web("app.js")
    assert "/api/v1/me/preferences" in js and '"PUT"' in js


def test_app_js_has_no_threshold_or_grouping_logic():
    js = web("app.js")
    assert "textContent" in js and "innerHTML" not in js and "insertAdjacentHTML" not in js
    for word in ("threshold", "critical_at", "warn_at", "reduce(", "RPM", "rpm"):
        assert word not in js
    assert ".sort(" not in js
    assert not re.search(r"(?:\.value|\.status|generated|last_seen)\s*[<>]=?", js)
    assert not re.search(r"\.source\s*===|\.id\s*===\s*\"(?:cpu|fans|pools)", js), "grouping in app.js"
    assert "outerHTML" not in js and "document.write" not in js


def test_status_icon_mapping_and_accessibility_hooks_are_in_the_page():
    js = web("app.js")
    for key, name in STATUS_ICONS.items():
        assert re.search(rf'{key}:\s*"{name}"', js)
    assert "aria-expanded" in js and "aria-label" in js and "aria-controls" in js


def test_icons_are_package_resources_and_same_origin_only():
    base = files("hostwatch").joinpath("web", "icons")
    for name in GROUP_ICONS + tuple(STATUS_ICONS.values()) + UI_ICONS:
        res = base.joinpath(f"{name}.svg")
        assert res.is_file() and b"<svg" in res.read_bytes(), name
    assert base.joinpath("LICENSE").is_file()
    css, html, js = web("app.css"), web("index.html"), web("app.js")
    assert not re.search(r"https?://", css + html)
    assert not re.search(r"https?://(?!www\.w3\.org/2000/svg)", js)
    urls = re.findall(r'url\("([^"]+)"\)', css)
    assert urls and all(re.fullmatch(r"icons/[a-z0-9-]+\.svg", u) for u in urls)
    for name in re.findall(r"\bic-([a-z0-9-]+)", html):
        assert base.joinpath(f"{name}.svg").is_file(), name
    for name in GROUP_ICONS + tuple(STATUS_ICONS.values()) + UI_ICONS:
        assert f".ic-{name} " in css, name


def test_icons_served_under_the_strict_csp(tmp_path):
    client, _ = build(tmp_path)
    r = client.get("/static/icons/circle-check.svg")
    assert r.status_code == 200 and "svg" in r.headers["content-type"]
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "unsafe" not in csp
    assert client.get("/static/icons/LICENSE").status_code == 200


def test_css_has_dark_scheme_visible_focus_and_status_tokens():
    css = web("app.css")
    assert re.search(r"prefers-color-scheme:\s*dark", css) and ":focus-visible" in css
    assert "--ok-text" in css
