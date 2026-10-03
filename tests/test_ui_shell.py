"""Static UI shell: served with a strict CSP, no inline code, packaged, and behind the same gates."""

from __future__ import annotations

import re
from importlib.resources import files

import pytest
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.store import Store

OTHER = ("203.0.113.9", 40000)
ASSETS = ("index.html", "app.css", "app.js")


def build(tmp_path, client=("127.0.0.1", 40000), **over):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1, **over)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(cfg, "correct horse battery"))
    return TestClient(create_app(cfg, store), client=client), store


def assert_headers(r):
    csp = r.headers["content-security-policy"]
    for directive in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'",
                      "frame-ancestors 'none'", "base-uri 'none'"):
        assert directive in csp
    assert "unsafe" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_index_is_html_with_security_headers(tmp_path):
    client, _ = build(tmp_path)
    r = client.get("/")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "<form" in r.text and "/static/app.js" in r.text
    assert_headers(r)


@pytest.mark.parametrize("name,kind", [("app.css", "text/css"), ("app.js", "javascript")])
def test_assets_served_with_headers(tmp_path, name, kind):
    client, _ = build(tmp_path)
    r = client.get(f"/static/{name}")
    assert r.status_code == 200 and kind in r.headers["content-type"]
    assert_headers(r)


def test_headers_also_on_api_errors(tmp_path):
    client, _ = build(tmp_path)
    r = client.get("/internal/v1/latest")
    assert r.status_code == 401
    assert_headers(r)


def test_no_inline_script_or_style_in_shipped_html():
    html = files("hostwatch").joinpath("web", "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html, re.I), "inline script block"
    assert not re.search(r"<style", html, re.I)
    assert not re.search(r"\sstyle\s*=", html, re.I)
    assert not re.search(r"\son[a-z]+\s*=", html, re.I), "inline event handler"
    assert "javascript:" not in html.lower()


def test_script_never_writes_html_from_data():
    js = files("hostwatch").joinpath("web", "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "outerHTML" not in js and "document.write" not in js
    assert "eval(" not in js


@pytest.mark.parametrize("name", ASSETS)
def test_assets_resolvable_via_importlib_resources(name):
    res = files("hostwatch").joinpath("web", name)
    assert res.is_file() and len(res.read_bytes()) > 0


def test_package_data_declared():
    import tomllib
    from pathlib import Path
    data = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = data["tool"]["setuptools"]["package-data"]["hostwatch"]
    assert {"web/*.html", "web/*.css", "web/*.js"} <= set(patterns)


def test_css_has_dark_tokens_and_focus_ring():
    css = files("hostwatch").joinpath("web", "app.css").read_text(encoding="utf-8")
    assert "prefers-color-scheme: dark" in css and ":focus-visible" in css


def test_unauthenticated_api_calls_still_401(tmp_path):
    client, _ = build(tmp_path)
    client.get("/")
    assert client.get("/internal/v1/latest").status_code == 401
    assert client.get("/internal/v1/events").status_code == 401
    assert client.post("/api/v1/logout").status_code == 401


def test_login_flow_from_shell_uses_csrf(tmp_path):
    client, _ = build(tmp_path)
    r = client.post("/api/v1/login", json={"username": "alice", "password": "correct horse battery"})
    token = r.json()["csrf_token"]
    assert client.post("/api/v1/logout").status_code == 403
    assert client.post("/api/v1/logout", headers={"X-CSRF-Token": token}).status_code == 200


def test_source_allowlist_applies_to_ui_paths(tmp_path):
    client, store = build(tmp_path, client=OTHER, allowed_clients="10.0.0.5")
    for path in ("/", "/static/app.js", "/static/app.css"):
        r = client.get(path)
        assert r.status_code == 403, path
        assert_headers(r)
    assert len([x for x in store.audit_rows() if x["kind"] == "source_denied"]) >= 1


def test_ui_requests_with_cookie_are_not_audited(tmp_path):
    client, store = build(tmp_path)
    client.post("/api/v1/login", json={"username": "alice", "password": "correct horse battery"})
    before = len(store.audit_rows())
    assert client.get("/").status_code == 200 and client.get("/static/app.js").status_code == 200
    assert len(store.audit_rows()) == before
