"""Admin screens: the page drives the admin endpoints and never decides anything itself."""

from __future__ import annotations

import re
from importlib.resources import files

from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.store import Store

PASSWORD = "correct horse battery"


def build(tmp_path):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(cfg, PASSWORD), is_admin=True)
    store.create_user("bob", auth.hash_password(cfg, PASSWORD))
    app = create_app(cfg, store)
    return app, store


def login(app, name):
    client = TestClient(app, client=("127.0.0.1", 40000))
    r = client.post("/api/v1/login", json={"username": name, "password": PASSWORD})
    assert r.status_code == 200
    return client, {"X-CSRF-Token": r.json()["csrf_token"]}


def text(name):
    return files("hostwatch").joinpath("web", name).read_text(encoding="utf-8")


def test_admin_flow_login_create_list_revoke_audit(tmp_path):
    app, _ = build(tmp_path)
    client, csrf = login(app, "alice")
    r = client.post("/api/v1/admin/keys", json={"scopes": ["read:metrics"], "owner": "ha"}, headers=csrf)
    assert r.status_code == 201 and r.headers["cache-control"] == "no-store"
    secret, key = r.json()["secret"], r.json()["key"]
    keys = client.get("/api/v1/admin/keys").json()["keys"]
    assert [k["id"] for k in keys] == [key["id"]] and keys[0]["revoked_at"] is None
    assert secret not in client.get("/api/v1/admin/keys").text
    r = client.post(f"/api/v1/admin/keys/{key['id']}/revoke", headers=csrf)
    assert r.status_code == 200
    assert client.get("/api/v1/admin/keys").json()["keys"][0]["revoked_at"] is not None
    rows = client.get("/api/v1/admin/audit", params={"kind": "api_key_create"}).json()["rows"]
    assert len(rows) == 1 and rows[0]["actor"] == "alice" and secret not in str(rows)
    for field in ("id", "ts", "actor", "kind", "method", "path", "status", "remote", "detail"):
        assert field in rows[0]
    kinds = {x["kind"] for x in client.get("/api/v1/admin/audit", params={"actor": "alice"}).json()["rows"]}
    assert {"api_key_create", "api_key_revoke"} <= kinds


def test_state_changes_need_the_csrf_header(tmp_path):
    app, _ = build(tmp_path)
    client, csrf = login(app, "alice")
    body = {"scopes": ["read:metrics"], "owner": "ha"}
    assert client.post("/api/v1/admin/keys", json=body).status_code == 403
    key_id = client.post("/api/v1/admin/keys", json=body, headers=csrf).json()["key"]["id"]
    assert client.post(f"/api/v1/admin/keys/{key_id}/revoke").status_code == 403
    assert client.get("/api/v1/admin/keys").json()["keys"][0]["revoked_at"] is None


def test_non_admin_gets_403_everywhere(tmp_path):
    app, _ = build(tmp_path)
    client, csrf = login(app, "bob")
    assert client.get("/api/v1/admin/keys").status_code == 403
    assert client.get("/api/v1/admin/audit").status_code == 403
    r = client.post("/api/v1/admin/keys", json={"scopes": ["admin"], "owner": "x"}, headers=csrf)
    assert r.status_code == 403
    assert client.post("/api/v1/admin/keys/1/revoke", headers=csrf).status_code == 403
    anon = TestClient(app, client=("127.0.0.1", 40001))
    assert anon.get("/api/v1/admin/keys").status_code == 401


def test_audit_filters_and_paging(tmp_path):
    app, store = build(tmp_path)
    client, _ = login(app, "alice")
    for i in range(5):
        store.append_audit("svc", "custom_kind", "GET", f"/p{i}", 200, "127.0.0.1", {})
    page = client.get("/api/v1/admin/audit", params={"kind": "custom_kind", "limit": 2}).json()["rows"]
    assert len(page) == 2
    rest = client.get("/api/v1/admin/audit", params={"kind": "custom_kind", "before_id": page[-1]["id"]})
    assert len(rest.json()["rows"]) == 3
    assert client.get("/api/v1/admin/audit", params={"since": 4_000_000_000}).json()["rows"] == []


def test_markup_labels_and_hidden_tabs():
    html = text("index.html")
    for tab in ("tab-keys", "tab-audit"):
        assert re.search(rf'<button type="button" id="{tab}"[^>]*\bhidden>', html)
    for fid in ("k-owner", "a-kind", "a-actor", "a-since"):
        assert f'<label for="{fid}">' in html and f'id="{fid}"' in html
    assert "<legend>Scopes</legend>" in html
    for name in ("Prefix", "Owner", "Scopes", "Action", "Actor", "Kind", "Detail"):
        assert f'<th scope="col">{name}</th>' in html
    assert 'id="secret-box" role="alert" hidden' in html


def test_script_is_text_only_sends_csrf_and_clears_secret():
    js = text("app.js")
    assert "innerHTML" not in js and "outerHTML" not in js and "document.write" not in js
    assert "/api/v1/admin/keys" in js and "/api/v1/admin/audit?" in js and "/revoke" in js
    # Every non-GET admin request goes through apiSend, which sets the CSRF header.
    assert 'return apiSend("POST", path, body)' in js and js.count('method: method') == 1
    assert '"X-CSRF-Token"' in js
    assert not re.search(r'fetch\("/api/v1/admin[^)]*method', js)
    # The secret is cleared on view change, sign out and page hide, and revoking asks twice.
    assert js.count("clearSecret()") >= 4 and 'addEventListener("pagehide", clearSecret)' in js
    assert "Confirm revoke" in js
