"""Admin endpoints for API keys and the audit log."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.store import Store

PASSWORD = "a long enough password"


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("HOSTWATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HOSTWATCH_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("HOSTWATCH_ARGON2_MEMORY_KIB", "8")
    monkeypatch.setenv("HOSTWATCH_ARGON2_PARALLELISM", "1")
    cfg = Config()
    store = Store(tmp_path / "hostwatch.db")
    for name, admin in (("alice", True), ("bob", False)):
        store.create_user(name, auth.hash_password(cfg, PASSWORD))
        store.set_user_admin(name, admin)
    return TestClient(create_app(cfg, store)), store


def login(client, name):
    r = client.post("/api/v1/login", json={"username": name, "password": PASSWORD})
    assert r.status_code == 200
    return {"X-CSRF-Token": r.json()["csrf_token"]}


def test_create_shows_secret_once_and_list_never_does(ctx):
    client, store = ctx
    csrf = login(client, "alice")
    r = client.post("/api/v1/admin/keys", json={"scopes": ["read:metrics"], "owner": "ha"}, headers=csrf)
    assert r.status_code == 201
    assert r.headers["cache-control"] == "no-store"
    secret = r.json()["secret"]
    assert secret.startswith("hw_")
    listing = client.get("/api/v1/admin/keys")
    assert listing.status_code == 200
    assert secret not in listing.text
    assert "hash" not in listing.text and "secret" not in listing.text
    keys = listing.json()["keys"]
    assert [k["owner"] for k in keys] == ["ha"]
    assert keys[0]["id"] == r.json()["key"]["id"]


def test_create_rejects_unknown_scope(ctx):
    client, _ = ctx
    csrf = login(client, "alice")
    r = client.post("/api/v1/admin/keys", json={"scopes": ["root"], "owner": "x"}, headers=csrf)
    assert r.status_code == 422


def test_revoke_disables_the_key_on_its_next_request(ctx):
    client, store = ctx
    csrf = login(client, "alice")
    created = client.post("/api/v1/admin/keys", json={"scopes": ["read:metrics"], "owner": "ha"}, headers=csrf).json()
    bearer = {"Authorization": f"Bearer {created['secret']}"}
    other = TestClient(client.app)
    assert other.get("/internal/v1/latest", headers=bearer).status_code == 200
    r = client.post(f"/api/v1/admin/keys/{created['key']['id']}/revoke", headers=csrf)
    assert r.status_code == 200
    assert other.get("/internal/v1/latest", headers=bearer).status_code == 401
    assert client.post("/api/v1/admin/keys/9999/revoke", headers=csrf).status_code == 404
    assert client.get("/api/v1/admin/keys").json()["keys"][0]["revoked_at"] is not None


def test_non_admin_gets_403_on_every_route(ctx):
    client, _ = ctx
    csrf = login(client, "bob")
    assert client.get("/api/v1/admin/keys").status_code == 403
    assert client.post("/api/v1/admin/keys", json={"scopes": ["read:metrics"], "owner": "x"},
                       headers=csrf).status_code == 403
    assert client.post("/api/v1/admin/keys/1/revoke", headers=csrf).status_code == 403
    assert client.get("/api/v1/admin/audit").status_code == 403


def test_anonymous_gets_401(ctx):
    client, _ = ctx
    assert client.get("/api/v1/admin/keys").status_code == 401
    assert client.get("/api/v1/admin/audit").status_code == 401


def test_missing_csrf_header_gets_403_and_changes_nothing(ctx):
    client, store = ctx
    login(client, "alice")
    r = client.post("/api/v1/admin/keys", json={"scopes": ["read:metrics"], "owner": "x"})
    assert r.status_code == 403
    assert store.list_api_keys() == []
    _, row = auth.generate_api_key(store, "read:metrics", "t")
    assert client.post(f"/api/v1/admin/keys/{row['id']}/revoke").status_code == 403
    assert store.list_api_keys()[0]["revoked_at"] is None


def test_create_and_revoke_are_audited_without_the_secret(ctx):
    client, store = ctx
    csrf = login(client, "alice")
    created = client.post("/api/v1/admin/keys", json={"scopes": ["read:events"], "owner": "ha"}, headers=csrf).json()
    client.post(f"/api/v1/admin/keys/{created['key']['id']}/revoke", headers=csrf)
    made = store.audit_rows(kind="api_key_create")
    gone = store.audit_rows(kind="api_key_revoke")
    assert made[0]["actor"] == "alice" and made[0]["detail"]["key_id"] == created["key"]["id"]
    assert gone[0]["detail"]["key_id"] == created["key"]["id"]
    assert created["secret"] not in json.dumps(store.audit_rows(limit=500))


def test_audit_filters(ctx):
    client, store = ctx
    store.append_audit("carol", "custom", "GET", "/x", 200, "127.0.0.1", {}, now=100.0)
    store.append_audit("dave", "custom", "GET", "/y", 200, "127.0.0.1", {}, now=200.0)
    store.append_audit("carol", "other", "GET", "/z", 200, "127.0.0.1", {}, now=300.0)
    login(client, "alice")

    def paths(**params):
        r = client.get("/api/v1/admin/audit", params=params)
        assert r.status_code == 200
        return [row["path"] for row in r.json()["rows"]]

    assert paths(kind="custom") == ["/y", "/x"]
    assert paths(actor="carol", kind="custom") == ["/x"]
    assert paths(kind="custom", since=150) == ["/y"]
    assert paths(kind="custom", until=150) == ["/x"]
    assert len(paths(limit=2)) == 2
    first = client.get("/api/v1/admin/audit", params={"kind": "custom"}).json()["rows"]
    assert paths(kind="custom", before_id=first[0]["id"]) == ["/x"]
    assert client.get("/api/v1/admin/audit", params={"limit": 0}).status_code == 422


def test_audit_is_read_only(ctx):
    client, _ = ctx
    csrf = login(client, "alice")
    for method in ("post", "put", "delete", "patch"):
        assert getattr(client, method)("/api/v1/admin/audit", headers=csrf).status_code == 405
