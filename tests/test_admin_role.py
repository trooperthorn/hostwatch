"""The users.is_admin flag, the CLI that toggles it and the require_admin dependency."""

from __future__ import annotations

import io

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.__main__ import main
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.store import Store

PASSWORD = "a long enough password"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOSTWATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HOSTWATCH_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("HOSTWATCH_ARGON2_MEMORY_KIB", "8")
    monkeypatch.setenv("HOSTWATCH_ARGON2_PARALLELISM", "1")
    return tmp_path


def store_of(path) -> Store:
    return Store(path / "hostwatch.db")


def make_user(monkeypatch, name):
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert main(["user", "create", name]) == 0


def app_for(path):
    cfg = Config()
    store = store_of(path)
    app = create_app(cfg, store)
    app.add_api_route("/test/admin-only", lambda: {"ok": True}, dependencies=[Depends(app.state.require_admin)])
    return TestClient(app), store, cfg


def test_bootstrap_creates_an_admin(env):
    assert main(["bootstrap-admin"]) == 0
    assert store_of(env).get_user("admin")["is_admin"] == 1


def test_new_users_are_not_admin_and_cli_toggles_with_audit(env, monkeypatch, capsys):
    make_user(monkeypatch, "alice")
    assert store_of(env).get_user("alice")["is_admin"] == 0
    assert main(["user", "grant-admin", "alice"]) == 0
    assert store_of(env).get_user("alice")["is_admin"] == 1
    assert main(["user", "revoke-admin", "alice"]) == 0
    assert store_of(env).get_user("alice")["is_admin"] == 0
    assert main(["user", "grant-admin", "nobody"]) == 1
    rows = store_of(env).audit_rows(kind="cli")
    assert [(r["path"], r["status"]) for r in rows][:3] == [
        ("user grant-admin", 1), ("user revoke-admin", 0), ("user grant-admin", 0)]


def test_session_is_admin_only_for_admin_users(env, monkeypatch):
    make_user(monkeypatch, "alice")
    make_user(monkeypatch, "bob")
    main(["user", "grant-admin", "alice"])
    client, store, cfg = app_for(env)
    alice = client.post("/api/v1/login", json={"username": "alice", "password": PASSWORD})
    assert alice.status_code == 200
    assert client.get("/test/admin-only").json() == {"ok": True}
    client.post("/api/v1/logout", headers={"X-CSRF-Token": alice.json()["csrf_token"]})
    client.cookies.clear()
    assert client.post("/api/v1/login", json={"username": "bob", "password": PASSWORD}).status_code == 200
    assert client.get("/test/admin-only").status_code == 403


def test_revoking_admin_takes_effect_on_the_live_session(env, monkeypatch):
    make_user(monkeypatch, "alice")
    main(["user", "grant-admin", "alice"])
    client, store, cfg = app_for(env)
    client.post("/api/v1/login", json={"username": "alice", "password": PASSWORD})
    assert client.get("/test/admin-only").status_code == 200
    store.set_user_admin("alice", False)
    assert client.get("/test/admin-only").status_code == 403


def test_api_keys_need_the_admin_scope(env):
    client, store, cfg = app_for(env)
    admin_secret, _ = auth.generate_api_key(store, "admin", "t")
    reader_secret, _ = auth.generate_api_key(store, "read:metrics,read:events", "t")
    assert client.get("/test/admin-only", headers={"Authorization": f"Bearer {admin_secret}"}).status_code == 200
    assert client.get("/test/admin-only", headers={"Authorization": f"Bearer {reader_secret}"}).status_code == 403
    assert client.get("/test/admin-only").status_code == 401
