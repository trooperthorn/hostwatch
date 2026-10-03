"""Per-user dashboard preferences: round trip, validation, CSRF, isolation and key refusal."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.integrations.summary import GROUP_IDS
from hostwatch.store import Store

PASSWORD = "a long enough password"
URL = "/api/v1/me/preferences"


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("HOSTWATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HOSTWATCH_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("HOSTWATCH_ARGON2_MEMORY_KIB", "8")
    monkeypatch.setenv("HOSTWATCH_ARGON2_PARALLELISM", "1")
    cfg = Config()
    store = Store(tmp_path / "hostwatch.db")
    for name in ("alice", "bob"):
        store.create_user(name, auth.hash_password(cfg, PASSWORD))
    return create_app(cfg, store), store


def login(app, name):
    client = TestClient(app)
    r = client.post("/api/v1/login", json={"username": name, "password": PASSWORD})
    assert r.status_code == 200
    return client, {"X-CSRF-Token": r.json()["csrf_token"]}


def test_default_then_round_trip_of_view_and_order(ctx):
    app, _ = ctx
    client, csrf = login(app, "alice")
    first = client.get(URL).json()
    assert first["view"] == "expanded"
    assert [g["id"] for g in first["groups"]] == list(GROUP_IDS)
    body = {"view": "expert", "groups": [{"id": "fans", "visible": True}, {"id": "cpu", "visible": False},
                                         {"id": "fans", "visible": False}]}
    r = client.put(URL, json=body, headers=csrf)
    assert r.status_code == 200
    got = client.get(URL).json()
    assert got["view"] == "expert"
    ids = [g["id"] for g in got["groups"]]
    assert ids[:2] == ["fans", "cpu"] and sorted(ids) == sorted(GROUP_IDS)
    assert got["groups"][0]["visible"] is True and got["groups"][1]["visible"] is False
    assert all(g["visible"] for g in got["groups"][2:])


def test_invalid_view_or_group_is_422(ctx):
    app, _ = ctx
    client, csrf = login(app, "alice")
    assert client.put(URL, json={"view": "huge", "groups": []}, headers=csrf).status_code == 422
    assert client.put(URL, json={"view": "simple", "groups": [{"id": "nope"}]}, headers=csrf).status_code == 422
    assert client.put(URL, json={"groups": []}, headers=csrf).status_code == 422
    assert client.get(URL).json()["view"] == "expanded"


def test_put_without_csrf_is_403(ctx):
    app, _ = ctx
    client, _ = login(app, "alice")
    assert client.put(URL, json={"view": "simple", "groups": []}).status_code == 403
    assert client.get(URL).json()["view"] == "expanded"


def test_unauthenticated_is_401(ctx):
    app, _ = ctx
    assert TestClient(app).get(URL).status_code == 401


def test_users_only_see_and_change_their_own_row(ctx):
    app, _ = ctx
    alice, a_csrf = login(app, "alice")
    bob, b_csrf = login(app, "bob")
    assert alice.put(URL, json={"view": "simple", "groups": [{"id": "disks"}]}, headers=a_csrf).status_code == 200
    assert bob.get(URL).json()["view"] == "expanded"
    assert bob.put(URL, json={"view": "expert", "groups": []}, headers=b_csrf).status_code == 200
    assert alice.get(URL).json()["view"] == "simple"
    assert alice.get(URL).json()["groups"][0]["id"] == "disks"


def test_api_keys_cannot_use_the_endpoint(ctx):
    app, store = ctx
    secret, _ = auth.generate_api_key(store, ["admin"], "ha")
    bearer = {"Authorization": f"Bearer {secret}"}
    client = TestClient(app)
    assert client.get(URL, headers=bearer).status_code == 403
    assert client.put(URL, json={"view": "simple", "groups": []}, headers=bearer).status_code == 403
