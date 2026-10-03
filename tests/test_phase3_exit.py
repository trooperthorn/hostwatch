"""Phase 3 exit criteria, asserted together over HTTP.

1. No endpoint except health answers without a session or key.
2. A revoked key is rejected on its next request.
3. Every access and every authentication failure is audited.
"""

from __future__ import annotations

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import CSRF_HEADER, create_app
from hostwatch.schema import Batch, Sample, SourceStatus
from hostwatch.store import Store

PASSWORD = "correct horse battery"
HEALTH = "/internal/v1/health"
LOGIN = "/api/v1/login"


def build(tmp_path):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(cfg, PASSWORD))
    return TestClient(create_app(cfg, store)), store


def batch_body() -> str:
    return Batch(agent_version="test", host="h1", platform="x86", sent_at=100.0, batch_id="exit-1",
                 sources=[SourceStatus(source="rapl", available=True)],
                 samples=[Sample(source="rapl", metric="watts", value=1.0, unit="W", ts=100.0)],
                 events=[]).model_dump_json()


def fill_path(path: str) -> str:
    return path.replace("{host}", "h1")


def test_default_deny_across_every_route(tmp_path):
    client, store = build(tmp_path)
    routes = [r for r in client.app.routes if isinstance(r, APIRoute)]
    assert routes, "the app must expose routes for this test to mean anything"
    checked = []
    for route in routes:
        if route.path == HEALTH:
            continue
        for method in route.methods - {"HEAD", "OPTIONS"}:
            r = client.request(method, fill_path(route.path), content=b"{}",
                               headers={"Content-Type": "application/json"})
            assert r.status_code in (401, 422), (method, route.path, r.status_code)
            if route.path != LOGIN:
                assert r.status_code == 401, (method, route.path, r.status_code)
            assert "set-cookie" not in r.headers, (method, route.path)
            checked.append((method, route.path))
    assert ("GET", "/internal/v1/latest") in checked and ("POST", "/internal/v1/ingest") in checked
    # Wrong credentials of each kind are refused the same way.
    for headers in ({"Authorization": "Bearer hw_deadbeef_nope"}, {"Authorization": "Bearer " + "x" * 64},
                    {"Authorization": "Basic YWxpY2U6cHc="}):
        assert client.get("/internal/v1/latest", headers=headers).status_code == 401
    client.cookies.set("hostwatch_session", "not-a-session")
    assert client.get("/internal/v1/latest").status_code == 401
    assert client.get(HEALTH).status_code == 200


def test_revoked_key_is_rejected_on_its_next_request(tmp_path):
    client, store = build(tmp_path)
    secret, row = auth.generate_api_key(store, "read:metrics,read:events", "exit-test")
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/internal/v1/latest", headers=headers).status_code == 200
    assert client.get("/internal/v1/events", headers=headers).status_code == 200
    assert store.revoke_api_key(row["id"])
    for path in ("/internal/v1/latest", "/internal/v1/events", "/internal/v1/sources"):
        assert client.get(path, headers=headers).status_code == 401
    failures = store.audit_rows(kind="auth_failure")
    assert len(failures) == 3 and all(f["status"] == 401 for f in failures)


def test_every_request_in_a_scripted_session_is_audited(tmp_path):
    client, store = build(tmp_path)
    key, row = auth.generate_api_key(store, "ingest,read:metrics", "exit-test", host="h1")
    keyh = {"Authorization": f"Bearer {key}"}

    keyclient = TestClient(client.app)  # no cookie jar shared with the session client

    def audited(method, path, using=None, **kw):
        before = len(store.audit_rows(limit=1000))
        r = (using or client).request(method, path, **kw)
        after = store.audit_rows(limit=1000)
        assert len(after) == before + 1, (method, path, r.status_code)
        return r, after[0]

    r, a = audited("POST", LOGIN, json={"username": "alice", "password": "wrong password"})
    assert r.status_code == 401 and a["kind"] == "auth_failure" and a["status"] == 401
    r, a = audited("POST", LOGIN, json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 200 and a["kind"] == "login" and a["actor"] == "alice"
    csrf = r.json()["csrf_token"]
    for path in ("/internal/v1/latest", "/internal/v1/sources", "/internal/v1/events"):
        r, a = audited("GET", path)
        assert r.status_code == 200 and a["kind"] == "access" and a["actor"] == "alice" and a["path"] == path
    r, a = audited("GET", "/internal/v1/gaps?host=h1&source=rapl&metric=watts")
    assert r.status_code == 200 and a["kind"] == "access"
    r, a = audited("POST", "/internal/v1/ingest", content=batch_body(),
                   headers={"Content-Type": "application/json", CSRF_HEADER: csrf})
    assert r.status_code == 403 and a["kind"] == "auth_failure"  # a session never holds the ingest scope
    r, a = audited("POST", "/internal/v1/ingest", using=keyclient, content=batch_body(),
                   headers={"Content-Type": "application/json", **keyh})
    assert r.status_code == 200 and a["kind"] == "access" and a["actor"] == f"key:{row['prefix']}"
    r, a = audited("POST", "/api/v1/logout", headers={CSRF_HEADER: csrf})
    assert r.status_code == 200 and a["kind"] == "logout"
    r, a = audited("GET", "/internal/v1/latest")
    assert r.status_code == 401 and a["kind"] == "auth_failure" and a["actor"] == "anonymous"
    # Health is the only unaudited route.
    before = len(store.audit_rows(limit=1000))
    assert client.get(HEALTH).status_code == 200
    assert len(store.audit_rows(limit=1000)) == before
    # No secret reached the log.
    dump = str(store.audit_rows(limit=1000))
    assert key not in dump and PASSWORD not in dump and "wrong password" not in dump
