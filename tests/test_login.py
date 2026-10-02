"""Login, logout, session cookie, lockout, uniform failures, CSRF and audit rows over HTTP."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import CSRF_COOKIE, SESSION_COOKIE, create_app
from hostwatch.store import Store

PASSWORD = "correct horse battery"


def build(tmp_path, **over):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1, login_max_failures=3, login_lock_s=600.0, **over)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(cfg, PASSWORD))
    return TestClient(create_app(cfg, store)), store


@pytest.fixture
def env(tmp_path):
    return build(tmp_path)


def login(client, user="alice", pw=PASSWORD):
    return client.post("/api/v1/login", json={"username": user, "password": pw})


def test_login_sets_cookie_with_attributes(tmp_path):
    client, store = build(tmp_path, tls_enabled=True)
    r = login(client)
    assert r.status_code == 200 and r.json()["username"] == "alice"
    cookies = {c.split("=", 1)[0]: c for c in r.headers.get_list("set-cookie")}
    sess = cookies[SESSION_COOKIE].lower()
    assert "httponly" in sess and "secure" in sess and "samesite=strict" in sess
    assert "path=/" in sess and "max-age=28800" in sess
    csrf = cookies[CSRF_COOKIE].lower()
    assert "httponly" not in csrf and "secure" in csrf and "samesite=strict" in csrf
    token = client.cookies.get(SESSION_COOKIE)
    assert token not in str(store._db.execute("SELECT id_hash FROM sessions").fetchall())
    secure_client = TestClient(client.app, base_url="https://testserver")
    secure_client.cookies.set(SESSION_COOKIE, token)
    assert secure_client.get("/internal/v1/latest").status_code == 200


def test_cookie_not_secure_without_tls(env):
    client, _ = env
    sess = [c for c in login(client).headers.get_list("set-cookie") if c.startswith(SESSION_COOKIE)][0]
    assert "secure" not in sess.lower() and "httponly" in sess.lower()


def test_logout_revokes_session_server_side(env):
    client, store = env
    csrf = login(client).json()["csrf_token"]
    stale = client.cookies.get(SESSION_COOKIE)
    assert client.post("/api/v1/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    reused = TestClient(client.app)
    reused.cookies.set(SESSION_COOKIE, stale)
    assert reused.get("/internal/v1/latest").status_code == 401
    assert store.get_session(stale) is None
    kinds = [a["kind"] for a in store.audit_rows()]
    assert "logout" in kinds


def test_lockout_after_bad_attempts_even_with_correct_password(env):
    client, store = env
    for _ in range(3):
        assert login(client, pw="wrong").status_code == 401
    r = login(client)
    assert r.status_code == 401
    assert SESSION_COOKIE not in r.headers.get("set-cookie", "")
    reasons = [a["detail"] for a in store.audit_rows(kind="auth_failure")]
    assert any('"locked"' in str(d) or "locked" in str(d) for d in reasons)


def test_unknown_user_and_wrong_password_and_locked_look_identical(env):
    client, _ = env
    unknown = login(client, user="nobody", pw="whatever")
    wrong = login(client, pw="wrong")
    for _ in range(2):
        login(client, pw="wrong")
    locked = login(client)
    for r in (wrong, locked):
        assert (r.status_code, r.content) == (unknown.status_code, unknown.content)
        assert r.headers.get("set-cookie") is None
    assert unknown.status_code == 401


def test_cookie_post_without_csrf_rejected(env):
    client, store = env
    csrf = login(client).json()["csrf_token"]
    assert client.post("/api/v1/logout").status_code == 403
    assert client.post("/api/v1/logout", headers={"X-CSRF-Token": "bad"}).status_code == 403
    # The failed attempts did not revoke the session.
    assert client.get("/internal/v1/latest").status_code == 200
    assert client.post("/api/v1/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert any("CSRF" in str(a["detail"]) for a in store.audit_rows(kind="auth_failure"))


def test_csrf_token_from_another_session_rejected(env):
    client, _ = env
    login(client)
    other = TestClient(client.app)
    other_csrf = login(other).json()["csrf_token"]
    assert client.post("/api/v1/logout", headers={"X-CSRF-Token": other_csrf}).status_code == 403


def test_every_attempt_is_audited_without_secrets(env):
    client, store = env
    login(client, user="nobody", pw="secret-one")
    login(client, pw="secret-two")
    login(client)
    rows = list(reversed(store.audit_rows()))
    assert [(r["kind"], r["status"]) for r in rows] == [("auth_failure", 401), ("auth_failure", 401), ("login", 200)]
    assert rows[0]["actor"] == "anonymous" and "nobody" not in str(rows[0]["detail"]) and rows[0]["detail"]["unknown_user"]
    assert rows[2]["actor"] == "alice"
    dump = str(rows)
    assert "secret-one" not in dump and "secret-two" not in dump and PASSWORD not in dump
    assert client.cookies.get(SESSION_COOKIE) not in dump


def test_logout_without_session_is_unauthorized(env):
    client, _ = env
    assert client.post("/api/v1/logout").status_code == 401


# ---- Audit privacy, completeness and the Secure flag (pre-production audit fixes) ----

def _session_cookie_header(resp):
    return [c for c in resp.headers.get_list("set-cookie") if c.startswith(SESSION_COOKIE)][0].lower()


def test_cookie_secure_when_hub_terminates_tls(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("x")
    key.write_text("x")
    client, _ = build(tmp_path, tls_cert=str(cert), tls_key=str(key))
    assert client.app and "secure" in _session_cookie_header(login(client))
    csrf = login(client).json()["csrf_token"]
    out = client.post("/api/v1/logout", headers={"X-CSRF-Token": csrf})
    assert all("secure" in c.lower() for c in out.headers.get_list("set-cookie"))


def test_password_typed_as_username_is_never_audited_and_attempts_correlate(tmp_path, caplog):
    client, store = build(tmp_path)
    typed = "Tr0ub4dor&3-typed-in-the-wrong-box"
    login(client, user=typed, pw="whatever")
    login(client, user=typed, pw="other")
    login(client, user="someone-else", pw="x")
    dump = repr(store._db.execute("SELECT * FROM audit_log").fetchall()) + caplog.text
    assert typed not in dump and "someone-else" not in dump
    rows = store.audit_rows(kind="auth_failure")
    unknown = [r for r in rows if r["detail"].get("unknown_user")]
    assert len(unknown) == 3 and all("username_attempted" not in r["detail"] for r in unknown)
    by_hmac = {}
    for r in unknown:
        by_hmac[r["detail"]["username_hmac"]] = by_hmac.get(r["detail"]["username_hmac"], 0) + 1
    assert sorted(by_hmac.values()) == [1, 2]  # the repeated name shares one HMAC, the other differs


def test_existing_username_is_still_recorded(env):
    client, store = env
    login(client, pw="wrong password")
    d = store.audit_rows(kind="auth_failure")[0]["detail"]
    assert d["username_attempted"] == "alice" and "unknown_user" not in d


def test_revoked_key_records_prefix_and_reason(env):
    client, store = env
    full, row = auth.generate_api_key(store, "read:metrics", "t")
    store.revoke_api_key(row["id"])
    assert client.get("/internal/v1/latest", headers={"Authorization": f"Bearer {full}"}).status_code == 401
    d = store.audit_rows(kind="auth_failure")[0]["detail"]
    assert d["key_prefix"] == row["prefix"] and d["key_reason"] == "revoked"
    assert full not in repr(store._db.execute("SELECT * FROM audit_log").fetchall())


def test_unknown_and_bad_secret_keys(env):
    client, store = env
    full, row = auth.generate_api_key(store, "read:metrics", "t")
    bad = f"hw_{row['prefix']}_not-the-secret"
    unknown = "hw_deadbeef_whatever"
    for k in (bad, unknown):
        client.get("/internal/v1/latest", headers={"Authorization": f"Bearer {k}"})
    rows = {r["detail"]["key_reason"]: r["detail"] for r in store.audit_rows(kind="auth_failure")}
    assert rows["bad_secret"]["key_prefix"] == row["prefix"]
    assert rows["unknown"].get("key_prefix") is None
    assert "deadbeef" not in repr(store._db.execute("SELECT * FROM audit_log").fetchall())


def test_route_that_raises_still_leaves_an_audit_row(tmp_path):
    client, store = build(tmp_path)
    full, _ = auth.generate_api_key(store, "read:metrics", "t")

    def boom(*a, **k):
        raise RuntimeError("store exploded")
    store.latest = boom
    c = TestClient(client.app, raise_server_exceptions=False)
    assert c.get("/internal/v1/latest", headers={"Authorization": f"Bearer {full}"}).status_code == 500
    row = [r for r in store.audit_rows() if r["path"] == "/internal/v1/latest"][0]
    assert row["status"] == 500 and row["actor"].startswith("key:")


def test_method_not_allowed_after_credentials_is_audited(env):
    client, store = env
    full, _ = auth.generate_api_key(store, "read:metrics", "t")
    r = client.delete("/internal/v1/latest", headers={"Authorization": f"Bearer {full}"})
    assert r.status_code == 405
    row = store.audit_rows()[0]
    assert row["status"] == 405 and row["method"] == "DELETE"
    n = len(store.audit_rows())
    client.delete("/internal/v1/latest")  # no credentials: scanner noise stays out
    assert len(store.audit_rows()) == n
