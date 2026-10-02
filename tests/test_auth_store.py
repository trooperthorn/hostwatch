"""Store-level tests for users, sessions, API keys and the audit log (schema version 4)."""

import sqlite3

import pytest

from hostwatch.store import Store


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "db.sqlite")


def test_user_round_trip_and_unique_username(store):
    uid = store.create_user("alice", "hash-value", now=10.0)
    u = store.get_user("alice")
    assert u["id"] == uid and u["hash"] == "hash-value" and u["disabled"] == 0 and u["created"] == 10.0
    assert store.get_user("nobody") is None
    with pytest.raises(sqlite3.IntegrityError):
        store.create_user("alice", "other")


def test_login_failures_lock_and_reset(store):
    store.create_user("alice", "h")
    assert store.record_login_failure("nobody", 3, 60) is None
    for _ in range(2):
        u = store.record_login_failure("alice", 3, 60, now=100.0)
    assert u["failed_count"] == 2 and u["locked_until"] is None
    u = store.record_login_failure("alice", 3, 60, now=100.0)
    assert u["locked_until"] == 160.0 and u["failed_count"] == 0
    store.reset_failures("alice")
    assert store.get_user("alice")["locked_until"] is None


def test_session_lifecycle_and_hashed_storage(store):
    uid = store.create_user("alice", "h")
    token = store.create_session(uid, 100, now=1000.0)
    stored = [r[0] for r in store._db.execute("SELECT id_hash FROM sessions")]
    assert stored and token not in stored
    s = store.get_session(token, now=1050.0)
    assert s["username"] == "alice" and s["last_seen"] == 1050.0
    assert store.get_session(token, now=1100.0) is None  # expired
    assert store.get_session("bogus", now=1050.0) is None
    t2 = store.create_session(uid, 100, now=1000.0)
    assert store.revoke_session(t2) is True
    assert store.get_session(t2, now=1001.0) is None
    assert store.revoke_session(t2) is False


def test_disabled_user_session_is_rejected(store):
    uid = store.create_user("alice", "h")
    token = store.create_session(uid, 100, now=1.0)
    store._db.execute("UPDATE users SET disabled = 1")
    assert store.get_session(token, now=2.0) is None


def test_api_key_round_trip_and_revocation(store):
    key, row = store.create_api_key(["ingest", "read"], "ha", now=5.0)
    assert row["scopes"] == ["ingest", "read"] and key.startswith("hw_")
    stored_hash = store._db.execute("SELECT hash FROM api_keys").fetchone()[0]
    assert stored_hash != key and key not in stored_hash
    found = store.find_api_key(key, now=6.0)
    assert found["id"] == row["id"] and found["owner"] == "ha" and found["last_used"] == 6.0
    assert "hash" not in found
    assert store.find_api_key(key + "x") is None
    assert store.find_api_key("not-a-key") is None
    assert store.revoke_api_key(row["id"], now=7.0) is True
    assert store.find_api_key(key) is None  # revoked: not returned as active
    assert store.revoke_api_key(row["id"]) is False


def test_audit_append_and_query(store):
    a = store.append_audit("alice", "access", "GET", "/api/x", 200, "127.0.0.1", {"k": 1}, now=1.0)
    b = store.append_audit("-", "auth_failure", "GET", "/api/y", 401, "10.0.0.1", now=2.0)
    rows = store.audit_rows()
    assert [r["id"] for r in rows] == [b, a]
    assert rows[1]["detail"] == {"k": 1}
    assert [r["id"] for r in store.audit_rows(kind="auth_failure")] == [b]
    assert [r["id"] for r in store.audit_rows(actor="alice")] == [a]
    assert [r["id"] for r in store.audit_rows(before_id=b)] == [a]
    assert not any(n in dir(Store) for n in ("update_audit", "delete_audit"))


def test_audit_update_and_delete_are_aborted(store):
    store.append_audit("alice", "access", "GET", "/x", 200, "127.0.0.1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("UPDATE audit_log SET status = 500")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("DELETE FROM audit_log")
    assert store.audit_rows()[0]["status"] == 200
