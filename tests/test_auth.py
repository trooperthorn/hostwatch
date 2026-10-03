"""Password hashing, lockout and key primitives, with low argon2 cost and an injected clock."""

import pytest

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.store import Store


@pytest.fixture
def cfg():
    return Config(argon2_time_cost=1, argon2_memory_kib=8, argon2_parallelism=1,
                  login_max_failures=3, login_lock_s=60.0)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "db.sqlite")


def _user(store, cfg, pw="correct horse"):
    store.create_user("alice", auth.hash_password(cfg, pw), now=0.0)


def test_hash_round_trip_and_wrong_password(cfg):
    h = auth.hash_password(cfg, "s3cret")
    assert h.startswith("$argon2id$") and "s3cret" not in h
    assert auth.verify_password(cfg, h, "s3cret")
    assert not auth.verify_password(cfg, h, "wrong")
    assert not auth.verify_password(cfg, "not-a-hash", "s3cret")


def test_needs_rehash_when_cost_changes(cfg):
    h = auth.hash_password(cfg, "x")
    assert not auth.needs_rehash(cfg, h)
    stronger = Config(argon2_time_cost=2, argon2_memory_kib=8, argon2_parallelism=1)
    assert auth.needs_rehash(stronger, h)


def test_login_success_and_wrong_password(store, cfg):
    _user(store, cfg)
    assert auth.check_login(store, cfg, "alice", "correct horse", now=1.0).ok
    r = auth.check_login(store, cfg, "alice", "nope", now=1.0)
    assert not r.ok and r.reason == "bad_credentials"


def test_unknown_user_is_generic_failure(store, cfg):
    r = auth.check_login(store, cfg, "ghost", "x", now=1.0)
    assert not r.ok and r.reason == "bad_credentials"


def test_lockout_after_n_failures_and_unlock_after_window(store, cfg):
    _user(store, cfg)
    for _ in range(2):
        assert auth.check_login(store, cfg, "alice", "bad", now=100.0).reason == "bad_credentials"
    r = auth.check_login(store, cfg, "alice", "bad", now=100.0)
    assert r.reason == "locked" and r.locked_until == 160.0
    # The correct password is refused while locked and does not shorten the lock.
    r = auth.check_login(store, cfg, "alice", "correct horse", now=159.0)
    assert not r.ok and r.reason == "locked"
    assert auth.check_login(store, cfg, "alice", "correct horse", now=161.0).ok


def test_success_clears_failure_count(store, cfg):
    _user(store, cfg)
    for _ in range(2):
        auth.check_login(store, cfg, "alice", "bad", now=1.0)
    assert auth.check_login(store, cfg, "alice", "correct horse", now=2.0).ok
    for _ in range(2):
        assert auth.check_login(store, cfg, "alice", "bad", now=3.0).reason == "bad_credentials"


def test_login_upgrades_outdated_hash(store, cfg):
    store.create_user("bob", auth.hash_password(cfg, "pw"), now=0.0)
    newer = Config(argon2_time_cost=2, argon2_memory_kib=8, argon2_parallelism=1)
    before = store.get_user("bob")["hash"]
    assert auth.check_login(store, newer, "bob", "pw", now=1.0).ok
    after = store.get_user("bob")["hash"]
    assert after != before and not auth.needs_rehash(newer, after)


def test_api_key_secret_not_stored(store):
    secret, row = auth.generate_api_key(store, "ingest, read:metrics", "agent1", now=1.0, host="h1")
    assert secret.startswith("hw_") and row["scopes"] == ["ingest", "read:metrics"]
    dump = " ".join(str(v) for r in store._db.execute("SELECT * FROM api_keys") for v in r)
    assert secret not in dump
    assert secret.split("_", 2)[2] not in dump
    assert store.find_api_key(secret)["id"] == row["id"]


@pytest.mark.parametrize("bad", ["bogus", "ingest,root", "", ",", []])
def test_unknown_or_empty_scope_rejected(store, bad):
    with pytest.raises(ValueError):
        auth.generate_api_key(store, bad, "x")
    assert store._db.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0] == 0


def test_session_token_stored_only_as_hash(store):
    uid = store.create_user("alice", "h")
    token = auth.generate_session_token(store, uid, 100, now=10.0)
    stored = [r[0] for r in store._db.execute("SELECT id_hash FROM sessions")]
    assert stored and token not in stored
    assert store.get_session(token, now=20.0)["username"] == "alice"
