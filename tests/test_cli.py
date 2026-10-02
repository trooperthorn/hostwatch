"""The operator CLI: bootstrap, users, keys, one-time secrets and audit rows."""

from __future__ import annotations

import io
import logging
import re

import pytest
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


def db_text(path) -> str:
    """Every table dumped as text, to prove a secret is not stored anywhere."""
    store = store_of(path)
    return "\n".join(store._db.iterdump())


def stdin(monkeypatch, text: str) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


def test_bootstrap_prints_password_once_and_never_logs_or_stores_it(env, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    assert main(["bootstrap-admin"]) == 0
    out = capsys.readouterr()
    password = out.out.strip()
    assert len(password) >= 20 and "\n" not in password
    assert out.out.count(password) == 1 and password not in out.err
    assert password not in caplog.text
    assert password not in db_text(env)
    cfg = Config()
    assert auth.check_login(store_of(env), cfg, "admin", password).ok
    row = store_of(env).audit_rows(kind="cli")[0]
    assert row["path"] == "bootstrap-admin" and row["status"] == 0
    assert password not in str(row)


def test_second_bootstrap_is_refused_and_audited(env, capsys):
    assert main(["bootstrap-admin"]) == 0
    first = capsys.readouterr().out.strip()
    assert main(["bootstrap-admin", "--username", "other"]) == 1
    out = capsys.readouterr()
    assert out.out == "" and "already exist" in out.err
    store = store_of(env)
    assert store.count_users() == 1 and store.get_user("other") is None
    assert auth.check_login(store, Config(), "admin", first).ok
    rows = store.audit_rows(kind="cli")
    assert rows[0]["status"] == 1 and rows[0]["detail"]["reason"].startswith("users already exist")


def test_bootstrap_refused_when_any_user_exists(env, monkeypatch, capsys):
    stdin(monkeypatch, PASSWORD + "\n")
    assert main(["user", "create", "alice"]) == 0
    assert main(["bootstrap-admin"]) == 1
    assert store_of(env).get_user("admin") is None


def test_user_create_reads_stdin_and_never_echoes_or_logs(env, monkeypatch, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    stdin(monkeypatch, PASSWORD + "\n")
    assert main(["user", "create", "alice"]) == 0
    out = capsys.readouterr()
    assert PASSWORD not in out.out + out.err and PASSWORD not in caplog.text
    assert PASSWORD not in db_text(env)
    assert auth.check_login(store_of(env), Config(), "alice", PASSWORD).ok
    stdin(monkeypatch, PASSWORD + "\n")
    assert main(["user", "create", "alice"]) == 1
    stdin(monkeypatch, "short\n")
    assert main(["user", "create", "bob"]) == 1
    assert store_of(env).get_user("bob") is None


def test_passwd_changes_password_and_revokes_sessions(env, monkeypatch):
    stdin(monkeypatch, PASSWORD + "\n")
    main(["user", "create", "alice"])
    store = store_of(env)
    token = store.create_session(store.get_user("alice")["id"], 3600)
    stdin(monkeypatch, "another long password\n")
    assert main(["user", "passwd", "alice"]) == 0
    store = store_of(env)
    assert store.get_session(token) is None
    cfg = Config()
    assert not auth.check_login(store, cfg, "alice", PASSWORD).ok
    assert auth.check_login(store, cfg, "alice", "another long password").ok
    assert main(["user", "passwd", "nobody"]) == 1


def test_disable_and_unlock(env, monkeypatch):
    stdin(monkeypatch, PASSWORD + "\n")
    main(["user", "create", "alice"])
    store = store_of(env)
    cfg = Config()
    token = store.create_session(store.get_user("alice")["id"], 3600)
    assert main(["user", "disable", "alice"]) == 0
    store = store_of(env)
    assert store.get_session(token) is None
    assert auth.check_login(store, cfg, "alice", PASSWORD).reason == "disabled"
    store.set_user_disabled("alice", False)
    for _ in range(cfg.login_max_failures):
        auth.check_login(store, cfg, "alice", "wrong")
    assert auth.check_login(store, cfg, "alice", PASSWORD).reason == "locked"
    assert main(["user", "unlock", "alice"]) == 0
    assert auth.check_login(store_of(env), cfg, "alice", PASSWORD).ok
    assert main(["user", "unlock", "nobody"]) == 1


def test_key_secret_printed_once_and_revoked_key_fails_at_hub(env, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    assert main(["key", "create", "--scopes", "read:metrics,read:events", "--owner", "ha"]) == 0
    out = capsys.readouterr()
    secret = out.out.strip()
    assert secret.startswith("hw_") and out.out.count(secret) == 1 and secret not in out.err
    assert secret not in caplog.text and secret not in db_text(env)
    assert main(["key", "list"]) == 0
    listing = capsys.readouterr()
    assert secret not in listing.out + listing.err
    assert "read:events,read:metrics" in listing.out and "active" in listing.out
    key_id = int(listing.out.split("\t")[0])

    store = store_of(env)
    client = TestClient(create_app(Config(), store))
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/internal/v1/latest", headers=headers).status_code == 200

    assert main(["key", "revoke", str(key_id)]) == 0
    capsys.readouterr()
    assert client.get("/internal/v1/latest", headers=headers).status_code == 401
    assert main(["key", "revoke", str(key_id)]) == 1
    assert main(["key", "list"]) == 0
    assert "revoked" in capsys.readouterr().out
    assert re.search(r"cli", store.audit_rows(kind="cli")[-1]["actor"])


def test_key_create_rejects_unknown_scope_without_output(env, capsys):
    assert main(["key", "create", "--scopes", "root"]) == 1
    out = capsys.readouterr()
    assert out.out == "" and "unknown scope" in out.err
    assert store_of(env).list_api_keys() == []


def test_every_action_writes_an_audit_row(env, monkeypatch, capsys):
    stdin(monkeypatch, PASSWORD + "\n")
    main(["user", "create", "alice"])
    main(["user", "unlock", "alice"])
    main(["user", "disable", "alice"])
    main(["key", "create", "--scopes", "ingest"])
    main(["key", "list"])
    main(["key", "revoke", "1"])
    paths = [r["path"] for r in store_of(env).audit_rows(kind="cli")]
    assert sorted(paths) == sorted(["user create", "user unlock", "user disable",
                                    "key create", "key list", "key revoke"])
    assert PASSWORD not in db_text(env)


def test_cert_bind_authenticates_proxy_request_and_revoke_gives_401(env, monkeypatch, capsys):
    from hostwatch.mtls import SUBJECT_HEADER, VERIFY_HEADER
    stdin(monkeypatch, PASSWORD + "\n")
    assert main(["user", "create", "alice"]) == 0
    assert main(["cert", "bind", "CN=alice-yubikey,O=Lab", "alice"]) == 0
    capsys.readouterr()
    cfg = Config(data_dir=env, mtls_mode="proxy", mtls_trusted_proxies="10.0.0.0/24")
    store = store_of(env)
    client = TestClient(create_app(cfg, store), client=("10.0.0.5", 40000))
    headers = {VERIFY_HEADER: "SUCCESS", SUBJECT_HEADER: "CN=alice-yubikey,O=Lab"}
    assert client.get("/internal/v1/latest", headers=headers).status_code == 200
    assert main(["cert", "list"]) == 0
    assert "CN=alice-yubikey,O=Lab\talice" in capsys.readouterr().out
    assert main(["cert", "revoke", "CN=alice-yubikey,O=Lab"]) == 0
    assert client.get("/internal/v1/latest", headers=headers).status_code == 401
    assert main(["cert", "revoke", "CN=alice-yubikey,O=Lab"]) == 1
    assert main(["cert", "bind", "CN=x", "nobody"]) == 1
    paths = [r["path"] for r in store.audit_rows(kind="cli")]
    assert paths.count("cert bind") == 2 and paths.count("cert revoke") == 2 and "cert list" in paths


def test_cookie_plus_bearer_is_400_and_audited(env, monkeypatch):
    stdin(monkeypatch, PASSWORD + "\n")
    main(["user", "create", "alice"])
    store = store_of(env)
    cfg = Config(data_dir=env, argon2_time_cost=1, argon2_memory_kib=8, argon2_parallelism=1)
    client = TestClient(create_app(cfg, store))
    assert client.post("/api/v1/login", json={"username": "alice", "password": PASSWORD}).status_code == 200
    assert client.get("/internal/v1/latest").status_code == 200
    r = client.get("/internal/v1/latest", headers={"Authorization": "Bearer something"})
    assert r.status_code == 400
    row = store.audit_rows()[0]
    assert row["status"] == 400 and row["kind"] == "auth_failure"
    assert row["detail"]["credentials"] == ["session_cookie", "bearer"]
