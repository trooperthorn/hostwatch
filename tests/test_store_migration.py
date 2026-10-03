import sqlite3

import pytest

from hostwatch.store import SCHEMA_VERSION, SchemaTooNewError, Store

# The exact Phase 1 DDL, copied so the test does not follow later edits to store.py.
PHASE1_DDL = """
CREATE TABLE samples (
  ts REAL NOT NULL, host TEXT NOT NULL, source TEXT NOT NULL, metric TEXT NOT NULL,
  labels TEXT NOT NULL, value REAL, unit TEXT NOT NULL
);
CREATE INDEX samples_lookup ON samples(host, source, metric, ts);
CREATE INDEX samples_ts ON samples(ts);
CREATE TABLE rollup_hourly (
  hour REAL NOT NULL, host TEXT NOT NULL, source TEXT NOT NULL, metric TEXT NOT NULL,
  labels TEXT NOT NULL, n INTEGER NOT NULL, vmin REAL, vavg REAL, vmax REAL, unit TEXT NOT NULL,
  PRIMARY KEY (hour, host, source, metric, labels)
);
CREATE TABLE sources (
  host TEXT NOT NULL, source TEXT NOT NULL, available INTEGER NOT NULL,
  reason TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY (host, source)
);
CREATE TABLE agents (
  host TEXT PRIMARY KEY, platform TEXT NOT NULL, agent_version TEXT NOT NULL, last_seen REAL NOT NULL
);
"""


def make_phase1(path):
    db = sqlite3.connect(path)
    db.executescript(PHASE1_DDL)
    db.execute("INSERT INTO samples VALUES (100.0,'h1','cpu','load1','{}',0.5,'')")
    db.execute("INSERT INTO sources VALUES ('h1','cpu',1,'',100.0)")
    db.execute("INSERT INTO agents VALUES ('h1','linux','0.1',100.0)")
    db.commit()
    assert db.execute("PRAGMA user_version").fetchone()[0] == 0
    db.close()


def tables(path):
    db = sqlite3.connect(path)
    try:
        return {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        db.close()


def version(path):
    db = sqlite3.connect(path)
    try:
        return db.execute("PRAGMA user_version").fetchone()[0]
    finally:
        db.close()


def test_phase1_database_upgrades_in_place(tmp_path):
    p = tmp_path / "db.sqlite"
    make_phase1(p)
    store = Store(p)
    assert {"events", "boot_state"} <= tables(p)
    assert version(p) == 11
    assert store.agents()[0]["host"] == "h1"
    assert store.sources()[0]["source"] == "cpu"
    db = sqlite3.connect(p)
    assert db.execute("SELECT value FROM samples").fetchall() == [(0.5,)]
    db.close()


def test_migration_twice_is_noop(tmp_path):
    p = tmp_path / "db.sqlite"
    make_phase1(p)
    Store(p).add_events("h1", [{"ts": 1.0, "kind": "k", "severity": "info", "source": "s",
                                "title": "t", "dedup_key": "a"}])
    store = Store(p)
    store._migrate()
    assert version(p) == 11
    assert len(store.events("h1")) == 1


def test_future_version_is_refused(tmp_path):
    p = tmp_path / "db.sqlite"
    make_phase1(p)
    db = sqlite3.connect(p)
    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    db.close()
    with pytest.raises(SchemaTooNewError, match="supports up to"):
        Store(p)
    assert version(p) == 12
    assert "events" not in tables(p)


def test_event_dedup_and_query(tmp_path):
    store = Store(tmp_path / "db.sqlite")

    def ev(key, ts, kind="md_degraded"):
        return {"ts": ts, "kind": kind, "severity": "warn", "source": "mdraid", "title": "x",
                "detail": {"a": 1}, "dedup_key": key}

    assert store.add_events("h1", [ev("a", 10.0), ev("a", 10.0), ev("b", 20.0, "boot")]) == 2
    assert store.add_events("h1", [ev("a", 10.0)]) == 0
    assert store.add_events("h2", [ev("a", 10.0)]) == 1  # dedup is per host
    assert [e["dedup_key"] for e in store.events("h1")] == ["b", "a"]
    assert store.events("h1", since=15.0)[0]["dedup_key"] == "b"
    assert store.events("h1", kind="md_degraded")[0]["detail"] == {"a": 1}
    assert len(store.events("h1", limit=1)) == 1


V3_EXTRA_DDL = """
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL, ts REAL NOT NULL,
  kind TEXT NOT NULL, severity TEXT NOT NULL, source TEXT NOT NULL, title TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}', dedup_key TEXT NOT NULL, boot_id TEXT,
  UNIQUE (host, dedup_key)
);
CREATE TABLE boot_state (
  host TEXT PRIMARY KEY, boot_id TEXT, heartbeat_ts REAL NOT NULL, boot_ts REAL, clean_shutdown INTEGER
);
CREATE TABLE batch_ids (
  host TEXT NOT NULL, batch_id TEXT NOT NULL, received REAL NOT NULL, PRIMARY KEY (host, batch_id)
);
"""

AUTH_TABLES = {"users", "sessions", "api_keys", "cert_bindings", "audit_log"}


def make_v3(path):
    make_phase1(path)
    db = sqlite3.connect(path)
    db.executescript(V3_EXTRA_DDL)
    db.execute("INSERT INTO events (host, ts, kind, severity, source, title, dedup_key) "
               "VALUES ('h1',1.0,'k','info','s','t','a')")
    db.execute("INSERT INTO batch_ids VALUES ('h1','b1',100.0)")
    db.execute("PRAGMA user_version = 3")
    db.commit()
    db.close()


def test_v3_database_migrates_to_v4_with_rows_intact(tmp_path):
    p = tmp_path / "db.sqlite"
    make_v3(p)
    assert not (AUTH_TABLES & tables(p))
    store = Store(p)
    assert version(p) == 11
    assert AUTH_TABLES <= tables(p)
    assert len(store.events("h1")) == 1
    assert store.agents()[0]["host"] == "h1"
    db = sqlite3.connect(p)
    assert db.execute("SELECT batch_id FROM batch_ids").fetchall() == [("b1",)]
    assert db.execute("SELECT value FROM samples").fetchall() == [(0.5,)]
    db.close()


def test_v4_second_run_is_noop(tmp_path):
    p = tmp_path / "db.sqlite"
    make_v3(p)
    store = Store(p)
    store.append_audit("a", "k", "GET", "/x", 200, "127.0.0.1")
    store._migrate()
    Store(p)
    assert version(p) == 11
    assert len(store.audit_rows()) == 1


def test_v7_to_v8_adds_is_admin_marks_earliest_user_and_keeps_rows(tmp_path):
    assert SCHEMA_VERSION == 11
    p = tmp_path / "db.sqlite"
    store = Store(p)
    for i, name in enumerate(("first", "second", "third")):
        store.create_user(name, "hash-" + name, now=100.0 + i)
    store.add_events("h1", [{"ts": 1.0, "kind": "k", "severity": "info", "source": "s",
                             "title": "t", "dedup_key": "a"}])
    del store
    db = sqlite3.connect(p)
    db.execute("ALTER TABLE users DROP COLUMN is_admin")
    db.execute("PRAGMA user_version = 7")
    db.commit()
    db.close()
    upgraded = Store(p)
    assert version(p) == 11
    assert [(u["username"], u["hash"], u["is_admin"])
            for u in map(upgraded.get_user, ("first", "second", "third"))] == [
        ("first", "hash-first", 1), ("second", "hash-second", 0), ("third", "hash-third", 0)]
    assert len(upgraded.events("h1")) == 1
    upgraded._migrate()  # a repeat run changes nothing
    assert upgraded.get_user("second")["is_admin"] == 0


def test_v10_to_v11_adds_user_preferences_and_keeps_rows(tmp_path):
    p = tmp_path / "db.sqlite"
    store = Store(p)
    uid = store.create_user("first", "hash-first", now=100.0)
    store.add_events("h1", [{"ts": 1.0, "kind": "k", "severity": "info", "source": "s",
                             "title": "t", "dedup_key": "a"}])
    del store
    db = sqlite3.connect(p)
    db.execute("DROP TABLE user_preferences")
    db.execute("PRAGMA user_version = 10")
    db.commit()
    db.close()
    assert "user_preferences" not in tables(p)
    upgraded = Store(p)
    assert version(p) == 11
    assert "user_preferences" in tables(p)
    assert upgraded.get_user("first")["id"] == uid
    assert len(upgraded.events("h1")) == 1
    assert upgraded.get_preferences(uid) is None
    upgraded.set_preferences(uid, "expert", [{"id": "cpu", "visible": False}])
    upgraded._migrate()  # a repeat run changes nothing
    assert upgraded.get_preferences(uid)["view"] == "expert"
