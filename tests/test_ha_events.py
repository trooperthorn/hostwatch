"""Home Assistant events topic: publishing, cursor persistence, migration and hub wiring."""

from __future__ import annotations

import json
import sqlite3

import pytest

from hostwatch.__main__ import build_ha, chain
from hostwatch.config import Config
from hostwatch.integrations.ha_events import CURSOR_NAME, HomeAssistantEventPublisher
from hostwatch.integrations.mqtt_client import MqttClient
from hostwatch.store import SCHEMA_VERSION, SchemaTooNewError, Store
from tests.test_ha_discovery import FakeBroker, FakeTransport

TOPIC = "hostwatch/events"


def cfg_for(tmp_path, **kw):
    return Config(data_dir=tmp_path, mqtt_host="broker.test", argon2_time_cost=1, argon2_memory_kib=8,
                  argon2_parallelism=1, **kw)


def ev(key, source="boot", kind="boot.clean_shutdown", ts=1.0):
    return {"ts": ts, "kind": kind, "severity": "info", "source": source, "title": f"t {key}",
            "detail": {"k": key}, "dedup_key": key}


def make(cfg, store, broker):
    client = MqttClient(cfg, FakeTransport(broker), clock=lambda: 0.0)
    return HomeAssistantEventPublisher(cfg, client, store)


def events_sent(broker):
    return [json.loads(p) for t, p, _q, _r in broker.log if t == TOPIC]


def test_new_events_published_once_not_retained(tmp_path):
    cfg, store, broker = cfg_for(tmp_path), Store(tmp_path / "db.sqlite"), FakeBroker()
    store.add_events("h1", [ev("old")])
    pub = make(cfg, store, broker)
    assert pub.tick() == 0  # first run starts after existing history
    store.add_events("h1", [ev("a", "pstore", "crash"), ev("b", "journal", "journal.mce"),
                            ev("c", "mdraid_other", "x"), ev("d", "rasdaemon", "hardware_error"),
                            ev("e", "thresholds", "md.degraded")])
    assert pub.tick() == 4
    assert pub.tick() == 0
    sent = events_sent(broker)
    assert [e["detail"]["k"] for e in sent] == ["a", "b", "d", "e"]
    assert sent[0]["host"] == "h1" and sent[0]["id"] > 0
    assert all(retain is False for t, _p, _q, retain in broker.log if t == TOPIC)
    assert TOPIC not in broker.retained


def test_cursor_survives_restart_without_duplicates(tmp_path):
    cfg, broker = cfg_for(tmp_path), FakeBroker()
    store = Store(tmp_path / "db.sqlite")
    pub = make(cfg, store, broker)
    pub.tick()
    store.add_events("h1", [ev("a")])
    assert pub.tick() == 1
    store.add_events("h1", [ev("b")])  # arrives while the hub is down
    restarted = make(cfg, Store(tmp_path / "db.sqlite"), broker)
    assert restarted.tick() == 1
    assert restarted.tick() == 0
    assert [e["detail"]["k"] for e in events_sent(broker)] == ["a", "b"]


def test_failed_publish_keeps_cursor_and_retries(tmp_path):
    cfg, store, broker = cfg_for(tmp_path), Store(tmp_path / "db.sqlite"), FakeBroker()
    pub = make(cfg, store, broker)
    pub.tick()
    store.add_events("h1", [ev("a"), ev("b")])
    real = pub.client.publish
    pub.client.publish = lambda *a, **k: False
    assert pub.tick() == 0
    assert store.get_cursor(CURSOR_NAME) == 0
    pub.client.publish = real
    assert pub.tick() == 2
    assert [e["detail"]["k"] for e in events_sent(broker)] == ["a", "b"]


def test_migration_from_version_4_keeps_rows(tmp_path):
    p = tmp_path / "db.sqlite"
    store = Store(p)
    store.add_events("h1", [ev("a")])
    store.create_user("u", "hash")
    del store
    db = sqlite3.connect(p)
    db.execute("DROP TABLE publish_cursors")
    db.execute("PRAGMA user_version = 4")
    db.commit()
    db.close()
    upgraded = Store(p)
    assert SCHEMA_VERSION == 5
    assert len(upgraded.events("h1")) == 1
    assert upgraded.get_user("u") is not None
    upgraded.set_cursor("x", 3)
    assert Store(p).get_cursor("x") == 3  # guarded, so a second open changes nothing


def test_newer_version_is_refused(tmp_path):
    p = tmp_path / "db.sqlite"
    Store(p)
    db = sqlite3.connect(p)
    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    db.commit()
    db.close()
    with pytest.raises(SchemaTooNewError):
        Store(p)


def test_not_started_when_mqtt_unconfigured(tmp_path):
    cfg = Config(data_dir=tmp_path)
    assert build_ha(cfg, Store(tmp_path / "db.sqlite")) == (None, None)
    assert chain(None, None) is None


def test_build_ha_shares_one_client_and_hooks_run_in_order(tmp_path):
    cfg, store = cfg_for(tmp_path), Store(tmp_path / "db.sqlite")
    ha, events = build_ha(cfg, store, transport_factory=lambda: FakeTransport(FakeBroker()))
    assert ha.client is events.client
    calls = []
    chain(lambda: calls.append(1), None, lambda: calls.append(2))()
    assert calls == [1, 2]


def test_start_and_stop_thread(tmp_path):
    cfg, store, broker = cfg_for(tmp_path, mqtt_events_interval=0.01), Store(tmp_path / "db.sqlite"), FakeBroker()
    pub = make(cfg, store, broker)
    pub.start()
    pub.stop()
    assert pub._thread is None
    assert store.get_cursor(CURSOR_NAME) is not None  # at least one tick ran before stop


def test_events_stored_while_broker_down_at_first_start_are_sent_once(tmp_path):
    cfg, store, broker = cfg_for(tmp_path), Store(tmp_path / "db.sqlite"), FakeBroker()
    store.add_events("h1", [ev("history")])
    pub = make(cfg, store, broker)
    real = pub.client.ensure_connected
    pub.client.ensure_connected = lambda: False  # broker unreachable
    assert pub.tick() == 0
    store.add_events("h1", [ev("a"), ev("b")])
    assert pub.tick() == 0
    pub.client.ensure_connected = real  # broker comes up
    assert pub.tick() == 2
    assert pub.tick() == 0
    assert [e["detail"]["k"] for e in events_sent(broker)] == ["a", "b"]
