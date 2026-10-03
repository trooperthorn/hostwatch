"""Crashed and silent hosts are critical through the shared summary, in every output."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient
from test_orion import H, cfg, key, seed
from test_prometheus import parse
from test_ui_status import login
from test_ui_status import seed as ui_seed

from hostwatch import auth
from hostwatch.__main__ import main
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.integrations.summary import build_host_summary
from hostwatch.store import Store


def age_host(store, host, seconds):
    """Make the host's last report `seconds` old, as if the agent had stopped."""
    with store._lock, store._db:
        store._db.execute("UPDATE sources SET updated = updated - ? WHERE host = ?", (seconds, host))
        store._db.execute("UPDATE agents SET last_seen = last_seen - ? WHERE host = ?", (seconds, host))


def boot_event(kind, ts, key="b1"):
    return {"ts": ts, "kind": kind, "severity": "critical", "source": "boot", "title": "Previous boot ended",
            "dedup_key": key}


def test_silent_host_is_critical_with_reason_in_orion_prometheus_and_ui(tmp_path):
    from dataclasses import replace
    c = replace(cfg(tmp_path), prometheus_enabled=True, argon2_time_cost=1)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(c, "correct horse battery"))
    client = TestClient(create_app(c, store), client=("127.0.0.1", 40000))
    headers = key(store, "read:metrics")
    seed(store)
    ui_seed(store, "aaa-warn", missing=("hwmon",))
    assert client.get(f"/api/v1/orion/hosts/{H}/summary", headers=headers).json()["overall_status"] == 0
    age_host(store, H, 600)

    doc = client.get(f"/api/v1/orion/hosts/{H}/summary", headers=headers).json()
    assert doc["overall_status"] == 2 and doc["overall_reason"].startswith("host silent: last report at ")

    metrics = parse(client.get("/metrics", headers=headers).text)
    status = [v for name, labels, v in metrics if name == "hostwatch_host_status" and labels.get("host") == H]
    assert status == [2.0]

    login(client)
    hosts = client.get("/api/v1/ui/status").json()["hosts"]
    assert hosts[0]["host"] == H and hosts[0]["status"] == 2 and "host silent" in hosts[0]["reason"]
    assert [h["host"] for h in hosts] == [H, "aaa-warn"]


def test_silence_window_is_configurable_and_defaults_to_three_intervals(tmp_path, monkeypatch):
    assert Config(interval_s=20.0, silent_after_s=None).silence_window_s == 60.0
    assert Config(interval_s=20.0, silent_after_s=500.0).silence_window_s == 500.0
    monkeypatch.setenv("HOSTWATCH_SILENT_AFTER_S", "90")
    monkeypatch.setenv("HOSTWATCH_CRASH_HOLD_S", "7200")
    assert Config().silence_window_s == 90.0 and Config().crash_hold_s == 7200.0
    store = Store(tmp_path / "db.sqlite")
    seed(store)
    age_host(store, H, 100)
    now = time.time()
    assert build_host_summary(store, H, now, silent_after_s=300.0).overall_status == 0
    assert build_host_summary(store, H, now, silent_after_s=90.0).overall_status == 2


def test_unclean_boot_holds_critical_until_ack_or_hold_window(tmp_path, monkeypatch):
    monkeypatch.setenv("HOSTWATCH_DATA_DIR", str(tmp_path))
    store = Store(tmp_path / "hostwatch.db")
    seed(store)
    now = time.time()
    store.add_events(H, [boot_event("boot.unknown_unclean", now - 3600)])
    event_id = store.events(H)[0]["id"]
    s = build_host_summary(store, H, now)
    assert s.overall_status == 2 and f"event {event_id}: unknown_unclean" in s.overall_reason

    # Past the hold window the condition clears by itself.
    assert build_host_summary(store, H, now, crash_hold_s=1800.0).overall_status == 0

    assert main(["event", "ack", str(event_id)]) == 0
    assert build_host_summary(store, H, now).overall_status == 0
    row = store.audit_rows(kind="cli")[0]
    assert row["path"] == "event ack" and row["status"] == 0 and row["detail"] == {"event_id": event_id}
    assert main(["event", "ack", "9999"]) == 1
    assert store.audit_rows(kind="cli")[0]["status"] == 1


def test_each_crash_kind_is_critical_and_clean_stops_are_not(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    seed(store)
    now = time.time()
    for i, kind in enumerate(("boot.kernel_panic", "boot.watchdog_reset", "pstore.kernel_panic",
                              "pstore.kernel_oops")):
        probe = Store(tmp_path / f"p{i}.sqlite")
        seed(probe)
        probe.add_events(H, [boot_event(kind, now - 60)])
        assert build_host_summary(probe, H, now).overall_status == 2, kind
    store.add_events(H, [boot_event("boot.clean_shutdown", now - 60, "c"),
                         boot_event("boot.agent_stopped", now - 50, "d")])
    assert build_host_summary(store, H, now).overall_status == 0


def test_crash_shows_in_orion_and_ui_banner(tmp_path):
    from dataclasses import replace
    c = replace(cfg(tmp_path), argon2_time_cost=1)
    store = Store(tmp_path / "db.sqlite")
    store.create_user("alice", auth.hash_password(c, "correct horse battery"))
    client = TestClient(create_app(c, store), client=("127.0.0.1", 40000))
    seed(store)
    store.add_events(H, [boot_event("boot.unknown_unclean", time.time() - 10)])
    doc = client.get(f"/api/v1/orion/hosts/{H}/summary", headers=key(store, "read:metrics")).json()
    assert doc["overall_status"] == 2 and "unknown_unclean" in doc["overall_reason"]
    login(client)
    banner = client.get("/api/v1/ui/status").json()["banner"]
    assert banner["status"] == 2 and "unknown_unclean" in banner["text"]
