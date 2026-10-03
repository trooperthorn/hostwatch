"""Agent keys are bound to one host, so one agent cannot post as, or read, another."""

from __future__ import annotations

import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.__main__ import main
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.schema import Batch, Event, Sample, SourceStatus
from hostwatch.store import SCHEMA_VERSION, Store


NOW = time.time()


def build(tmp_path):
    cfg = Config(data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8, argon2_parallelism=1)
    store = Store(tmp_path / "db.sqlite")
    return TestClient(create_app(cfg, store)), store


def batch(host: str, batch_id: str) -> str:
    return Batch(agent_version="t", host=host, platform="x86", sent_at=NOW, batch_id=batch_id,
                 sources=[SourceStatus(source="rapl", available=True)],
                 samples=[Sample(source="rapl", metric="watts", value=1.0, unit="W", ts=NOW)],
                 events=[Event(kind="md.degraded", severity="warning", source="mdraid", ts=NOW,
                               title="t", dedup_key=f"k-{host}")]).model_dump_json()


def hdr(secret: str) -> dict:
    return {"Authorization": f"Bearer {secret}", "Content-Type": "application/json"}


def test_bound_key_cannot_post_as_another_host(tmp_path):
    client, store = build(tmp_path)
    secret, _ = auth.generate_api_key(store, "ingest", "pi", host="ai-pi")
    r = client.post("/internal/v1/ingest", content=batch("TrueNAS-SVR", "a"), headers=hdr(secret))
    assert r.status_code == 403
    assert store.latest("TrueNAS-SVR") == [] and store.events("TrueNAS-SVR") == []
    assert store.agents() == []
    row = store.audit_rows(kind="auth_failure")[0]
    assert row["status"] == 403
    assert row["detail"]["key_host"] == "ai-pi" and row["detail"]["batch_host"] == "TrueNAS-SVR"
    ok = client.post("/internal/v1/ingest", content=batch("ai-pi", "b"), headers=hdr(secret))
    assert ok.status_code == 200 and ok.json()["stored"] == 1
    assert len(store.latest("ai-pi")) == 1


def test_unbound_ingest_key_is_flagged_in_the_audit(tmp_path):
    client, store = build(tmp_path)
    secret, _ = store.create_api_key(["ingest"], "old-agent")  # as created before host binding existed
    assert client.post("/internal/v1/ingest", content=batch("h1", "a"), headers=hdr(secret)).status_code == 200
    assert store.audit_rows(kind="access")[0]["detail"]["unbound_key"] is True


def test_new_ingest_key_requires_a_host_and_admin_keys_cannot_be_bound(tmp_path):
    _, store = build(tmp_path)
    with pytest.raises(ValueError, match="bound to a host"):
        auth.generate_api_key(store, "ingest", "pi")
    with pytest.raises(ValueError, match="admin"):
        auth.generate_api_key(store, "admin", "x", host="h1")


def test_bound_read_key_sees_only_its_own_host(tmp_path):
    client, store = build(tmp_path)
    for host in ("ai-pi", "TrueNAS-SVR"):
        store.ingest_batch(Batch.model_validate_json(batch(host, host)))
    bound, _ = auth.generate_api_key(store, "read:metrics,read:events", "pi-reader", host="ai-pi")
    unbound, _ = auth.generate_api_key(store, "read:metrics,read:events", "ha")
    h = {"Authorization": f"Bearer {bound}"}
    assert client.get("/internal/v1/latest", params={"host": "TrueNAS-SVR"}, headers=h).status_code == 403
    assert client.get("/internal/v1/events", params={"host": "TrueNAS-SVR"}, headers=h).status_code == 403
    assert client.get("/api/v1/orion/hosts/TrueNAS-SVR/summary", headers=h).status_code == 403
    own = client.get("/internal/v1/latest", params={"host": "ai-pi"}, headers=h)
    assert own.status_code == 200 and {r["host"] for r in own.json()} == {"ai-pi"}
    # With no host given, a bound key is narrowed to its own host.
    assert {r["host"] for r in client.get("/internal/v1/latest", headers=h).json()} == {"ai-pi"}
    assert {e["host"] for e in client.get("/internal/v1/events", headers=h).json()} == {"ai-pi"}
    assert {a["host"] for a in client.get("/internal/v1/sources", headers=h).json()["agents"]} == {"ai-pi"}
    assert client.get("/api/v1/orion/hosts", headers=h).json()["host_count"] == 1
    hu = {"Authorization": f"Bearer {unbound}"}
    assert {r["host"] for r in client.get("/internal/v1/latest", headers=hu).json()} == {"ai-pi", "TrueNAS-SVR"}
    assert client.get("/api/v1/orion/hosts", headers=hu).json()["host_count"] == 2


def test_role_all_internal_key_is_bound_to_the_local_host(tmp_path):
    client, store = build(tmp_path)
    cfg = Config(role="all", data_dir=tmp_path, host_name="media")
    key = auth.mint_internal_ingest_key(cfg, store)
    assert store.find_api_key(key)["host"] == "media"
    assert client.post("/internal/v1/ingest", content=batch("other", "a"), headers=hdr(key)).status_code == 403
    assert client.post("/internal/v1/ingest", content=batch("media", "b"), headers=hdr(key)).status_code == 200


def test_migration_from_version_9_keeps_keys_unbound(tmp_path):
    p = tmp_path / "db.sqlite"
    store = Store(p)
    secret, _ = store.create_api_key(["ingest"], "old")
    store._db.close()
    db = sqlite3.connect(p)
    db.execute("ALTER TABLE api_keys DROP COLUMN host")
    db.execute("PRAGMA user_version = 9")
    db.commit()
    db.close()
    assert SCHEMA_VERSION == 11
    upgraded = Store(p)
    assert upgraded.find_api_key(secret)["host"] is None
    assert Store(p).find_api_key(secret)["host"] is None  # guarded, a second open changes nothing


def test_cli_creates_host_bound_key_and_refuses_unbound_ingest(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOSTWATCH_DATA_DIR", str(tmp_path))
    assert main(["key", "create", "--scopes", "ingest"]) == 1
    assert main(["key", "create", "--scopes", "ingest", "--host", "ai-pi"]) == 0
    store = Store(tmp_path / "hostwatch.db")
    assert [k["host"] for k in store.list_api_keys()] == ["ai-pi"]


def test_ingest_only_bound_key_can_seed_from_its_own_events_only(tmp_path):
    client, store = build(tmp_path)
    for host in ("ai-pi", "TrueNAS-SVR"):
        store.ingest_batch(Batch.model_validate_json(batch(host, host)))
    secret, _ = auth.generate_api_key(store, "ingest", "pi", host="ai-pi")
    h = {"Authorization": f"Bearer {secret}"}
    own = client.get("/internal/v1/events", params={"host": "ai-pi"}, headers=h)
    assert own.status_code == 200 and {e["host"] for e in own.json()} == {"ai-pi"}
    assert client.get("/internal/v1/events", params={"host": "TrueNAS-SVR"}, headers=h).status_code == 403
    assert client.get("/internal/v1/latest", headers=h).status_code == 403
