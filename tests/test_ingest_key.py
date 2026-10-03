"""The agent sends a scoped ingest key, and the hub can retire the shared token."""

from __future__ import annotations

import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.agent import Agent
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.schema import Batch, Sample, SourceStatus
from hostwatch.store import Store

TOKEN = "t" * 64
KEY = "hw_abcd1234_" + "k" * 43


def make_agent(tmp_path, **over):
    for d in ("sys", "proc", "data"):
        (tmp_path / d).mkdir(exist_ok=True)
    args = dict(sysfs=tmp_path / "sys", procfs=tmp_path / "proc", data_dir=tmp_path / "data", host_name="h1",
                hub_url="http://hub.test", pstore=tmp_path / "none", journal=tmp_path / "none",
                rasdaemon_db=tmp_path / "none.db")
    args.update(over)
    return Agent(Config(**args))


def recording_client(seen):
    def handler(request):
        seen.append(request.headers.get("authorization"))
        return httpx.Response(200, json=[])
    return httpx.Client(transport=httpx.MockTransport(handler))


def queue_batch(agent):
    agent.outbox.enqueue(Batch(agent_version="t", host="h1", platform="x86", sent_at=time.time(),
                               sources=[SourceStatus(source="rapl", available=True)],
                               samples=[Sample(source="rapl", metric="watts", value=1.0, unit="W",
                                               labels={}, ts=time.time())]))


@pytest.mark.parametrize("over,expected", [
    ({"ingest_key": KEY, "ingest_token": TOKEN}, KEY),
    ({"ingest_key": KEY}, KEY),
    ({"ingest_token": TOKEN}, TOKEN),
])
def test_flush_sends_key_when_set_else_legacy_token(tmp_path, over, expected):
    agent = make_agent(tmp_path, **over)
    queue_batch(agent)
    seen: list = []
    agent.flush(recording_client(seen))
    assert seen == [f"Bearer {expected}"]


def test_seed_sends_key_when_set(tmp_path):
    agent = make_agent(tmp_path, ingest_key=KEY, ingest_token=TOKEN)
    seen: list = []
    assert agent.seed_thresholds(recording_client(seen)) is True
    assert seen == [f"Bearer {KEY}"]


def test_agent_validate_accepts_either_credential_but_not_none():
    Config(role="agent", ingest_key=KEY).validate()
    Config(role="agent", ingest_token=TOKEN).validate()
    with pytest.raises(ValueError, match="needs a credential"):
        Config(role="agent").validate()


def test_all_role_validates_without_legacy_token(tmp_path):
    Config(role="all", data_dir=tmp_path, host_name="h1").validate()
    with pytest.raises(ValueError):
        Config(role="all", ingest_token="short").validate()


def hub(tmp_path, **over):
    cfg = Config(data_dir=tmp_path, **over)
    store = Store(tmp_path / "db.sqlite")
    return TestClient(create_app(cfg, store)), store


def body():
    return Batch(agent_version="t", host="h1", platform="x86", sent_at=time.time(),
                 sources=[SourceStatus(source="rapl", available=True)], samples=[]).model_dump_json()


def test_legacy_token_rejected_when_disabled(tmp_path):
    client, store = hub(tmp_path, ingest_token=TOKEN, legacy_token_disabled=True)
    h = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    assert client.post("/internal/v1/ingest", content=body(), headers=h).status_code == 401
    row = store.audit_rows(kind="auth_failure")[0]
    assert "disabled" in row["detail"]["reason"]
    secret, _ = store.create_api_key(["ingest"], "agent")
    h["Authorization"] = f"Bearer {secret}"
    assert client.post("/internal/v1/ingest", content=body(), headers=h).status_code == 200


def test_legacy_token_use_writes_deprecation_audit_entry(tmp_path):
    client, store = hub(tmp_path, ingest_token=TOKEN)
    h = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    for _ in range(2):
        assert client.post("/internal/v1/ingest", content=body(), headers=h).status_code == 200
    dep = store.audit_rows(kind="deprecation")
    assert len(dep) == 1 and dep[0]["actor"] == "legacy-token"
    assert TOKEN not in json.dumps(store.audit_rows(limit=100))


def test_minted_internal_key_ingests_and_is_stored_hashed(tmp_path):
    client, store = hub(tmp_path)  # no legacy token configured
    cfg = Config(role="all", data_dir=tmp_path, host_name="h1")
    key = auth.mint_internal_ingest_key(cfg, store)
    assert key.startswith("hw_")
    h = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    assert client.post("/internal/v1/ingest", content=body(), headers=h).status_code == 200
    assert client.get("/internal/v1/latest", headers=h).status_code == 403
    assert key not in str(store._db.execute("SELECT * FROM api_keys").fetchall())
    # A restart mints a new key and retires the old one.
    key2 = auth.mint_internal_ingest_key(cfg, store)
    assert key2 != key
    assert client.post("/internal/v1/ingest", content=body(),
                       headers={**h, "Authorization": f"Bearer {key}"}).status_code == 401


def test_configured_ingest_key_is_not_replaced(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    assert auth.mint_internal_ingest_key(Config(role="all", ingest_key=KEY), store) == KEY
    assert store._db.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0] == 0
