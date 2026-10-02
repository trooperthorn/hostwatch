"""Source address allowlist: exposure control that runs before authentication. Not authentication."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.schema import Batch, SourceStatus
from hostwatch.store import Store

ALLOWED = ("10.0.0.5", 40000)
OTHER = ("203.0.113.9", 40000)
LOOPBACK = ("127.0.0.1", 40000)
MAPPED = ("::ffff:10.0.0.5", 40000)


def build(tmp_path, client, allowed="10.0.0.5"):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1, allowed_clients=allowed)
    store = Store(tmp_path / "db.sqlite")
    return TestClient(create_app(cfg, store), client=client), store


def denials(store):
    return [r for r in store.audit_rows() if r["kind"] == "source_denied"]


def test_allowed_ip_still_needs_credentials(tmp_path):
    client, _ = build(tmp_path, ALLOWED)
    assert client.get("/internal/v1/latest").status_code == 401
    assert client.get("/internal/v1/health").status_code == 200


@pytest.mark.parametrize("method,path", [("GET", "/internal/v1/health"), ("GET", "/internal/v1/latest"),
                                         ("POST", "/internal/v1/login"), ("GET", "/nope")])
def test_other_ip_gets_403_on_every_route(tmp_path, method, path):
    client, store = build(tmp_path, OTHER)
    assert client.request(method, path, json={}).status_code == 403
    rows = denials(store)
    assert len(rows) == 1
    assert rows[0]["actor"] == "anonymous" and rows[0]["remote"] == "203.0.113.9"
    assert rows[0]["path"] == path and rows[0]["status"] == 403


def test_forwarded_header_does_not_bypass(tmp_path):
    client, store = build(tmp_path, OTHER)
    r = client.get("/internal/v1/health", headers={"X-Forwarded-For": "10.0.0.5", "Forwarded": "for=10.0.0.5"})
    assert r.status_code == 403
    assert denials(store)[0]["remote"] == "203.0.113.9"


def test_ipv4_mapped_peer_matches(tmp_path):
    client, store = build(tmp_path, MAPPED)
    assert client.get("/internal/v1/health").status_code == 200
    assert denials(store) == []


def test_loopback_always_allowed(tmp_path):
    client, store = build(tmp_path, LOOPBACK)
    assert client.get("/internal/v1/latest").status_code == 401
    assert denials(store) == []


def test_loopback_ingest_works(tmp_path):
    client, _ = build(tmp_path, LOOPBACK)
    body = Batch(agent_version="test", host="h1", platform="x86", sent_at=time.time(),
                 sources=[SourceStatus(source="rapl", available=True)], samples=[]).model_dump_json()
    r = client.post("/internal/v1/ingest", content=body,
                    headers={"Authorization": "Bearer " + "t" * 64, "Content-Type": "application/json"})
    assert r.status_code == 200


def test_no_allowlist_means_no_filter(tmp_path):
    client, store = build(tmp_path, OTHER, allowed="")
    assert client.get("/internal/v1/health").status_code == 200
    assert denials(store) == []
