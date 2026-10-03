from __future__ import annotations

import re
import time

from fastapi.testclient import TestClient

from hostwatch.config import Config
from hostwatch.hub import create_app, csrf_token_for
from hostwatch.schema import Batch, Event, Sample, SourceStatus
from hostwatch.store import Store

TOKEN = "t" * 64


def make(tmp_path):
    cfg = Config(ingest_token=TOKEN, data_dir=tmp_path)
    store = Store(tmp_path / "db.sqlite")
    return TestClient(create_app(cfg, store)), store


def key_header(store, scopes, owner="test"):
    secret, row = store.create_api_key(scopes, owner)
    return {"Authorization": f"Bearer {secret}"}, secret, row


def batch(ts, value=1.0):
    return Batch(agent_version="test", host="h1", platform="x86", sent_at=ts,
                 sources=[SourceStatus(source="rapl", available=True)],
                 samples=[Sample(source="rapl", metric="watts", value=value, unit="W",
                                 labels={"domain": "package-0"}, ts=ts)])


def test_ingest_requires_token(tmp_path):
    client, _ = make(tmp_path)
    body = batch(time.time()).model_dump_json()
    assert client.post("/internal/v1/ingest", content=body).status_code == 401
    assert client.post("/internal/v1/ingest", content=body,
                       headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = client.post("/internal/v1/ingest", content=body, headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json() == {"stored": 1, "events_stored": 0}


def test_read_endpoints_reject_missing_and_wrong_credentials(tmp_path):
    client, _ = make(tmp_path)
    for path in ("/internal/v1/latest", "/internal/v1/sources", "/internal/v1/events"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_latest_and_gaps(tmp_path):
    client, store = make(tmp_path)
    now = time.time()
    for ts in (now - 300, now - 285, now - 100):  # a 185 s gap
        store.ingest(batch(ts))
    h, _, _ = key_header(store, ["read:metrics"])
    latest = client.get("/internal/v1/latest", headers=h).json()
    assert len(latest) == 1 and latest[0]["ts"] == now - 100
    gaps = client.get("/internal/v1/gaps", headers=h,
                      params={"host": "h1", "source": "rapl", "metric": "watts", "max_gap_s": 60}).json()
    assert gaps["gap_count"] == 1


def test_null_values_count_as_gaps(tmp_path):
    _, store = make(tmp_path)
    now = time.time()
    store.ingest(batch(now - 100))
    store.ingest(batch(now - 85, value=None))
    store.ingest(batch(now - 10))
    assert len(store.gaps("h1", "rapl", "watts", now - 200, 60)) == 1


def test_rollup_then_prune(tmp_path):
    _, store = make(tmp_path)
    old = time.time() - 10 * 86400
    for v in (10.0, 20.0, 30.0):
        store.ingest(batch(old, v))
    store.maintain(raw_days=7, rollup_days=400)
    row = store._db.execute("SELECT n, vmin, vavg, vmax FROM rollup_hourly").fetchone()
    assert row == (3, 10.0, 20.0, 30.0)
    assert store._db.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 0


def test_config_rejects_short_token():
    import pytest
    with pytest.raises(ValueError):
        Config(ingest_token="short").validate()


H = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}  # legacy token: ingest only


def rw(store):
    """Headers for a key that may read events and metrics."""
    return key_header(store, ["read:events", "read:metrics"])[0]


def event(ts, kind="md.degraded", key="k1"):
    return Event(kind=kind, severity="warning", source="mdraid", ts=ts, title="t",
                 detail={"array": "md127"}, dedup_key=key)


def test_batch_without_events_is_accepted(tmp_path):
    client, store = make(tmp_path)
    body = batch(time.time()).model_dump(exclude={"events"})
    assert "events" not in body
    r = client.post("/internal/v1/ingest", json=body, headers=H)
    assert r.status_code == 200 and r.json()["events_stored"] == 0
    assert client.get("/internal/v1/events", headers=rw(store)).json() == []


def test_events_stored_and_deduplicated(tmp_path):
    client, store = make(tmp_path)
    now = time.time()
    b = batch(now)
    b.events = [event(now, key="a"), event(now, key="a")]
    assert client.post("/internal/v1/ingest", content=b.model_dump_json(), headers=H).json()["events_stored"] == 1
    assert client.post("/internal/v1/ingest", content=b.model_dump_json(), headers=H).json()["events_stored"] == 0
    rows = client.get("/internal/v1/events", headers=rw(store)).json()
    assert len(rows) == 1 and rows[0]["detail"] == {"array": "md127"} and rows[0]["host"] == "h1"


def test_events_endpoint_filters(tmp_path):
    client, store = make(tmp_path)
    H = rw(store)
    now = time.time()
    store.add_events("h1", [event(now - 100, "md.degraded", "a").model_dump(),
                            event(now - 10, "boot.panic", "b").model_dump()])
    got = client.get("/internal/v1/events", headers=H, params={"kind": "boot.panic"}).json()
    assert [e["dedup_key"] for e in got] == ["b"]
    got = client.get("/internal/v1/events", headers=H, params={"since": now - 50}).json()
    assert [e["dedup_key"] for e in got] == ["b"]
    assert len(client.get("/internal/v1/events", headers=H, params={"host": "h1", "limit": 1}).json()) == 1
    assert client.get("/internal/v1/events", headers=H, params={"host": "other"}).json() == []


def test_event_source_unavailable_reason_is_reported(tmp_path):
    client, store = make(tmp_path)
    b = batch(time.time())
    b.sources.append(SourceStatus(source="events.pstore", available=False, reason="/sys/fs/pstore not mounted"))
    client.post("/internal/v1/ingest", content=b.model_dump_json(), headers=H)
    src = {s["source"]: s for s in client.get("/internal/v1/sources", headers=rw(store)).json()["sources"]}
    assert src["events.pstore"]["available"] == 0 and "not mounted" in src["events.pstore"]["reason"]


def test_nan_event_ts_is_rejected_and_nothing_acknowledged(tmp_path):
    client, store = make(tmp_path)
    now = time.time()
    b = batch(now)
    b.events = [event(now, key="a")]
    # The event ts is the last "ts" in the body; make that one NaN.
    body = b.model_dump_json()
    idx = body.rindex('"ts":')
    end = body.index(",", idx)
    body = body[:idx] + '"ts":NaN' + body[end:]
    r = client.post("/internal/v1/ingest", content=body, headers={**H, "Content-Type": "application/json"})
    assert r.status_code == 422
    assert client.get("/internal/v1/events", headers=rw(store)).json() == []


def test_store_ignores_only_the_uniqueness_conflict(tmp_path):
    import sqlite3

    import pytest
    store = Store(tmp_path / "db.sqlite")
    ev = event(time.time(), key="k").model_dump()
    assert store.add_events("h1", [ev]) == 1
    assert store.add_events("h1", [ev]) == 0
    bad = dict(ev, dedup_key="other", title=None)
    with pytest.raises(sqlite3.IntegrityError):
        store.add_events("h1", [bad])


# ---- Authentication, scopes and audit ----

def test_default_deny_every_route_but_health(tmp_path):
    client, store = make(tmp_path)
    seen = []
    for route in client.app.routes:
        methods = getattr(route, "methods", None)
        # Health, login and the static UI shell page are the only routes that answer without a
        # credential. Login grants nothing without a correct password (tests/test_login.py), and
        # the shell holds no data (tests/test_ui_shell.py).
        if not methods or route.path in ("/internal/v1/health", "/api/v1/login", "/"):
            continue
        # Path parameters get a placeholder value: authentication runs before the handler, so
        # the value is never looked up and every parameterised route must still answer 401.
        path = re.sub(r"\{[^}]+\}", "x", route.path)
        for m in methods - {"HEAD", "OPTIONS"}:
            seen.append((m, route.path))
            assert client.request(m, path).status_code == 401, (m, route.path)
            bad = {"Authorization": "Bearer wrong"}
            assert client.request(m, path, headers=bad).status_code == 401, (m, route.path)
    assert ("POST", "/internal/v1/ingest") in seen and len(seen) >= 5
    assert client.get("/internal/v1/health").status_code == 200
    assert store.audit_rows(kind="auth_failure")


def test_wrong_scope_is_403(tmp_path):
    client, store = make(tmp_path)
    ev, _, _ = key_header(store, ["read:events"])
    met, _, _ = key_header(store, ["read:metrics"])
    ing, _, _ = key_header(store, ["ingest"])
    gp = {"host": "h1", "source": "rapl", "metric": "watts"}
    js = {"Content-Type": "application/json"}
    assert client.get("/internal/v1/latest", headers=ev).status_code == 403
    assert client.get("/internal/v1/gaps", headers=ev, params=gp).status_code == 403
    assert client.get("/internal/v1/events", headers=met).status_code == 403
    assert client.get("/internal/v1/sources", headers=ing).status_code == 403
    body = batch(time.time()).model_dump_json()
    assert client.post("/internal/v1/ingest", content=body, headers={**met, **js}).status_code == 403
    assert client.get("/internal/v1/latest", headers=met).status_code == 200
    assert client.get("/internal/v1/events", headers=ev).status_code == 200
    assert client.post("/internal/v1/ingest", content=body, headers={**ing, **js}).status_code == 200
    reasons = [r["detail"].get("reason") for r in store.audit_rows(kind="auth_failure")]
    assert "missing scope read:metrics" in reasons


def test_revoked_key_is_rejected_on_next_request(tmp_path):
    client, store = make(tmp_path)
    h, _, row = key_header(store, ["read:metrics"])
    assert client.get("/internal/v1/latest", headers=h).status_code == 200
    assert store.revoke_api_key(row["id"])
    assert client.get("/internal/v1/latest", headers=h).status_code == 401


def test_legacy_token_ingests_but_cannot_read(tmp_path):
    client, store = make(tmp_path)
    r = client.post("/internal/v1/ingest", content=batch(time.time()).model_dump_json(), headers=H)
    assert r.status_code == 200
    for path in ("/internal/v1/latest", "/internal/v1/sources", "/internal/v1/events"):
        assert client.get(path, headers=H).status_code == 403
    row = [a for a in store.audit_rows() if a["path"] == "/internal/v1/ingest"][0]
    assert row["actor"] == "legacy-token" and "deprecated" in row["detail"]


def test_session_cookie_reads_but_cannot_ingest(tmp_path):
    client, store = make(tmp_path)
    uid = store.create_user("alice", "x")
    token = store.create_session(uid, 3600)
    client.cookies.set("hostwatch_session", token)
    assert client.get("/internal/v1/latest").status_code == 200
    r = client.post("/internal/v1/ingest", content=batch(time.time()).model_dump_json(),
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token_for(token)})
    assert r.status_code == 403
    assert store.audit_rows(actor="alice")
    store.revoke_session(token)
    assert client.get("/internal/v1/latest").status_code == 401


def test_mtls_hook_authenticates(tmp_path):
    from hostwatch.hub import Principal

    def hook(req):
        if req.headers.get("x-test-cert"):
            return Principal("cert:CN=a", "mtls", frozenset({"read:metrics"}))
        return None

    cfg = Config(ingest_token=TOKEN, data_dir=tmp_path)
    store = Store(tmp_path / "db.sqlite")
    client = TestClient(create_app(cfg, store, mtls_identity=hook))
    assert client.get("/internal/v1/latest").status_code == 401
    assert client.get("/internal/v1/latest", headers={"x-test-cert": "1"}).status_code == 200
    assert store.audit_rows(actor="cert:CN=a")


def test_every_request_is_audited_and_no_secret_is_recorded(tmp_path, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    client, store = make(tmp_path)
    h, secret, _ = key_header(store, ["read:metrics"])
    uid = store.create_user("bob", "x")
    cookie = store.create_session(uid, 3600)
    bad = "hw_deadbeef_" + "z" * 43
    client.get("/internal/v1/latest", headers=h)
    client.get("/internal/v1/latest", headers={"Authorization": f"Bearer {bad}"})
    client.get("/internal/v1/events", headers=h)
    client.get("/internal/v1/sources", headers={"Authorization": "Bearer wrong-secret-value"})
    client.post("/internal/v1/ingest", content=batch(time.time()).model_dump_json(), headers=H)
    client.get("/internal/v1/latest", headers={"Cookie": f"hostwatch_session={cookie}"})
    client.get("/internal/v1/health")
    rows = [r for r in store.audit_rows(limit=100) if r["kind"] != "deprecation"]  # the one-time deprecation note is extra
    assert [(r["method"], r["path"], r["status"]) for r in reversed(rows)] == [
        ("GET", "/internal/v1/latest", 200), ("GET", "/internal/v1/latest", 401),
        ("GET", "/internal/v1/events", 403), ("GET", "/internal/v1/sources", 401),
        ("POST", "/internal/v1/ingest", 200), ("GET", "/internal/v1/latest", 200)]
    assert {r["kind"] for r in rows} == {"access", "auth_failure"}
    assert all(r["remote"] and r["actor"] for r in rows)
    dump = repr(store._db.execute("SELECT * FROM audit_log").fetchall()) + caplog.text
    for sec in (secret, bad, TOKEN, cookie, "wrong-secret-value", "z" * 43):
        assert sec not in dump
