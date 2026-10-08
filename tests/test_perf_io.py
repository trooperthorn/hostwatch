"""Regression tests for the read, commit and encoding savings: the pstore cache, one commit per
delivery pass, markers restaged only on change, and JSON as the default encoding."""

from __future__ import annotations

import gzip
import json
import sqlite3

import pytest
from agent_helpers import FakeObserve
from fakes_windows import FakeCimQuery, FakeCommandRunner, FakeEventLogReader, FakePipeStatusReader
from otlp_decoder import decode
from test_outbox import make_cfg, pt, rec, requests_for

import hostwatch.agent as agent_mod
import hostwatch.events.pstore as pstore_mod
from hostwatch import otlp
from hostwatch.agent import Agent
from hostwatch.config import Config
from hostwatch.events.pstore import read_pstore
from hostwatch.events.winevent import PROVIDER_EVENTLOG, WinEventReader
from hostwatch.outbox import Outbox
from hostwatch.windows import WindowsSeam

RES = {"host.name": "h"}
WRITES = {"BEGIN", "COMMIT", "INSERT", "DELETE", "UPDATE", "REPLACE"}


def statements(db: sqlite3.Connection) -> list[str]:
    """Start recording the first word of every statement the connection runs."""
    seen: list[str] = []
    db.set_trace_callback(lambda sql: seen.append(sql.strip().split(None, 1)[0].upper()) if sql.strip() else None)
    return seen


# -- pstore cache -------------------------------------------------------------------------------

def pstore_tree(tmp_path, n=8):
    root = tmp_path / "pstore"
    root.mkdir()
    for i in range(n):
        (root / f"dmesg-ramoops-{i}").write_bytes(b"line of old console log\n" * 1000)
    return root


def count_reads(monkeypatch):
    calls: list[str] = []
    real = pstore_mod._read_file

    def spy(path):
        calls.append(path.name)
        return real(path)

    monkeypatch.setattr(pstore_mod, "_read_file", spy)
    return calls


def test_pstore_cache_does_not_reread_unchanged_records_and_gives_the_same_events(tmp_path, monkeypatch):
    root = pstore_tree(tmp_path)
    calls = count_reads(monkeypatch)
    cache: dict = {}
    _, first = read_pstore(root, cache)
    assert len(calls) == 8
    _, second = read_pstore(root, cache)
    assert len(calls) == 8, "an unchanged record must not be read or hashed again"
    _, uncached = read_pstore(root)
    assert [e.model_dump() for e in second] == [e.model_dump() for e in first] == [e.model_dump() for e in uncached]


def test_pstore_cache_rereads_a_record_whose_size_or_mtime_changed(tmp_path, monkeypatch):
    root = pstore_tree(tmp_path, n=2)
    calls = count_reads(monkeypatch)
    cache: dict = {}
    (_, before) = read_pstore(root, cache)
    (root / "dmesg-ramoops-0").write_bytes(b"Kernel panic - not syncing: test\n")
    (_, after) = read_pstore(root, cache)
    assert calls.count("dmesg-ramoops-0") == 2 and calls.count("dmesg-ramoops-1") == 1
    changed = next(e for e in after if e.detail["file"] == "dmesg-ramoops-0")
    old = next(e for e in before if e.detail["file"] == "dmesg-ramoops-0")
    assert changed.kind == "pstore.kernel_panic" and changed.dedup_key != old.dedup_key


def test_pstore_cache_forgets_deleted_records_and_returns_independent_events(tmp_path):
    root = pstore_tree(tmp_path, n=2)
    cache: dict = {}
    _, events = read_pstore(root, cache)
    events[0].detail["excerpt"] = "changed by the caller"
    (root / "dmesg-ramoops-1").unlink()
    _, again = read_pstore(root, cache)
    assert [e.detail["file"] for e in again] == ["dmesg-ramoops-0"]
    assert again[0].detail["excerpt"] != "changed by the caller"
    assert set(cache) == {"dmesg-ramoops-0"}


# -- one commit per delivery pass --------------------------------------------------------------

def test_a_delivery_pass_commits_its_acknowledgements_once(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    for i in range(5):
        agent.outbox.enqueue(requests_for(f"e{i}", n_points=1), f"e{i}")
    seen = statements(agent.outbox._db)
    with FakeObserve(answers=[200] * 5).client() as client:
        agent.flush(client)
    assert agent.outbox.depth() == 0
    assert seen.count("COMMIT") == 1, seen
    reopened = sqlite3.connect(agent.cfg.data_dir / "outbox.db")
    assert reopened.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0


def test_acknowledgements_are_durable_when_a_later_request_fails(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    for i in range(3):
        agent.outbox.enqueue(requests_for(f"e{i}", n_points=1), f"e{i}")
    with FakeObserve(answers=[200, 503]).client() as client:
        with pytest.raises(agent_mod.DeliveryError):
            agent.flush(client)
    reopened = sqlite3.connect(agent.cfg.data_dir / "outbox.db")
    assert reopened.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 2


def test_ack_without_commit_is_hidden_from_peek_and_made_durable_by_commit_acks(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    box.enqueue(requests_for("e1", n_points=1), "e1")
    box.enqueue(requests_for("e2", n_points=1), "e2")
    box.ack(box.peek().seq, commit=False)
    assert box.peek().entry_id == "e2"
    box.commit_acks()
    other = sqlite3.connect(tmp_path / "outbox.db")
    assert other.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1


# -- markers restaged only on change -----------------------------------------------------------

def test_staging_an_unchanged_marker_causes_no_commit(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    box.stage("k", "v")
    box.enqueue([], "e1")
    seen = statements(box._db)
    box.stage("k", "v")
    box.stage("absent", None)
    box.enqueue([], "e2")
    assert not WRITES & set(seen), seen
    box.stage("k", "w")
    box.enqueue([], "e3")
    assert "COMMIT" in seen and box.get("k") == "w"
    box.stage("k", None)
    box.enqueue([], "e4")
    assert box.get("k") is None


def test_staging_back_to_the_durable_value_after_a_change_is_kept(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    box.stage("k", "v")
    box.enqueue([], "e1")
    box.stage("k", "w")
    box.stage("k", "v")
    assert box.get("k") == "v"
    box.enqueue([], "e2")
    assert box.get("k") == "v"


def test_winevent_reread_of_an_unchanged_log_causes_no_marker_only_commit(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    t0 = 1_790_000_000.0
    logs = [{"id": 6006, "record": 1, "provider": PROVIDER_EVENTLOG, "level": 4, "time": t0, "message": "stop"}]
    seam = WindowsSeam(events=FakeEventLogReader({"System": logs}), cim=FakeCimQuery({}),
                       pipe=FakePipeStatusReader({}), runner=FakeCommandRunner())
    reader = WinEventReader(seam, tmp_path / "data", clock=lambda: t0 + 10_000, markers=box)
    reader.read()
    box.enqueue([], "e1")
    seen = statements(box._db)
    reader.read()
    box.enqueue([], "e2")
    assert not WRITES & set(seen), seen


# -- encoding ----------------------------------------------------------------------------------

def test_json_with_gzip_is_the_default_encoding(monkeypatch):
    for name in ("HOSTWATCH_OTLP_FORMAT", "HOSTWATCH_OTLP_GZIP"):
        monkeypatch.delenv(name, raising=False)
    cfg = Config()
    assert cfg.otlp_format == "json" and cfg.otlp_gzip is True


def test_protobuf_stays_available_and_decodes_to_the_same_points():
    points = [pt(i) for i in range(40)]
    as_json = otlp.build_metrics_requests("e", RES, points, fmt="json", compress=True).requests
    as_pb = otlp.build_metrics_requests("e", RES, points, fmt="protobuf", compress=True).requests
    assert as_json[0].headers["Content-Type"] == "application/json"
    assert as_pb[0].headers["Content-Type"] == "application/x-protobuf"
    tree_json = json.loads(gzip.decompress(as_json[0].body))
    tree_pb = decode(gzip.decompress(as_pb[0].body), "metrics")

    def values(tree):
        return sorted((m["name"], str(dp["timeUnixNano"]), dp.get("asDouble", dp.get("asInt")))
                      for rm in tree["resourceMetrics"] for sm in rm["scopeMetrics"]
                      for m in sm["metrics"] for dp in m["gauge"]["dataPoints"])

    assert values(tree_json) == values(tree_pb) and len(values(tree_json)) == 40
    logs = otlp.build_logs_requests("e", RES, [rec(i) for i in range(3)], fmt="json").requests
    assert logs[0].headers["Content-Type"] == "application/json"
    logs_pb = otlp.build_logs_requests("e", RES, [rec(i) for i in range(3)], fmt="protobuf").requests
    assert logs_pb[0].headers["Content-Type"] == "application/x-protobuf"

    def bodies(tree):
        return sorted((str(lr["timeUnixNano"]), lr["body"]["stringValue"])
                      for rl in tree["resourceLogs"] for sl in rl["scopeLogs"] for lr in sl["logRecords"])

    log_json = json.loads(gzip.decompress(logs[0].body))
    log_pb = decode(gzip.decompress(logs_pb[0].body), "logs")
    assert bodies(log_json) == bodies(log_pb) and len(bodies(log_json)) == 3


# -- failure paths of the single commit -------------------------------------------------------

def test_a_failed_ack_commit_does_not_hide_the_delivery_error(tmp_path, monkeypatch):
    agent = Agent(make_cfg(tmp_path))
    for i in range(2):
        agent.outbox.enqueue(requests_for(f"e{i}", n_points=1), f"e{i}")

    def broken():
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(agent.outbox, "commit_acks", broken)
    with FakeObserve(answers=[200, 503]).client() as client:
        with pytest.raises(agent_mod.DeliveryError):
            agent.flush(client)


def test_a_dead_letter_during_a_pass_commits_the_pending_acknowledgements(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    for i in range(3):
        box.enqueue(requests_for(f"e{i}", n_points=1), f"e{i}")
    box.ack(box.peek().seq, commit=False)
    box.dead_letter(box.peek().seq, 400, "bad")
    other = sqlite3.connect(tmp_path / "outbox.db")
    assert other.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1
    box.commit_acks()
    assert box.depth() == 1


def test_stage_survives_an_unreadable_marker_lookup(tmp_path, monkeypatch):
    box = Outbox(tmp_path / "outbox.db")

    def broken(key):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(box, "get", broken)
    box.stage("k", "v")
    assert box._staged == {"k": "v"}


def test_a_long_drain_commits_its_acknowledgements_in_bounded_batches(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_mod, "ACK_COMMIT_EVERY", 2)
    agent = Agent(make_cfg(tmp_path))
    for i in range(5):
        agent.outbox.enqueue(requests_for(f"e{i}", n_points=1), f"e{i}")
    commits = []
    real = agent.outbox.commit_acks
    monkeypatch.setattr(agent.outbox, "commit_acks", lambda: (commits.append(1), real())[1])
    with FakeObserve().client() as client:
        agent.flush(client)
    assert agent.outbox.peek() is None
    assert len(commits) >= 3  # two full batches of two, then the final commit
