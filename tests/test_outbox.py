"""Durable outbox tests: restarts, outages, limits, dead letters and markers.

Each test that simulates a restart builds a second Agent on the same data directory, which is what
a restarted process does. Observe is played by FakeObserve (agent_helpers.py).
"""

from __future__ import annotations

import json
import logging
import sqlite3

import httpx
import pytest
from agent_helpers import FakeObserve, collect_once, drain_logs, event, event_cycle

import hostwatch.agent as agent_mod
from hostwatch import otlp, tiers
from hostwatch.agent import Agent
from hostwatch.config import Config
from hostwatch.events.journal import BackgroundJournal, JournalWatcher
from hostwatch.model import Sample, SourceStatus
from hostwatch.outbox import Outbox

OLD, NEW = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"
RES = {"host.name": "h"}


def make_cfg(tmp_path, **over):
    procfs, sysfs, data = tmp_path / "proc", tmp_path / "sys", tmp_path / "data"
    (procfs / "sys/kernel/random").mkdir(parents=True, exist_ok=True)
    (procfs / "sys/kernel/random/boot_id").write_text(NEW + "\n")
    sysfs.mkdir(exist_ok=True)
    data.mkdir(exist_ok=True)
    args = dict(procfs=procfs, sysfs=sysfs, data_dir=data, ingest_key="k" * 24, host_name="h",
                observe_url="http://observe.test", pstore=tmp_path / "none", journal=tmp_path / "none",
                rasdaemon_db=tmp_path / "none.db")
    args.update(over)
    return Config(**args)


def down_client():
    def refuse(request):
        raise httpx.ConnectError("refused")

    return httpx.Client(transport=httpx.MockTransport(refuse))


def requests_for(entry, n_points=0, n_records=0, **kw):
    pts = [pt(i) for i in range(n_points)]
    recs = [rec(i) for i in range(n_records)]
    return [*otlp.build_metrics_requests(entry, RES, pts, **kw).requests,
            *otlp.build_logs_requests(entry, RES, recs, **kw).requests]


def pt(i):
    from hostwatch.otel_map import GAUGE, Point
    return Point("hostwatch.collector.cpu", "hw.cpu.utilization", "1", GAUGE, 0.5, 1700000000.0 + i, {})


def rec(i):
    from hostwatch.otel_map import LogRecord
    return LogRecord("hostwatch.collector.journal", 1700000000.0 + i, "hostwatch.x", 13, "WARN", "b",
                     {"observe.dedup_key": f"k{i}"})


def queued(agent):
    """(path, Idempotency-Key, body) of every request in the outbox, oldest first, without removing any."""
    rows = sqlite3.connect(agent.cfg.data_dir / "outbox.db").execute(
        "SELECT path, headers, body FROM requests ORDER BY seq").fetchall()
    return [(p, json.loads(h)["Idempotency-Key"], bytes(b)) for p, h, b in rows]


# -- replay -----------------------------------------------------------------------------------

def test_replay_after_restart_sends_each_request_once_with_the_same_key_and_body(tmp_path):
    cfg = make_cfg(tmp_path)
    first = Agent(cfg)
    first.detect()
    first.run_tier(tiers.DEVICE_METRICS)
    first.run_tier(tiers.AVAILABILITY)
    first.outbox.enqueue(requests_for("ev1", n_records=2), "ev1")
    before = queued(first)
    assert len(before) >= 2
    with pytest.raises(httpx.ConnectError):
        first.flush(down_client())  # the outage: nothing was delivered
    assert queued(first) == before
    first.outbox.close()
    second = Agent(cfg)  # restart
    observe = FakeObserve()
    with observe.client() as client:
        second.flush(client)
        second.flush(client)  # nothing is left, so nothing more is sent
    assert [(r.url.path, r.headers["idempotency-key"], r.content) for r in observe.posts] == before
    assert len({k for _, k, _ in before}) == len(before)
    assert second.outbox.depth() == 0
    assert all(r.headers["authorization"] == "Bearer " + "k" * 24 for r in observe.posts)


def test_a_replay_of_the_same_request_uses_the_same_key_even_when_sent_twice(tmp_path):
    """A 5xx after Observe stored the data makes the agent send the request again: same key."""
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(requests_for("e1", n_points=3), "e1")
    observe = FakeObserve(answers=[503, 200])
    with observe.client() as client:
        with pytest.raises(agent_mod.DeliveryError):
            agent.flush(client)
        agent.flush(client)
    assert len(observe.posts) == 2
    assert observe.posts[0].headers["idempotency-key"] == observe.posts[1].headers["idempotency-key"]
    assert observe.posts[0].content == observe.posts[1].content


def test_the_credential_is_never_written_to_the_outbox(tmp_path):
    cfg = make_cfg(tmp_path)
    agent = Agent(cfg)
    agent.run_tier(tiers.AVAILABILITY)
    agent.outbox.close()
    raw = (cfg.data_dir / "outbox.db").read_bytes()
    assert b"k" * 24 not in raw and b"Authorization" not in raw


def test_request_stays_queued_on_5xx_and_is_acked_only_on_2xx(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(requests_for("e1", n_points=1), "e1")
    with FakeObserve(answers=[503]).client() as client:
        with pytest.raises(agent_mod.DeliveryError):
            agent.flush(client)
    assert agent.outbox.depth() == 1
    with FakeObserve(answers=[200]).client() as client:
        agent.flush(client)
    assert agent.outbox.depth() == 0


# -- markers committed with their requests -----------------------------------------------------

class FakeReader:
    def __init__(self, entries):
        self.entries = entries

    def __call__(self, directory, cursor):
        start = [e["__CURSOR"] for e in self.entries].index(cursor) + 1 if cursor else 0
        return [json.dumps(e) for e in self.entries[start:]]


def journal_agent(tmp_path, entries):
    jdir = tmp_path / "journal"
    jdir.mkdir(exist_ok=True)
    (jdir / "system.journal").write_bytes(b"x")
    agent = Agent(make_cfg(tmp_path, journal=jdir))
    watcher = JournalWatcher(jdir, agent.cfg.data_dir, FakeReader(entries), markers=agent.outbox)
    agent.event_sources = {"journal": watcher.read}
    agent.detect()
    return agent


ENTRIES = [{"__CURSOR": "c1", "__REALTIME_TIMESTAMP": "1000000", "MESSAGE": "ata3: hard resetting link"},
           {"__CURSOR": "c2", "__REALTIME_TIMESTAMP": "2000000", "MESSAGE": "md127: Disk failure on sdc"}]


def test_journal_entries_read_before_a_crash_are_not_skipped(tmp_path):
    crashed = journal_agent(tmp_path, ENTRIES)
    assert len(collect_once(crashed).events) == 2
    # Crash after reading but before the requests reached the outbox: the cursor was only staged,
    # so the restarted agent reads the entries again.
    crashed.outbox.close()
    again = journal_agent(tmp_path, ENTRIES)
    assert event_cycle(again) is True
    # Crash after enqueue: the events are in the outbox and the cursor moved with them.
    again.outbox.close()
    final = journal_agent(tmp_path, ENTRIES)
    assert collect_once(final).events == []
    keys = [r["dedup_key"] for r in drain_logs(final)]
    assert keys == ["journal:c1", "journal:c2"]


def test_legacy_journal_cursor_file_is_imported(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data/journal.cursor").write_text("c1")
    agent = journal_agent(tmp_path, ENTRIES)
    assert [e.dedup_key for e in collect_once(agent).events] == ["journal:c2"]


def test_pstore_sent_keys_survive_restart(tmp_path):
    pstore = tmp_path / "pstore"
    pstore.mkdir()
    (pstore / "dmesg-efi-1").write_text("Kernel panic - not syncing")
    cfg = make_cfg(tmp_path, pstore=pstore)
    first = Agent(cfg)
    first.detect()
    assert event_cycle(first) is True  # the sent keys are committed with the logs request
    first.outbox.close()
    second = Agent(cfg)
    second.detect()
    assert [e for e in collect_once(second).events if e.source == "pstore"] == []


def test_rasdaemon_high_water_commits_with_the_requests(tmp_path):
    db = tmp_path / "ras.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE mc_event (id INTEGER PRIMARY KEY, timestamp TEXT, err_type TEXT, err_msg TEXT)")
    conn.execute("INSERT INTO mc_event (timestamp, err_type, err_msg) VALUES ('2026-10-02 12:00:00', 'Corrected', 'm')")
    conn.commit()
    conn.close()
    cfg = make_cfg(tmp_path, rasdaemon_db=db)
    lost = Agent(cfg)
    assert len([e for e in collect_once(lost).events if e.source == "rasdaemon"]) == 1
    lost.outbox.close()  # crashed before enqueue
    kept = Agent(cfg)
    assert event_cycle(kept) is True
    kept.outbox.close()
    final = Agent(cfg)
    assert [e for e in collect_once(final).events if e.source == "rasdaemon"] == []


def boot_cfg(tmp_path):
    cfg = make_cfg(tmp_path)
    (cfg.data_dir / "heartbeat.json").write_text(
        json.dumps({"boot_id": OLD, "ts": 1000.0, "clean_shutdown": True}))
    return cfg


def test_boot_event_survives_agent_restart_before_delivery(tmp_path):
    cfg = boot_cfg(tmp_path)
    first = Agent(cfg)
    first.start_boot_check()
    first.heartbeat.beat()  # the heartbeat now names the new boot
    first.outbox.close()    # crash before any request was built
    second = Agent(cfg)
    second.start_boot_check()  # same boot, so nothing is classified again
    (ev,) = collect_once(second).events
    assert ev.kind == "boot.agent_stopped" and ev.dedup_key == f"boot:{NEW}"


# -- failed units of work ----------------------------------------------------------------------

def test_an_event_cycle_that_raises_is_followed_by_a_normal_cycle(tmp_path, caplog):
    agent = Agent(make_cfg(tmp_path))
    real, calls = agent.event_cycle, {"n": 0}

    def flaky(watch):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return real(watch)

    agent.event_cycle = flaky
    with caplog.at_level(logging.ERROR, logger="hostwatch.agent"):
        assert event_cycle(agent) is False
    assert any("event read failed" in r.getMessage() for r in caplog.records)
    assert agent.status["agent"].available is False and "boom" in agent.status["agent"].reason
    assert agent.outbox.depth() == 0
    assert event_cycle(agent) is True and agent.status["agent"].available is True


def test_events_read_in_a_failed_cycle_are_not_lost(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    fake = event(key="lost-1", source="fake")
    agent.event_sources = {"fake": lambda: (SourceStatus(source="fake", available=True), [fake])}
    real = agent.outbox.enqueue
    agent.outbox.enqueue = lambda *a: (_ for _ in ()).throw(sqlite3.OperationalError("disk full"))
    assert event_cycle(agent) is False
    agent.outbox.enqueue = real
    assert event_cycle(agent) is True
    assert [r["dedup_key"] for r in drain_logs(agent)] == ["lost-1"]


def test_threshold_event_is_not_lost_when_the_tier_run_fails_after_it_opened(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.detect()
    samples = [Sample(source="mdraid", metric="degraded", value=1, labels={"array": "md0"}, ts=1.0)]
    agent.collect_samples = lambda tier=None, watched=False: samples
    real = agent.outbox.enqueue
    agent.outbox.enqueue = lambda *a: (_ for _ in ()).throw(sqlite3.OperationalError("disk full"))
    assert agent._guard("poll", lambda: agent.run_tier(tiers.STORAGE_HEALTH)) is False
    agent.outbox.enqueue = real
    assert agent._guard("poll", lambda: agent.run_tier(tiers.STORAGE_HEALTH)) is True
    names = [r["event"] for r in drain_logs(agent)]
    assert names.count("hostwatch.md.degraded") == 1


def test_threshold_state_survives_a_restart_so_an_open_condition_is_not_repeated(tmp_path):
    cfg = make_cfg(tmp_path)
    samples = [Sample(source="mdraid", metric="degraded", value=1, labels={"array": "md0"}, ts=1.0)]
    first = Agent(cfg)
    first.detect()
    first.collect_samples = lambda tier=None, watched=False: samples
    first.run_tier(tiers.STORAGE_HEALTH)
    assert [r["event"] for r in drain_logs(first)] == ["hostwatch.md.degraded"]
    first.outbox.close()
    second = Agent(cfg)
    second.detect()
    second.collect_samples = lambda tier=None, watched=False: samples
    second.run_tier(tiers.STORAGE_HEALTH)
    assert drain_logs(second) == []


ENTRIES_FOR_REREAD = ENTRIES


def test_cycle_that_fails_after_the_journal_read_rereads_the_same_entries(tmp_path, monkeypatch):
    jdir = tmp_path / "journal"
    jdir.mkdir()
    (jdir / "system.journal").write_bytes(b"x")
    agent = Agent(make_cfg(tmp_path, journal=jdir))
    watcher = JournalWatcher(jdir, agent.cfg.data_dir, FakeReader(ENTRIES_FOR_REREAD), markers=agent.outbox)
    background = agent.journal = BackgroundJournal(watcher)
    agent.event_sources = {"journal": background.read}
    agent.detect()

    def cycle_and_settle():
        ok = event_cycle(agent)
        if background._thread is not None:
            background._thread.join()
        return ok

    cycle_and_settle()  # starts the first worker
    real_enqueue = agent.outbox.enqueue
    state = {"fail": True}

    def flaky(requests, entry_id):
        if state["fail"] and any(r.signal == "logs" for r in requests):
            state["fail"] = False
            raise RuntimeError("disk full")
        real_enqueue(requests, entry_id)

    monkeypatch.setattr(agent.outbox, "enqueue", flaky)
    assert cycle_and_settle() is False  # the cycle read the entries, then failed
    assert agent.outbox.get("journal.cursor") is None
    for _ in range(3):
        assert cycle_and_settle() is True
    assert [r["dedup_key"] for r in drain_logs(agent)] == ["journal:c1", "journal:c2"]
    assert agent.outbox.get("journal.cursor") == "c2"


# -- limits ------------------------------------------------------------------------------------

def counted(box, signal):
    return box._db.execute("SELECT COUNT(*) FROM requests WHERE signal=?", (signal,)).fetchone()[0]


def test_over_the_count_limit_drops_metrics_before_logs_and_counts_them(tmp_path, caplog):
    box = Outbox(tmp_path / "data/o.db", max_requests=4)
    box.enqueue(requests_for("e0", n_records=2), "e0")
    with caplog.at_level(logging.WARNING, logger="hostwatch.outbox"):
        for n in range(1, 7):
            box.enqueue(requests_for(f"m{n}", n_points=3), f"m{n}")
    assert box.depth() == 4 and counted(box, "logs") == 1
    assert box.dropped_total() == 3 and box.dropped_points_total() == 9 and box.dropped_records_total() == 0
    assert any("dropped" in r.getMessage() for r in caplog.records)
    assert box.peek().signal == "logs"  # the event outlived every metrics request that came after it


def test_logs_are_dropped_only_when_no_metrics_request_is_left(tmp_path):
    box = Outbox(tmp_path / "data/o.db", max_requests=2)
    for n in range(4):
        box.enqueue(requests_for(f"l{n}", n_records=1), f"l{n}")
    assert box.depth() == 2 and box.dropped_records_total() == 2
    assert [r["attrs"]["observe.dedup_key"] for r in _logs_in(box)] == ["k0", "k0"]


def _logs_in(box):
    out = []
    from agent_helpers import log_records, request_json
    while (req := box.peek()) is not None:
        out.extend(log_records(request_json(req)))
        box.ack(req.seq)
    return out


def test_over_the_byte_limit_drops_the_oldest_metrics_first(tmp_path):
    one = requests_for("a", n_points=50)[0]
    box = Outbox(tmp_path / "data/o.db", max_bytes=len(one.body) * 2 + 10)
    for n in range(5):
        box.enqueue(requests_for(f"m{n}", n_points=50), f"m{n}")
    assert box.depth() == 2 and box.size_bytes() <= box.max_bytes
    assert [json.loads(h)["Idempotency-Key"] for (h,) in box._db.execute(
        "SELECT headers FROM requests ORDER BY seq")] == ["hw-m3-m0", "hw-m4-m0"]


def test_old_requests_are_dropped_by_age_with_metrics_expiring_before_logs(tmp_path):
    now = [1000.0]
    box = Outbox(tmp_path / "data/o.db", max_metrics_age_s=100, max_logs_age_s=1000, clock=lambda: now[0])
    box.enqueue(requests_for("m", n_points=2), "m")
    box.enqueue(requests_for("l", n_records=1), "l")
    now[0] += 200
    box.prune()
    assert counted(box, "metrics") == 0 and counted(box, "logs") == 1
    assert box.dropped_points_total() == 2
    now[0] += 900
    box.prune()
    assert box.depth() == 0 and box.dropped_records_total() == 1


def test_a_failed_marker_write_leaves_no_request_behind(tmp_path):
    box = Outbox(tmp_path / "data/o.db")
    box.stage("k", "v")
    box._db.execute("DROP TABLE markers")
    with pytest.raises(sqlite3.OperationalError):
        box.enqueue(requests_for("e", n_points=1), "e")
    assert box.depth() == 0


def test_overflow_is_reported_as_outbox_source_status(tmp_path):
    cfg = make_cfg(tmp_path)
    agent = Agent(cfg)
    agent.outbox.close()
    agent.outbox = Outbox(cfg.data_dir / "outbox.db", max_requests=2)
    for n in range(1, 5):
        agent.outbox.enqueue(requests_for(f"m{n}", n_points=3), f"m{n}")
    agent._outbox_status()
    status = agent.status["outbox"]
    assert status.available is False and "6 data point(s)" in status.reason
    with FakeObserve().client() as client:
        agent.flush(client)
    agent.outbox.enqueue(requests_for("m9", n_points=1), "m9")
    agent._outbox_status()
    assert agent.status["outbox"].available is True  # drained, so the drop run is over


# -- dead letters ------------------------------------------------------------------------------

@pytest.mark.parametrize("code", [400, 409, 413, 415, 422])
def test_a_status_that_can_never_succeed_dead_letters_the_request_and_the_next_is_sent(tmp_path, code, caplog):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(requests_for("bad", n_points=1), "bad")
    agent.outbox.enqueue(requests_for("good", n_points=1), "good")
    observe = FakeObserve(answers=[code, 200])
    with caplog.at_level(logging.ERROR, logger="hostwatch.outbox"), observe.client() as client:
        agent.flush(client)
    assert [r.headers["idempotency-key"] for r in observe.posts] == ["hw-bad-m0", "hw-good-m0"]
    assert agent.outbox.depth() == 0 and agent.outbox.dead_letter_count() == 1
    assert any(str(code) in r.getMessage() for r in caplog.records)
    agent._outbox_status()
    assert "dead-letter" in agent.status["outbox"].reason
    row = sqlite3.connect(tmp_path / "data/outbox.db").execute("SELECT entry_id, status FROM dead_letters").fetchone()
    assert row == ("bad", code)


@pytest.mark.parametrize("code", [500, 501, 502, 503, 504, 408, 429, 401, 403, 404])
def test_statuses_about_observe_or_the_key_never_dead_letter(tmp_path, code):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(requests_for("e", n_points=1), "e")
    for _ in range(4):
        with FakeObserve(answers=[code]).client() as client:
            with pytest.raises(agent_mod.DeliveryError) as err:
                agent.flush(client)
        assert err.value.status == code
    assert agent.outbox.depth() == 1 and agent.outbox.dead_letter_count() == 0


def test_network_errors_never_dead_letter(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(requests_for("e", n_points=1), "e")
    for _ in range(8):
        with pytest.raises(httpx.ConnectError):
            agent.flush(down_client())
    assert agent.outbox.depth() == 1 and agent.outbox.dead_letter_count() == 0


def test_dead_letter_table_is_capped(tmp_path, monkeypatch):
    import hostwatch.outbox as ob
    monkeypatch.setattr(ob, "MAX_DEAD_LETTERS", 2)
    agent = Agent(make_cfg(tmp_path))
    for n in range(5):
        agent.outbox.enqueue(requests_for(f"e{n}", n_points=1), f"e{n}")
        agent.outbox.dead_letter(agent.outbox.peek().seq, 400)
    assert agent.outbox.dead_letter_count() == 2


def test_a_row_with_undecodable_headers_is_dead_lettered_and_later_rows_deliver(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    for n in range(3):
        agent.outbox.enqueue(requests_for(f"e{n}", n_points=1), f"e{n}")
    db = sqlite3.connect(tmp_path / "data/outbox.db")
    db.execute("UPDATE requests SET headers='{not json' WHERE entry_id='e0'")
    db.commit()
    db.close()
    observe = FakeObserve()
    with observe.client() as client:
        agent.flush(client)
    assert [r.headers["idempotency-key"] for r in observe.posts] == ["hw-e1-m0", "hw-e2-m0"]
    assert agent.outbox.depth() == 0 and agent.outbox.dead_letter_count() == 1
    row = sqlite3.connect(tmp_path / "data/outbox.db").execute(
        "SELECT entry_id, status, error FROM dead_letters").fetchone()
    assert row[0] == "e0" and row[1] == 0 and "undecodable" in row[2]


# -- the file itself ---------------------------------------------------------------------------

def test_garbage_outbox_is_quarantined_and_the_agent_starts(tmp_path, caplog):
    cfg = make_cfg(tmp_path)
    (cfg.data_dir / "outbox.db").write_bytes(b"this is not a sqlite database " * 50)
    with caplog.at_level(logging.ERROR, logger="hostwatch.outbox"):
        agent = Agent(cfg)
    assert any("could not be opened" in r.getMessage() for r in caplog.records)
    moved = list(cfg.data_dir.glob("outbox.db.corrupt-*"))
    assert len(moved) == 1
    agent.outbox.enqueue(requests_for("e", n_points=1), "e")
    assert agent.outbox.depth() == 1
    agent._outbox_status()
    assert "corrupt" in agent.status["outbox"].reason and moved[0].name in agent.status["outbox"].reason


def test_locked_outbox_is_not_replaced(tmp_path, monkeypatch):
    path = tmp_path / "data/outbox.db"
    Outbox(path).close()
    before = path.read_bytes()

    def locked(p):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(Outbox, "_open", staticmethod(locked))
    with pytest.raises(sqlite3.OperationalError):
        Outbox(path)
    assert path.read_bytes() == before and not list(path.parent.glob("outbox.db.corrupt-*"))


def test_no_stale_sidecar_files_remain_beside_a_fresh_outbox(tmp_path):
    path = tmp_path / "data/outbox.db"
    path.parent.mkdir()
    path.write_bytes(b"garbage " * 100)
    (tmp_path / "data/outbox.db-journal").write_bytes(b"j")
    (tmp_path / "data/outbox.db-wal").write_bytes(b"w")
    box = Outbox(path)
    assert box.recovered_from is not None
    assert not (tmp_path / "data/outbox.db-journal").exists() and not (tmp_path / "data/outbox.db-wal").exists()
    box.enqueue(requests_for("e", n_points=1), "e")
    assert box.depth() == 1


def test_the_old_batch_table_is_dropped_and_markers_are_kept(tmp_path):
    path = tmp_path / "data/outbox.db"
    path.parent.mkdir()
    old = sqlite3.connect(path)
    old.executescript(
        "CREATE TABLE batches (seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);"
        "INSERT INTO batches (payload) VALUES ('{}');"
        "CREATE TABLE markers (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
        "INSERT INTO markers VALUES ('journal.cursor', 'cursor-1');")
    old.commit()
    old.close()
    box = Outbox(path)
    assert box.recovered_from is None and box.get("journal.cursor") == "cursor-1"
    tables = {r[0] for r in sqlite3.connect(path).execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "batches" not in tables and "requests" in tables


def _fail_first_open(monkeypatch):
    """Report corruption on the first open without touching the files, so the
    sidecars are still present when the move code runs."""
    real = Outbox._open
    calls = {"n": 0}

    def fake(path):
        calls["n"] += 1
        if calls["n"] == 1:
            raise sqlite3.DatabaseError("file is not a database")
        return real(path)

    monkeypatch.setattr(Outbox, "_open", staticmethod(fake))


def test_sidecars_are_moved_with_a_corrupt_outbox(tmp_path, monkeypatch):
    _fail_first_open(monkeypatch)
    path = tmp_path / "data/outbox.db"
    path.parent.mkdir()
    path.write_bytes(b"garbage " * 100)
    (tmp_path / "data/outbox.db-wal").write_bytes(b"w")
    box = Outbox(path)
    moved = box.recovered_from
    assert moved is not None and moved.read_bytes() == b"garbage " * 100
    assert (moved.parent / (moved.name + "-wal")).read_bytes() == b"w"
    assert not (tmp_path / "data/outbox.db-wal").exists()


def test_failed_sidecar_move_leaves_the_corrupt_file_in_place(tmp_path, monkeypatch):
    _fail_first_open(monkeypatch)
    from pathlib import Path
    path = tmp_path / "data/outbox.db"
    path.parent.mkdir()
    path.write_bytes(b"garbage " * 100)
    (tmp_path / "data/outbox.db-wal").write_bytes(b"w")
    real = Path.rename

    def failing(self, target):
        if self.name.endswith("-wal"):
            raise PermissionError("locked")
        return real(self, target)

    monkeypatch.setattr(Path, "rename", failing)
    with pytest.raises(PermissionError):
        Outbox(path)
    assert path.read_bytes() == b"garbage " * 100


# -- delivery backoff and the loop -------------------------------------------------------------

def test_thirty_minute_5xx_episode_keeps_every_request_and_delivers_after_recovery(tmp_path):
    clock = {"t": 1000.0}
    agent = Agent(make_cfg(tmp_path), clock=lambda: clock["t"])
    agent.detect()
    observe = FakeObserve(answers=[503, 500])
    n = 0
    with observe.client() as client:
        while clock["t"] < 1000.0 + 30 * 60:
            agent.outbox.enqueue(requests_for(f"e{n}", n_records=1), f"e{n}")
            n += 1
            agent._try_flush(client)
            clock["t"] += 15.0
        assert agent.outbox.depth() == n and agent.outbox.dead_letter_count() == 0
        assert agent._next_flush - clock["t"] <= agent_mod.MAX_BACKOFF_S
        agent._outbox_status()
        assert "stalled for 1" in agent.status["outbox"].reason
        clock["t"] = agent._next_flush
        observe.answers = [200]
        agent._try_flush(client)
    assert agent.outbox.depth() == 0 and agent._stall_since is None


def test_a_retry_after_longer_than_the_backoff_is_honoured_up_to_the_cap(tmp_path):
    clock = {"t": 1000.0}
    agent = Agent(make_cfg(tmp_path), clock=lambda: clock["t"])
    agent.outbox.enqueue(requests_for("e", n_points=1), "e")
    with FakeObserve(answers=[(429, {"Retry-After": "120"}, b"")]).client() as client:
        agent._try_flush(client)
    assert agent._next_flush == 1000.0 + 120
    with FakeObserve(answers=[(503, {"Retry-After": "99999"}, b"")]).client() as client:
        agent._next_flush = 0.0
        agent._try_flush(client)
    assert agent._next_flush == 1000.0 + agent_mod.MAX_BACKOFF_S


def _patch_client(monkeypatch, observe=None):
    observe = observe or FakeObserve()
    real_client = httpx.Client
    monkeypatch.setattr(agent_mod.httpx, "Client",
                        lambda **_kw: real_client(transport=httpx.MockTransport(observe.handler)))
    return observe


def _fast_loop(agent):
    agent.sleep_s = lambda: 0.0


def test_start_boot_check_raising_does_not_stop_the_loop(tmp_path, monkeypatch):
    agent = Agent(make_cfg(tmp_path))
    ticks = []

    def boom():
        raise RuntimeError("classifier exploded")

    monkeypatch.setattr(agent, "start_boot_check", boom)
    real_tick = agent.tick

    def counting(client):
        ticks.append(1)
        if len(ticks) >= 2:
            agent.stop()
        return real_tick(client)

    monkeypatch.setattr(agent, "tick", counting)
    _fast_loop(agent)
    _patch_client(monkeypatch)
    agent.run()
    assert len(ticks) == 2
    assert agent.status["boot"].available is False
    assert "unknown" in agent.status["boot"].reason and "classifier exploded" in agent.status["boot"].reason


def test_unexpected_error_in_the_loop_body_is_logged_and_the_loop_continues(tmp_path, monkeypatch):
    agent = Agent(make_cfg(tmp_path))
    calls = []

    def flaky_tick(client):
        calls.append(1)
        if len(calls) == 1:
            raise MemoryError("odd")
        agent.stop()

    monkeypatch.setattr(agent, "tick", flaky_tick)
    _fast_loop(agent)
    _patch_client(monkeypatch)
    agent.run()
    assert len(calls) == 2


def test_sigterm_during_a_heartbeat_write_completes_shutdown_with_the_clean_flag(tmp_path, monkeypatch):
    from hostwatch.events import boot

    cfg = make_cfg(tmp_path)
    agent = Agent(cfg)
    _fast_loop(agent)
    _patch_client(monkeypatch)
    real_write = boot.Heartbeat._write
    seen = {"signalled": False}

    def write_with_signal(self, clean):
        if not clean and not seen["signalled"]:
            seen["signalled"] = True
            agent.stop()  # what the SIGTERM handler does, while the heartbeat lock is held
        real_write(self, clean)

    monkeypatch.setattr(boot.Heartbeat, "_write", write_with_signal)
    agent.run()  # a handler that took the heartbeat lock would deadlock here
    assert seen["signalled"]
    assert boot.load_heartbeat(cfg.data_dir)["agent_stopped_cleanly"] is True


def test_first_poll_detects_sources_on_a_freshly_booted_host(tmp_path):
    """Regression: a monotonic clock counts from host boot on Linux, so a host up for less than
    redetect_s used to skip detection and fail every poll."""
    agent = Agent(make_cfg(tmp_path), clock=lambda: 5.0)
    collect_once(agent)
    assert all(c.id in agent.status for c in agent.collectors)


def test_an_idle_event_read_writes_nothing_to_the_outbox(tmp_path):
    """The loop reads events every few seconds, and SQLite with synchronous FULL syncs on each write,
    so a read that found nothing must not open a transaction."""
    agent = Agent(make_cfg(tmp_path))
    agent.detect()
    for _ in range(2):  # the second read sees the `agent` source the first one reported
        assert event_cycle(agent, watch=True) is True
    before = agent.outbox._db.total_changes
    for _ in range(3):
        assert event_cycle(agent, watch=True) is True
    assert agent.outbox._db.total_changes == before and agent.outbox.depth() == 0
