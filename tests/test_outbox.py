"""Durable outbox tests: restarts, outages, overflow, dead letters and markers.

Each test that simulates a restart builds a second Agent on the same data
directory, which is what a restarted process does.
"""

from __future__ import annotations

import json
import logging
import sqlite3

import httpx
import pytest

from hostwatch.agent import Agent
from hostwatch.config import Config
from hostwatch.events.journal import JournalWatcher
from hostwatch.outbox import Outbox
from hostwatch.schema import Batch, Event, Sample, SourceStatus

TOKEN = "t" * 32
OLD, NEW = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"


def make_cfg(tmp_path, **over):
    procfs, sysfs, data = tmp_path / "proc", tmp_path / "sys", tmp_path / "data"
    (procfs / "sys/kernel/random").mkdir(parents=True, exist_ok=True)
    (procfs / "sys/kernel/random/boot_id").write_text(NEW + "\n")
    sysfs.mkdir(exist_ok=True)
    data.mkdir(exist_ok=True)
    args = dict(procfs=procfs, sysfs=sysfs, data_dir=data, ingest_token=TOKEN, host_name="h",
                pstore=tmp_path / "none", journal=tmp_path / "none", rasdaemon_db=tmp_path / "none.db")
    args.update(over)
    return Config(**args)


def hub_client(status=200, log=None):
    def handler(request):
        body = json.loads(request.content)
        if log is not None:
            log.append(body)
        code = status(body) if callable(status) else status
        return httpx.Response(code, json={})

    return httpx.Client(transport=httpx.MockTransport(handler))


def down_client():
    def refuse(request):
        raise httpx.ConnectError("refused")

    return httpx.Client(transport=httpx.MockTransport(refuse))


def event(key, source="journal"):
    return Event(kind="x", severity="info", source=source, ts=1.0, title="t", dedup_key=key)


def batch(n, samples=0, events=()):
    return Batch(agent_version="t", host="h", platform="x86", sent_at=float(n), sources=[],
                 samples=[Sample(source="s", metric="m", value=1.0, ts=float(n)) for _ in range(samples)],
                 events=list(events), batch_id=f"b{n}")


def test_restart_during_hub_outage_resends_queued_events(tmp_path):
    cfg = make_cfg(tmp_path)
    first = Agent(cfg)
    first.detect()
    first.outbox.stage("k", "v")
    first.outbox.enqueue(batch(1, events=[event("e1")]))
    first.cycle()
    try:
        first.flush(down_client())
    except httpx.ConnectError:
        pass
    assert first.outbox.depth() == 2
    first.outbox.close()
    second = Agent(cfg)  # restart
    assert second.outbox.depth() == 2 and second.outbox.get("k") == "v"
    received: list = []
    second.flush(hub_client(log=received))
    assert second.outbox.depth() == 0
    assert received[0]["batch_id"] == "b1" and received[0]["events"][0]["dedup_key"] == "e1"
    assert len(received) == 2


def test_batch_stays_queued_on_5xx_and_is_acked_only_on_2xx(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(batch(1))
    try:
        agent.flush(hub_client(status=503))
    except httpx.HTTPStatusError:
        pass
    assert agent.outbox.depth() == 1
    agent.flush(hub_client(status=200))
    assert agent.outbox.depth() == 0


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
    assert len(crashed.collect_once().events) == 2
    # Crash after reading but before the batch reached the outbox: the cursor
    # was only staged, so the restarted agent reads the entries again.
    crashed.outbox.close()
    again = journal_agent(tmp_path, ENTRIES)
    batch_two = again.collect_once()
    assert [e.dedup_key for e in batch_two.events] == ["journal:c1", "journal:c2"]
    again.outbox.enqueue(batch_two)
    # Crash after enqueue: the events are in the outbox and the cursor moved with them.
    again.outbox.close()
    final = journal_agent(tmp_path, ENTRIES)
    assert final.collect_once().events == []
    received: list = []
    final.flush(hub_client(log=received))
    assert [e["dedup_key"] for e in received[0]["events"]] == ["journal:c1", "journal:c2"]


def test_legacy_journal_cursor_file_is_imported(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data/journal.cursor").write_text("c1")
    agent = journal_agent(tmp_path, ENTRIES)
    assert [e.dedup_key for e in agent.collect_once().events] == ["journal:c2"]


def test_pstore_sent_keys_survive_restart(tmp_path):
    pstore = tmp_path / "pstore"
    pstore.mkdir()
    (pstore / "dmesg-efi-1").write_text("Kernel panic - not syncing")
    cfg = make_cfg(tmp_path, pstore=pstore)
    first = Agent(cfg)
    first.detect()
    assert len([e for e in first.collect_once().events if e.source == "pstore"]) == 1
    first.cycle()  # the sent keys are committed with this batch
    first.outbox.close()
    second = Agent(cfg)
    second.detect()
    assert [e for e in second.collect_once().events if e.source == "pstore"] == []


def test_rasdaemon_high_water_commits_with_the_batch(tmp_path):
    db = tmp_path / "ras.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE mc_event (id INTEGER PRIMARY KEY, timestamp TEXT, err_type TEXT, err_msg TEXT)")
    conn.execute("INSERT INTO mc_event (timestamp, err_type, err_msg) VALUES ('2026-10-02 12:00:00', 'Corrected', 'm')")
    conn.commit()
    conn.close()
    cfg = make_cfg(tmp_path, rasdaemon_db=db)
    lost = Agent(cfg)
    assert len([e for e in lost.collect_once().events if e.source == "rasdaemon"]) == 1
    lost.outbox.close()  # crashed before enqueue
    kept = Agent(cfg)
    b = kept.collect_once()
    assert len([e for e in b.events if e.source == "rasdaemon"]) == 1
    kept.outbox.enqueue(b)
    kept.outbox.close()
    final = Agent(cfg)
    assert [e for e in final.collect_once().events if e.source == "rasdaemon"] == []


def test_overflow_drops_samples_before_events_and_reports_count(tmp_path, caplog):
    cfg = make_cfg(tmp_path)
    agent = Agent(cfg)
    agent.outbox.close()
    agent.outbox = Outbox(cfg.data_dir / "outbox.db", max_batches=3)
    agent.outbox.enqueue(batch(1, samples=4, events=[event("keep-me")]))
    with caplog.at_level(logging.WARNING, logger="hostwatch.outbox"):
        for n in range(2, 7):
            agent.outbox.enqueue(batch(n, samples=2))
    assert agent.outbox.depth() == 3
    assert agent.outbox.dropped_total() == 4 + 2 + 2
    sent: list = []
    agent.flush(hub_client(log=sent))
    keys = [e["dedup_key"] for b in sent for e in b["events"]]
    assert keys == ["keep-me"]  # the event outlived the batch that first carried it
    assert all(b["samples"] for b in sent)  # what remains are the newest samples
    assert any("dropped" in r.getMessage() for r in caplog.records)


def test_overflow_is_reported_as_outbox_source_status(tmp_path):
    cfg = make_cfg(tmp_path)
    agent = Agent(cfg)
    agent.outbox.close()
    agent.outbox = Outbox(cfg.data_dir / "outbox.db", max_batches=2)
    for n in range(1, 5):
        agent.outbox.enqueue(batch(n, samples=3))
    out = agent.collect_once()
    status = next(s for s in out.sources if s.source == "outbox")
    assert status.available is False and "6 sample(s) dropped" in status.reason
    agent.flush(hub_client())
    agent.outbox.enqueue(batch(9))
    agent.collect_once()
    assert agent.status["outbox"].available is True  # drained, so the drop run is over


def test_400_dead_letters_the_batch_and_the_next_is_sent(tmp_path, caplog):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(batch(1, events=[event("bad")]))
    agent.outbox.enqueue(batch(2, events=[event("good")]))
    sent: list = []
    with caplog.at_level(logging.ERROR, logger="hostwatch.outbox"):
        agent.flush(hub_client(status=lambda body: 400 if body["batch_id"] == "b1" else 200, log=sent))
    assert [b["batch_id"] for b in sent] == ["b1", "b2"]
    assert agent.outbox.depth() == 0 and agent.outbox.dead_letter_count() == 1
    assert any("400" in r.getMessage() for r in caplog.records)
    agent.collect_once()
    assert "dead-letter" in agent.status["outbox"].reason
    row = sqlite3.connect(tmp_path / "data/outbox.db").execute("SELECT batch_id, status FROM dead_letters").fetchone()
    assert row == ("b1", 400)


def test_401_keeps_the_batch(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(batch(1))
    try:
        agent.flush(hub_client(status=401))
    except httpx.HTTPStatusError:
        pass
    assert agent.outbox.depth() == 1 and agent.outbox.dead_letter_count() == 0


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
    first.outbox.close()    # crash before any batch was built
    second = Agent(cfg)
    second.start_boot_check()  # same boot, so nothing is classified again
    (ev,) = second.collect_once().events
    assert ev.kind == "boot.agent_stopped" and ev.dedup_key == f"boot:{NEW}"


def test_a_cycle_that_raises_is_followed_by_a_normal_cycle(tmp_path, caplog):
    agent = Agent(make_cfg(tmp_path))
    real = agent.collect_once
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return real()

    agent.collect_once = flaky
    with caplog.at_level(logging.ERROR, logger="hostwatch.agent"):
        assert agent.safe_cycle() is False
    assert any("cycle failed" in r.getMessage() for r in caplog.records)
    assert agent.status["agent"].available is False and "boom" in agent.status["agent"].reason
    assert agent.outbox.depth() == 0
    assert agent.safe_cycle() is True
    assert agent.outbox.depth() == 1 and agent.status["agent"].available is True


def test_events_read_in_a_failed_cycle_are_not_lost(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    fake = event("lost-1", source="fake")
    agent.event_sources = {"fake": lambda: (SourceStatus(source="fake", available=True), [fake])}
    real = agent.outbox.enqueue
    agent.outbox.enqueue = lambda b: (_ for _ in ()).throw(sqlite3.OperationalError("disk full"))
    assert agent.safe_cycle() is False
    agent.outbox.enqueue = real
    assert agent.safe_cycle() is True
    (_, queued) = agent.outbox.peek()
    assert [e.dedup_key for e in queued.events] == ["lost-1"]


def test_404_stays_queued_and_is_retried(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(batch(1, events=[event("k")]))
    for _ in range(2):
        with pytest.raises(httpx.HTTPStatusError):
            agent.flush(hub_client(status=404))
    assert agent.outbox.depth() == 1 and agent.outbox.dead_letter_count() == 0
    sent: list = []
    agent.flush(hub_client(log=sent))
    assert [b["batch_id"] for b in sent] == ["b1"] and agent.outbox.depth() == 0


def test_422_dead_letters_the_batch(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(batch(1))
    agent.flush(hub_client(status=422))
    assert agent.outbox.depth() == 0 and agent.outbox.dead_letter_count() == 1


def test_network_errors_never_dead_letter(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(batch(1))
    for _ in range(8):
        with pytest.raises(httpx.ConnectError):
            agent.flush(down_client())
    assert agent.outbox.depth() == 1 and agent.outbox.dead_letter_count() == 0


def test_garbage_outbox_is_quarantined_and_the_agent_starts(tmp_path, caplog):
    cfg = make_cfg(tmp_path)
    (cfg.data_dir / "outbox.db").write_bytes(b"this is not a sqlite database " * 50)
    with caplog.at_level(logging.ERROR, logger="hostwatch.outbox"):
        agent = Agent(cfg)
    assert any("could not be opened" in r.getMessage() for r in caplog.records)
    moved = list(cfg.data_dir.glob("outbox.db.corrupt-*"))
    assert len(moved) == 1
    agent.outbox.enqueue(batch(1))
    assert agent.outbox.depth() == 1
    agent.collect_once()
    assert "corrupt" in agent.status["outbox"].reason and moved[0].name in agent.status["outbox"].reason


def md_agent(tmp_path):
    cfg = make_cfg(tmp_path)
    (cfg.sysfs / "block/md0/md").mkdir(parents=True)
    (cfg.sysfs / "block/md0/md/degraded").write_text("1\n")
    agent = Agent(cfg)
    agent.detect()
    return agent


def seed_client(rows):
    def handler(request):
        return httpx.Response(200, json=rows)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_threshold_events_wait_for_a_delayed_seed_and_do_not_duplicate(tmp_path):
    from hostwatch.events.thresholds import ThresholdEngine

    prior = ThresholdEngine().evaluate(
        [Sample(source="mdraid", metric="degraded", value=1, labels={"array": "md0"}, ts=1.0)], [], now=1.0)
    stored = [{**e.model_dump(), "id": 1} for e in prior]
    agent = md_agent(tmp_path)
    assert agent.seed_thresholds(down_client()) is False
    held = agent.collect_once()
    assert not [e for e in held.events if e.source == "thresholds"]
    assert agent.seed_thresholds(seed_client(stored)) is True
    after = agent.collect_once()
    assert not [e for e in after.events if e.kind == "md.degraded"]


def test_threshold_event_would_be_emitted_without_a_seed_of_the_open_condition(tmp_path):
    """Control for the test above: seeded from an empty hub, the same sample
    does produce md.degraded, so the held-back result is meaningful."""
    agent = md_agent(tmp_path)
    assert agent.seed_thresholds(seed_client([])) is True
    assert [e for e in agent.collect_once().events if e.kind == "md.degraded"]


def test_failed_seed_is_reported_in_a_source_status_and_cleared_when_it_succeeds(tmp_path):
    agent = md_agent(tmp_path)
    agent._try_seed(down_client())
    assert not agent.status["thresholds"].available
    assert "held back" in agent.status["thresholds"].reason
    agent._next_seed = 0.0
    agent._try_seed(seed_client([]))
    assert agent.seeded and "thresholds" not in agent.status


def test_seed_and_flush_retries_back_off_and_recover(tmp_path):
    agent = Agent(make_cfg(tmp_path, interval_s=15.0))
    agent._try_seed(down_client())
    assert agent._seed_failures == 1 and agent._next_seed > 0
    first = agent._next_seed
    agent._try_seed(seed_client([]))  # still inside the backoff window, so no attempt is made
    assert not agent.seeded and agent._seed_failures == 1 and agent._next_seed == first
    agent._next_seed = 0.0
    agent._try_seed(seed_client([]))
    assert agent.seeded

    agent.outbox.enqueue(batch(1))
    agent._try_flush(down_client())
    assert agent._flush_failures == 1 and agent._next_flush > 0
    agent._try_flush(hub_client())  # backoff not elapsed, nothing is sent
    assert agent.outbox.depth() == 1
    agent._next_flush = 0.0
    agent._try_flush(hub_client())
    assert agent.outbox.depth() == 0 and agent._flush_failures == 0


@pytest.mark.parametrize("code", [500, 501, 502, 503, 504, 408, 429, 401, 404])
def test_hub_side_statuses_never_dead_letter(tmp_path, code):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(batch(1))
    for _ in range(8):
        with pytest.raises(httpx.HTTPStatusError):
            agent.flush(hub_client(status=code))
    assert agent.outbox.depth() == 1 and agent.outbox.dead_letter_count() == 0


def test_quarantined_batches_are_not_trimmed_by_the_dead_letter_cap(tmp_path, monkeypatch):
    import hostwatch.outbox as ob

    monkeypatch.setattr(ob, "MAX_DEAD_LETTERS", 2)
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(batch(1))
    seq, _ = agent.outbox.peek()
    agent.outbox.dead_letter(seq, 500, quarantine=True)
    for n in range(2, 7):
        agent.outbox.enqueue(batch(n))
        agent.outbox.dead_letter(agent.outbox.peek()[0], 400)
    rows = sqlite3.connect(tmp_path / "data/outbox.db").execute(
        "SELECT batch_id FROM dead_letters ORDER BY id").fetchall()
    assert ("b1",) in rows and len(rows) == 3


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
    # SQLite may itself discard an invalid sidecar while probing the file; either
    # way none may be left next to the fresh database.
    box.enqueue(batch(1))
    assert box.depth() == 1


def test_outbox_created_with_the_previous_schema_is_migrated_and_keeps_dead_letters(tmp_path):
    path = tmp_path / "data/outbox.db"
    path.parent.mkdir()
    old = sqlite3.connect(path)
    old.executescript(
        "CREATE TABLE batches (seq INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT NOT NULL, payload TEXT NOT NULL);"
        "CREATE TABLE markers (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
        "CREATE TABLE dead_letters (id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT NOT NULL, "
        "status INTEGER NOT NULL, ts REAL NOT NULL, payload TEXT NOT NULL);"
        "CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);"
        "INSERT INTO dead_letters (batch_id, status, ts, payload) VALUES ('old-1', 422, 1.0, '{}');"
        "INSERT INTO markers VALUES ('journal', 'cursor-1');")
    old.commit()
    old.close()
    box = Outbox(path)
    assert box.recovered_from is None
    assert box.dead_letter_count() == 1
    assert box.quarantined_total() == 0
    assert box.get("journal") == "cursor-1"
    box.enqueue(batch(1))
    (seq, _) = box.peek()
    box.dead_letter(seq, 500, quarantine=True)
    assert box.dead_letter_count() == 2
    assert box.quarantined_total() == 1


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


def test_threshold_event_is_not_lost_when_the_cycle_fails_after_it_opened(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.seeded = True
    samples = [Sample(source="mdraid", metric="degraded", value=1, labels={"array": "md0"}, ts=1.0)]
    real_collect = agent.collect_once
    agent.collectors = []
    real_eval = agent.thresholds.evaluate
    agent.thresholds.evaluate = lambda s, st, now=None: real_eval(samples, st)
    real = agent.outbox.enqueue
    agent.outbox.enqueue = lambda b: (_ for _ in ()).throw(sqlite3.OperationalError("disk full"))
    assert agent.safe_cycle() is False
    agent.outbox.enqueue = real
    assert agent.safe_cycle() is True
    kinds = [e.kind for e in agent.outbox.peek()[1].events]
    assert kinds.count("md.degraded") == 1
    assert real_collect is not None


ENTRIES_FOR_REREAD = [
    {"__CURSOR": "c1", "__REALTIME_TIMESTAMP": "1000000", "MESSAGE": "ata3: hard resetting link"},
    {"__CURSOR": "c2", "__REALTIME_TIMESTAMP": "2000000", "MESSAGE": "md127: Disk failure on sdc"}]


class AfterCursorReader:
    """Serves entries after the cursor, like journalctl --after-cursor."""

    def __init__(self, entries):
        self.entries = entries

    def __call__(self, directory, cursor):
        start = [e["__CURSOR"] for e in self.entries].index(cursor) + 1 if cursor else 0
        return [json.dumps(e) for e in self.entries[start:]]


def _patch_client(monkeypatch):
    import hostwatch.agent as agent_mod

    real_client = httpx.Client
    monkeypatch.setattr(agent_mod.httpx, "Client", lambda **_kw: real_client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))))


def test_cycle_that_fails_after_the_journal_read_rereads_the_same_entries(tmp_path, monkeypatch):
    from hostwatch.events.journal import BackgroundJournal

    jdir = tmp_path / "journal"
    jdir.mkdir()
    (jdir / "system.journal").write_bytes(b"x")
    agent = Agent(make_cfg(tmp_path, journal=jdir))
    watcher = JournalWatcher(jdir, agent.cfg.data_dir, AfterCursorReader(ENTRIES_FOR_REREAD), markers=agent.outbox)
    background = agent.journal = BackgroundJournal(watcher)
    agent.event_sources = {"journal": background.read}
    agent.detect()

    def cycle_and_settle():
        ok = agent.safe_cycle()
        if background._thread is not None:
            background._thread.join()
        return ok

    cycle_and_settle()  # starts the first worker
    real_enqueue = agent.outbox.enqueue
    state = {"fail": True}

    def flaky(batch):
        if state["fail"] and batch.events:
            state["fail"] = False
            raise RuntimeError("disk full")
        real_enqueue(batch)

    monkeypatch.setattr(agent.outbox, "enqueue", flaky)
    assert cycle_and_settle() is False  # the cycle read the entries, then failed
    assert agent.outbox.get("journal.cursor") is None
    for _ in range(3):
        assert cycle_and_settle() is True
    sent: list = []
    agent.flush(hub_client(log=sent))
    keys = [e["dedup_key"] for b in sent for e in b["events"]]
    assert keys == ["journal:c1", "journal:c2"]
    assert agent.outbox.get("journal.cursor") == "c2"


def test_thirty_minute_5xx_episode_keeps_every_batch_and_delivers_after_recovery(tmp_path, monkeypatch):
    import hostwatch.agent as agent_mod

    clock = {"t": 1000.0}
    monkeypatch.setattr(agent_mod.time, "monotonic", lambda: clock["t"])
    agent = Agent(make_cfg(tmp_path, interval_s=15.0))
    agent.detect()
    outage = hub_client(status=503)
    mixed = hub_client(status=500)
    n = 0
    while clock["t"] < 1000.0 + 30 * 60:
        agent.outbox.enqueue(batch(n, events=[event(f"e{n}")]))
        n += 1
        agent._try_flush(outage if n % 2 else mixed)
        clock["t"] += 15.0
    assert agent.outbox.depth() == n and agent.outbox.dead_letter_count() == 0
    assert agent._next_flush - clock["t"] <= agent_mod.MAX_BACKOFF_S
    agent.collect_once()
    assert "stalled for 1" in agent.status["outbox"].reason
    sent: list = []
    clock["t"] = agent._next_flush
    agent._try_flush(hub_client(log=sent))
    assert [b["batch_id"] for b in sent] == [f"b{i}" for i in range(n)]
    assert agent.outbox.depth() == 0 and agent._stall_since is None


def test_corrupt_outbox_row_is_dead_lettered_and_later_rows_deliver(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(batch(1, events=[event("a")]))
    agent.outbox.enqueue(batch(2, events=[event("b")]))
    agent.outbox.enqueue(batch(3, events=[event("c")]))
    db = sqlite3.connect(tmp_path / "data/outbox.db")
    db.execute("UPDATE batches SET payload='{not json' WHERE batch_id='b1'")
    db.commit()
    db.close()
    sent: list = []
    agent.flush(hub_client(log=sent))
    assert [b["batch_id"] for b in sent] == ["b2", "b3"]
    assert agent.outbox.depth() == 0 and agent.outbox.dead_letter_count() == 1
    row = sqlite3.connect(tmp_path / "data/outbox.db").execute(
        "SELECT batch_id, status, error FROM dead_letters").fetchone()
    assert row[0] == "b1" and row[1] == 0 and row[2]
    agent.collect_once()
    assert "could not be decoded" in agent.status["outbox"].reason


def test_corrupt_row_at_the_overflow_edge_does_not_fail_enqueue(tmp_path):
    box = Outbox(tmp_path / "data/o.db", max_batches=2)
    box.enqueue(batch(1, samples=1))
    box.enqueue(batch(2, events=[event("b")]))
    db = sqlite3.connect(tmp_path / "data/o.db")
    db.execute("UPDATE batches SET payload='garbage' WHERE batch_id='b1'")
    db.commit()
    db.close()
    box.enqueue(batch(3))
    assert box.undecodable_total() == 1 and box.depth() == 2


def test_start_boot_check_raising_does_not_stop_the_loop(tmp_path, monkeypatch):
    agent = Agent(make_cfg(tmp_path, interval_s=0.01))
    cycles = []

    def boom():
        raise RuntimeError("classifier exploded")

    monkeypatch.setattr(agent, "start_boot_check", boom)
    real_cycle = agent.safe_cycle

    def counting():
        cycles.append(1)
        if len(cycles) >= 2:
            agent.stop()
        return real_cycle()

    monkeypatch.setattr(agent, "safe_cycle", counting)
    _patch_client(monkeypatch)
    monkeypatch.setattr(agent, "seed_thresholds", lambda c: (_ for _ in ()).throw(ValueError("bad page")))
    agent.run()
    assert len(cycles) == 2
    assert agent.status["boot"].available is False
    assert "unknown" in agent.status["boot"].reason and "classifier exploded" in agent.status["boot"].reason


def test_unexpected_error_in_the_loop_body_is_logged_and_the_loop_continues(tmp_path, monkeypatch):
    agent = Agent(make_cfg(tmp_path, interval_s=0.01))
    calls = []

    def flaky_seed(client):
        calls.append(1)
        if len(calls) == 1:
            raise MemoryError("odd")
        agent.stop()

    monkeypatch.setattr(agent, "_try_seed", flaky_seed)
    _patch_client(monkeypatch)
    agent.run()
    assert len(calls) == 2


def test_sigterm_during_a_heartbeat_write_completes_shutdown_with_the_clean_flag(tmp_path, monkeypatch):
    from hostwatch.events import boot

    cfg = make_cfg(tmp_path, interval_s=0.01)
    agent = Agent(cfg)
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


def test_first_cycle_detects_sources_on_a_freshly_booted_host(tmp_path, monkeypatch):
    """Regression: time.monotonic() counts from host boot on Linux, so a host up
    for less than redetect_s used to skip detection and fail every cycle."""
    import hostwatch.agent as agent_mod
    monkeypatch.setattr(agent_mod.time, "monotonic", lambda: 5.0)
    agent = Agent(make_cfg(tmp_path))
    agent.collect_once()
    assert all(c.id in agent.status for c in agent.collectors)
