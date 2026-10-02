"""Durable outbox tests: restarts, outages, overflow, dead letters and markers.

Each test that simulates a restart builds a second Agent on the same data
directory, which is what a restarted process does.
"""

from __future__ import annotations

import json
import logging
import sqlite3

import httpx

from hostwatch.agent import Agent
from hostwatch.config import Config
from hostwatch.events.journal import JournalWatcher
from hostwatch.outbox import Outbox
from hostwatch.schema import Batch, Event, Sample

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
    assert ev.kind == "boot.clean_shutdown" and ev.dedup_key == f"boot:{NEW}"
