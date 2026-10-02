"""rasdaemon ingestion tests on a fixture database."""

from __future__ import annotations

import sqlite3
import time

import pytest

from hostwatch.outbox import Outbox
from hostwatch.schema import Batch

from hostwatch.events.rasdaemon import KIND, RasdaemonReader, open_readonly


def make_db(tmp_path, tables=("mc_event", "aer_event", "mce_record")):
    path = tmp_path / "ras-mc_event.db"
    conn = sqlite3.connect(path)
    if "mc_event" in tables:
        conn.execute("CREATE TABLE mc_event (id INTEGER PRIMARY KEY, timestamp TEXT, err_count INTEGER, "
                     "err_type TEXT, err_msg TEXT, label TEXT, mc INTEGER)")
    if "aer_event" in tables:
        conn.execute("CREATE TABLE aer_event (id INTEGER PRIMARY KEY, timestamp TEXT, dev_name TEXT, "
                     "err_type TEXT, err_msg TEXT)")
    if "mce_record" in tables:
        conn.execute("CREATE TABLE mce_record (id INTEGER PRIMARY KEY, timestamp TEXT, bank INTEGER, "
                     "status INTEGER, error_msg TEXT)")
    conn.commit()
    conn.close()
    return path


def insert(path, sql, args=()):
    conn = sqlite3.connect(path)
    conn.execute(sql, args)
    conn.commit()
    conn.close()


def add_mc(path, err_type="Corrected", ts="2026-10-02 12:00:00 +0000"):
    insert(path, "INSERT INTO mc_event (timestamp, err_count, err_type, err_msg, label, mc) "
                 "VALUES (?, 1, ?, 'page error', 'DIMM_A1', 0)", (ts, err_type))


def test_new_rows_give_events_and_nothing_is_reemitted(tmp_path):
    path = make_db(tmp_path)
    add_mc(path)
    reader = RasdaemonReader(path)
    status, first = reader.read()
    assert status.available
    (ev,) = first
    assert ev.kind == KIND and ev.source == "rasdaemon" and ev.severity == "warning"
    assert ev.dedup_key == "rasdaemon:mc_event:1:2026-10-02 12:00:00 +0000" and ev.detail["label"] == "DIMM_A1"
    assert ev.ts == pytest.approx(1790942400.0)
    _, again = reader.read()
    assert again == []
    add_mc(path, err_type="Uncorrected")
    _, third = reader.read()
    assert [e.dedup_key for e in third] == ["rasdaemon:mc_event:2:2026-10-02 12:00:00 +0000"]
    assert third[0].severity == "critical"


def test_aer_and_mce_rows(tmp_path):
    path = make_db(tmp_path)
    insert(path, "INSERT INTO aer_event (timestamp, dev_name, err_type, err_msg) "
                 "VALUES ('2026-10-02 12:00:00', '0000-00-1c.0', 'Corrected', 'RxErr')")
    insert(path, "INSERT INTO mce_record (timestamp, bank, status, error_msg) "
                 "VALUES ('2026-10-02 12:00:01', 4, 1, 'cache error')")
    _, events = RasdaemonReader(path).read()
    by_key = {e.dedup_key: e for e in events}
    assert by_key["rasdaemon:aer_event:1:2026-10-02 12:00:00"].severity == "warning"
    assert by_key["rasdaemon:mce_record:1:2026-10-02 12:00:01"].severity == "critical"


def test_missing_table_is_skipped_with_reason(tmp_path):
    path = make_db(tmp_path, tables=("mc_event",))
    add_mc(path)
    status, events = RasdaemonReader(path).read()
    assert status.available and len(events) == 1
    assert "aer_event" in status.reason and "mce_record" in status.reason


def test_no_known_tables_is_unavailable(tmp_path):
    path = make_db(tmp_path, tables=())
    status, events = RasdaemonReader(path).read()
    assert not status.available and "absent" in status.reason and events == []


def test_missing_database_is_unavailable(tmp_path):
    status, events = RasdaemonReader(tmp_path / "absent.db").read()
    assert not status.available and "does not exist" in status.reason and events == []


def test_unparseable_timestamp_is_flagged(tmp_path):
    path = make_db(tmp_path)
    add_mc(path, ts="yesterday")
    _, (ev,) = RasdaemonReader(path).read()
    assert ev.detail["ts_is_read_time"] and ev.detail["timestamp_raw"] == "yesterday"


def test_connection_is_read_only(tmp_path):
    path = make_db(tmp_path)
    add_mc(path)
    conn = open_readonly(path)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("INSERT INTO mc_event (timestamp) VALUES ('x')")
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("DELETE FROM mc_event")
    conn.close()
    _, events = RasdaemonReader(path).read()
    assert len(events) == 1


def drain(path, outbox, max_cycles=10):
    """Run reader cycles the way the agent does: a fresh reader per process,
    each cycle's events enqueued with the markers it staged."""
    keys = []
    for _ in range(max_cycles):
        _, events = RasdaemonReader(path, markers=outbox).read()
        if not events:
            break
        keys.extend(e.dedup_key for e in events)
        outbox.enqueue(Batch(agent_version="t", host="h", platform="x86", sent_at=0.0,
                             sources=[], samples=[], events=events))
    return keys


def test_restart_with_1200_rows_delivers_each_once(tmp_path):
    path = make_db(tmp_path)
    conn = sqlite3.connect(path)
    conn.executemany("INSERT INTO mc_event (timestamp, err_count, err_type, err_msg, label, mc) "
                     "VALUES (?, 1, 'Corrected', 'x', 'D', 0)",
                     [(f"2026-10-02 12:{i // 60:02d}:{i % 60:02d} +0000",) for i in range(1200)])
    conn.commit()
    conn.close()
    out = tmp_path / "outbox.db"
    ob = Outbox(out)
    _, first = RasdaemonReader(path, markers=ob).read()
    assert len(first) == 500
    ob.enqueue(Batch(agent_version="t", host="h", platform="x86", sent_at=0.0,
                     sources=[], samples=[], events=first))
    ob.close()
    ob = Outbox(out)  # restart: new process, same durable file
    rest = drain(path, ob)
    keys = [e.dedup_key for e in first] + rest
    assert len(keys) == 1200 and len(set(keys)) == 1200
    ob.close()


def test_recreated_database_with_reused_ids_gives_new_events(tmp_path):
    path = make_db(tmp_path)
    for _ in range(3):
        add_mc(path, ts="2026-10-02 12:00:00 +0000")
    ob = Outbox(tmp_path / "outbox.db")
    old = drain(path, ob)
    assert len(old) == 3
    path.unlink()
    make_db(tmp_path)
    add_mc(path, ts="2026-10-03 08:00:00 +0000")
    _, events = RasdaemonReader(path, markers=ob).read()
    (ev,) = events
    assert ev.detail["database_recreated"] is True
    assert ev.dedup_key not in old
    ob.close()


def test_naive_timestamp_is_flagged_and_ignores_tz(tmp_path, monkeypatch):
    if not hasattr(time, "tzset"):
        pytest.skip("tzset is not available on this platform")
    path = make_db(tmp_path)
    add_mc(path, ts="2026-10-02 12:00:00")
    results = []
    for tz in ("UTC", "America/New_York", "Asia/Tokyo"):
        monkeypatch.setenv("TZ", tz)
        time.tzset()
        _, (ev,) = RasdaemonReader(path).read()
        results.append(ev.ts)
        assert ev.detail["ts_uncertain"] is True
    assert results == [1790942400.0] * 3


def test_naive_timestamp_is_utc_and_flagged(tmp_path):
    path = make_db(tmp_path)
    add_mc(path, ts="2026-10-02 12:00:00")
    add_mc(path, ts="2026-10-02 12:00:00 -0500")
    _, (naive, explicit) = RasdaemonReader(path).read()
    assert naive.ts == pytest.approx(1790942400.0) and naive.detail["ts_uncertain"] is True
    assert explicit.ts == pytest.approx(1790942400.0 + 5 * 3600)
    assert "ts_uncertain" not in explicit.detail
