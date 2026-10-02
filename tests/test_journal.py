"""Journal watcher tests with a fake reader that yields JSON lines."""

from __future__ import annotations

import json
import subprocess

import pytest

from hostwatch.events import journal
from hostwatch.events.journal import JournalWatcher, ReaderError


def entry(n, message, **extra):
    return {"__CURSOR": f"c{n}", "__REALTIME_TIMESTAMP": str(1790942400_000000 + n),
            "MESSAGE": message, "PRIORITY": "3", **extra}


class FakeReader:
    """Serves entries after the given cursor, like journalctl --after-cursor."""

    def __init__(self, entries):
        self.entries = entries
        self.cursors = []

    def __call__(self, directory, cursor):
        self.cursors.append(cursor)
        start = 0
        if cursor:
            start = [e["__CURSOR"] for e in self.entries].index(cursor) + 1
        return [json.dumps(e) for e in self.entries[start:]]


@pytest.fixture
def dirs(tmp_path):
    jdir = tmp_path / "journal"
    jdir.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    return jdir, data


CASES = [
    ("watchdog: watchdog0: watchdog did not stop!", "watchdog.event"),
    ("md/raid1:md127: Disk failure on sdc, disabling device.", "md.degraded"),
    ("md/raid1:md127: Operation continuing on 1 devices. degraded", "md.degraded"),
    ("e1000e 0000:00:19.0 eth0: Detected Hardware Unit Hang", "net.e1000e_hardware_error"),
    ("mce: [Hardware Error]: Machine check events logged", "hardware.mce"),
    ("blk_update_request: I/O error, dev sda, sector 123", "disk.io_error"),
    ("ata3: hard resetting link", "disk.ata_link_reset"),
    ("CPU0: Core temperature above threshold, cpu clock throttled", "thermal.throttle"),
]


@pytest.mark.parametrize("message,kind", CASES)
def test_each_pattern_gives_its_kind(dirs, message, kind):
    jdir, data = dirs
    status, events = JournalWatcher(jdir, data, FakeReader([entry(1, message)])).read()
    assert status.available
    (ev,) = events
    assert ev.kind == kind and ev.source == "journal" and ev.dedup_key == "journal:c1"
    assert ev.ts == pytest.approx(1790942400.000001)


def test_unrelated_lines_give_no_events(dirs):
    jdir, data = dirs
    reader = FakeReader([entry(1, "Started Daily apt download activities."), entry(2, "ok")])
    status, events = JournalWatcher(jdir, data, reader).read()
    assert status.available and events == []
    assert (data / "journal.cursor").read_text() == "c2"


def test_resumed_cursor_causes_no_duplicates(dirs):
    jdir, data = dirs
    entries = [entry(1, "ata3: hard resetting link")]
    reader = FakeReader(entries)
    _, first = JournalWatcher(jdir, data, reader).read()
    assert len(first) == 1
    # A new watcher stands in for a restart; it must resume from the saved cursor.
    _, again = JournalWatcher(jdir, data, reader).read()
    assert again == [] and reader.cursors == [None, "c1"]
    entries.append(entry(2, "blk_update_request: I/O error, dev sdc, sector 9"))
    _, later = JournalWatcher(jdir, data, reader).read()
    assert [e.dedup_key for e in later] == ["journal:c2"]


def test_binary_message_and_bad_lines(dirs):
    jdir, data = dirs
    good = entry(1, list(b"ata1: hard resetting link"))

    def reader(directory, cursor):
        return ["not json", "[1]", json.dumps(good)]

    status, events = JournalWatcher(jdir, data, reader).read()
    assert len(events) == 1 and "2 unreadable" in status.reason


def test_missing_directory_is_unavailable(tmp_path):
    status, events = JournalWatcher(tmp_path / "nope", tmp_path, FakeReader([])).read()
    assert not status.available and "nope" in status.reason and events == []


def test_reader_failure_is_unavailable(dirs):
    jdir, data = dirs

    def reader(directory, cursor):
        raise ReaderError("journalctl is not installed")

    status, events = JournalWatcher(jdir, data, reader).read()
    assert not status.available and status.reason == "journalctl is not installed" and events == []


def test_default_reader_without_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(journal.shutil, "which", lambda name: None)
    with pytest.raises(ReaderError, match="not installed"):
        journal.default_reader(tmp_path, None)


def test_default_reader_command_is_read_only(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(journal.shutil, "which", lambda name: "/usr/bin/journalctl")

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout='{"a": 1}\n', stderr="")

    monkeypatch.setattr(journal.subprocess, "run", fake_run)
    assert journal.default_reader(tmp_path, "c9") == ['{"a": 1}']
    assert seen["cmd"][1:] == [f"--directory={tmp_path}", "-o", "json", "--no-pager", "--after-cursor", "c9"]


def test_default_reader_nonzero_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(journal.shutil, "which", lambda name: "/usr/bin/journalctl")
    monkeypatch.setattr(journal.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom"))
    with pytest.raises(ReaderError, match="exited 1: boom"):
        journal.default_reader(tmp_path, None)
