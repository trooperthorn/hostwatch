"""Journal watcher tests with a fake reader that yields JSON lines."""

from __future__ import annotations

import json
import subprocess
import threading
import time

import pytest

from hostwatch.events import journal
from hostwatch.events.journal import BackgroundJournal, JournalWatcher, ReaderError


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
    (jdir / "system.journal").write_bytes(b"x")
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


def completed(cmd, out="", err="", code=0):
    return subprocess.CompletedProcess(cmd, code, stdout=out, stderr=err)


def test_exit_zero_with_permission_stderr_is_unavailable(monkeypatch, dirs):
    jdir, data = dirs
    monkeypatch.setattr(journal.shutil, "which", lambda name: "/usr/bin/journalctl")
    monkeypatch.setattr(journal.subprocess, "run", lambda cmd, **kw: completed(
        cmd, err="Failed to open journal file: Permission denied"))
    status, events = JournalWatcher(jdir, data).read()
    assert not status.available and "Permission denied" in status.reason and events == []


def test_no_entries_notice_is_not_an_error(monkeypatch, dirs):
    jdir, data = dirs
    monkeypatch.setattr(journal.shutil, "which", lambda name: "/usr/bin/journalctl")
    monkeypatch.setattr(journal.subprocess, "run", lambda cmd, **kw: completed(cmd, err="-- No entries --"))
    status, events = JournalWatcher(jdir, data).read()
    assert status.available and events == []


def test_first_read_is_bounded_to_two_boots(monkeypatch, tmp_path):
    cmds = []
    monkeypatch.setattr(journal.shutil, "which", lambda name: "/usr/bin/journalctl")

    def fake_run(cmd, **kw):
        cmds.append(cmd[1:])
        if "--boot=-1" in cmd:
            return completed(cmd, err="No journal boot entry found", code=1)  # single-boot journal
        return completed(cmd, out='{"a": 1}\n')

    monkeypatch.setattr(journal.subprocess, "run", fake_run)
    assert journal.default_reader(tmp_path, None) == ['{"a": 1}']
    cap = ["-n", str(journal.FIRST_READ_MAX_LINES)]
    base = [f"--directory={tmp_path}", "-o", "json", "--no-pager"]
    assert cmds == [[*base, "--boot=0", *cap], [*base, "--boot=-1", *cap]]


def test_directory_without_journal_files_is_unavailable(tmp_path):
    jdir = tmp_path / "journal"
    jdir.mkdir()
    (jdir / "notes.txt").write_text("x")
    status, events = JournalWatcher(jdir, tmp_path, FakeReader([entry(1, "ata3: hard resetting link")])).read()
    assert not status.available and "no readable journal files" in status.reason and events == []


def test_volatile_is_used_when_persistent_is_empty(tmp_path):
    persistent, volatile = tmp_path / "p", tmp_path / "v"
    persistent.mkdir()
    volatile.mkdir()
    (volatile / "system.journal").write_bytes(b"x")
    used = []

    def reader(directory, cursor):
        used.append(directory)
        return [json.dumps(entry(1, "ata3: hard resetting link"))]

    status, events = JournalWatcher(persistent, tmp_path, reader, volatile=volatile).read()
    assert status.available and len(events) == 1 and used == [volatile]


def test_persistent_wins_when_it_has_files(dirs, tmp_path):
    jdir, data = dirs
    volatile = tmp_path / "v"
    volatile.mkdir()
    (volatile / "system.journal").write_bytes(b"x")
    used = []
    JournalWatcher(jdir, data, lambda d, c: used.append(d) or [], volatile=volatile).read()
    assert used == [jdir]


def test_sata_link_up_at_normal_boot_gives_no_event(dirs):
    jdir, data = dirs
    reader = FakeReader([entry(1, "ata1: SATA link up 6.0 Gbps (SStatus 133 SControl 300)")])
    status, events = JournalWatcher(jdir, data, reader).read()
    assert status.available and events == []


def test_sata_link_up_after_reset_on_same_port_counts(dirs):
    jdir, data = dirs
    reader = FakeReader([entry(1, "ata2: hard resetting link"),
                         entry(2, "ata2: SATA link up 3.0 Gbps (SStatus 123 SControl 300)"),
                         entry(3, "ata1: SATA link up 6.0 Gbps (SStatus 133 SControl 300)")])
    _, events = JournalWatcher(jdir, data, reader).read()
    assert [e.dedup_key for e in events] == ["journal:c1", "journal:c2"]


def test_stray_raid_status_line_gives_no_event(dirs):
    jdir, data = dirs
    reader = FakeReader([entry(1, "some tool printed [U_] in a table"),
                         entry(2, "md127: array status [UU]")])
    _, events = JournalWatcher(jdir, data, reader).read()
    assert events == []


def test_md_status_with_context_is_degraded(dirs):
    jdir, data = dirs
    _, events = JournalWatcher(jdir, data, FakeReader([entry(1, "md127: raid1 status [U_]")])).read()
    assert [e.kind for e in events] == ["md.degraded"]


def test_slow_reader_does_not_delay_the_sample_cycle(dirs):
    jdir, data = dirs
    release = threading.Event()
    started = threading.Event()
    inner = FakeReader([entry(1, "ata3: hard resetting link")])

    def slow(directory, cursor):
        started.set()
        assert release.wait(30)
        return inner(directory, cursor)

    bg = BackgroundJournal(JournalWatcher(jdir, data, slow))
    t0 = time.monotonic()
    status, events = bg.read()
    _, none = bg.read()
    assert time.monotonic() - t0 < 1.0
    assert started.wait(5) and events == [] and none == [] and not status.available
    release.set()
    bg._thread.join(5)
    status, events = bg.read()
    assert status.available and [e.dedup_key for e in events] == ["journal:c1"]
    bg._thread.join(5)


def test_background_reader_failure_is_unavailable(dirs):
    jdir, data = dirs

    def failing(directory, cursor):
        raise ReaderError("journalctl is not installed")

    bg = BackgroundJournal(JournalWatcher(jdir, data, failing))
    bg.read()
    bg._thread.join(5)
    status, events = bg.read()
    assert not status.available and status.reason == "journalctl is not installed"
    bg._thread.join(5)


def test_rejected_cursor_resets_emits_event_and_recovers(monkeypatch, dirs):
    jdir, data = dirs
    (data / journal.CURSOR_FILE).write_text("rotated-away")
    monkeypatch.setattr(journal.shutil, "which", lambda name: "/usr/bin/journalctl")
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd[1:])
        if "--after-cursor" in cmd:
            return completed(cmd, err="Failed to seek to cursor: No data available", code=1)
        if "--boot=-1" in cmd:
            return completed(cmd, code=1, err="No journal boot entry found")
        return completed(cmd, out=json.dumps(entry(1, "ata3: hard resetting link")) + "\n")

    monkeypatch.setattr(journal.subprocess, "run", fake_run)
    watcher = JournalWatcher(jdir, data)
    status, events = watcher.read()
    assert status.available
    kinds = [e.kind for e in events]
    assert kinds == ["journal.cursor_reset", "disk.ata_link_reset"]
    assert events[0].detail["rejected_cursor"] == "rotated-away"
    assert watcher.load_cursor() == "c1"
    # The next read uses the new cursor, so no reset is repeated.
    calls.clear()
    monkeypatch.setattr(journal.subprocess, "run", lambda cmd, **kw: completed(cmd))
    status, events = watcher.read()
    assert status.available and events == []


def test_rejected_cursor_with_empty_reread_clears_the_cursor(monkeypatch, dirs):
    jdir, data = dirs
    (data / journal.CURSOR_FILE).write_text("gone")

    def reader(directory, cursor):
        if cursor:
            raise journal.CursorRejected("rejected")
        return []

    watcher = JournalWatcher(jdir, data, reader=reader)
    status, events = watcher.read()
    assert status.available and [e.kind for e in events] == ["journal.cursor_reset"]
    assert watcher.load_cursor() is None
    status, events = watcher.read()
    assert status.available and events == []


def test_capped_first_read_marks_backlog_truncated(monkeypatch, dirs):
    jdir, data = dirs
    monkeypatch.setattr(journal, "FIRST_READ_MAX_LINES", 2)
    monkeypatch.setattr(journal.shutil, "which", lambda name: "/usr/bin/journalctl")
    monkeypatch.setattr(journal.subprocess, "run", lambda cmd, **kw: completed(
        cmd, out='{"a": 1}\n{"a": 2}\n') if "--boot=0" in cmd else completed(cmd, code=1, err="none"))
    status, _ = JournalWatcher(jdir, data).read()
    assert status.available and "journal.backlog_truncated" in status.reason


def test_uncapped_first_read_is_not_marked(monkeypatch, dirs):
    jdir, data = dirs
    status, _ = JournalWatcher(jdir, data, reader=FakeReader([entry(1, "x")])).read()
    assert "backlog_truncated" not in status.reason


def test_partial_unreadable_journal_files_are_named(monkeypatch, dirs):
    jdir, data = dirs
    (jdir / "bad1.journal").write_bytes(b"x")
    real_open = journal.Path.open

    def fake_open(self, *a, **kw):
        if self.name.startswith("bad"):
            raise PermissionError("denied")
        return real_open(self, *a, **kw)

    monkeypatch.setattr(journal.Path, "open", fake_open)
    status, _ = JournalWatcher(jdir, data, reader=FakeReader([entry(1, "x")])).read()
    assert status.available
    assert "bad1.journal" in status.reason and "unreadable" in status.reason
    assert "system.journal" not in status.reason


BOOT_LINES = [
    "mce: CPU0: Thermal monitoring enabled (TM1)",
    "MCE: In-kernel MCE decoding enabled.",
    "mce: [Firmware Bug]: Ignoring request to disable invalid MCA bank 0.",
    "NMI watchdog: Enabled. Permanently consumes one hw-PMU counter.",
    "iTCO_wdt: Intel TCO WatchDog Timer Driver v1.11",
    "iTCO_wdt iTCO_wdt: initialized. heartbeat=30 sec (nowayout=0)",
    "systemd[1]: Using hardware watchdog 'iTCO_wdt', version 0, device /dev/watchdog0",
    "systemd[1]: Watchdog running with a timeout of 30s.",
    "ata1: SATA link up 6.0 Gbps (SStatus 133 SControl 300)",
    "md/raid1:md127: active with 2 out of 2 mirrors",
    "md127: detected capacity change from 0 to 1953382400",
    "md: md127 assembled clean",
]


def test_ordinary_debian_boot_lines_give_no_events(dirs):
    jdir, data = dirs
    reader = FakeReader([entry(i, m) for i, m in enumerate(BOOT_LINES, 1)])
    status, events = JournalWatcher(jdir, data, reader).read()
    assert status.available and events == []


@pytest.mark.parametrize("message,kind", [
    ("watchdog: BUG: soft lockup - CPU#3 stuck for 26s! [kworker/3:1:123]", "watchdog.event"),
    ("NMI watchdog: Watchdog detected hard LOCKUP on cpu 2", "watchdog.event"),
    ("watchdog: watchdog0: watchdog did not stop!", "watchdog.event"),
    ("systemd[1]: Watchdog timeout (limit 3min)!", "watchdog.event"),
    ("mce: [Hardware Error]: CPU 0: Machine Check: 0 Bank 5: be00000000800400", "hardware.mce"),
    ("mce: [Hardware Error]: Machine check events logged", "hardware.mce"),
    ("MCE: Uncorrected error reported on CPU 1", "hardware.mce"),
    ("md/raid1:md127: Operation continuing on 1 devices. degraded", "md.degraded"),
    ("md127: raid1 status [U_]", "md.degraded"),
])
def test_real_error_forms_give_one_event(dirs, message, kind):
    jdir, data = dirs
    _, events = JournalWatcher(jdir, data, FakeReader([entry(1, message)])).read()
    assert [e.kind for e in events] == [kind]
