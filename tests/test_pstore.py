"""pstore ingestion tests on fake trees."""

from __future__ import annotations

import os
import stat

import pytest

import hostwatch.events.pstore as pstore_mod
from hostwatch.config import Config
from hostwatch.events.pstore import OOPS, PANIC, RECORD, read_pstore


def snapshot(root):
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}


def make_tree(tmp_path):
    root = tmp_path / "pstore"
    root.mkdir()
    (root / "dmesg-efi-1700000000001").write_text("Panic#1 Part1\nKernel panic - not syncing: test\n")
    return root


def test_panic_record_gives_one_event_and_no_duplicate(tmp_path):
    root = make_tree(tmp_path)
    status, first = read_pstore(root)
    assert status.available
    (ev,) = first
    assert ev.kind == PANIC and ev.severity == "critical" and ev.source == "pstore"
    _, second = read_pstore(root)
    assert [e.dedup_key for e in second] == [ev.dedup_key]


def test_changed_content_changes_dedup_key(tmp_path):
    root = make_tree(tmp_path)
    (_, (a,)) = read_pstore(root)
    (root / "dmesg-efi-1700000000001").write_text("Panic#2 Part1\nKernel panic again\n")
    (_, (b,)) = read_pstore(root)
    assert a.dedup_key != b.dedup_key


def test_oops_and_other_records(tmp_path):
    root = tmp_path / "pstore"
    root.mkdir()
    (root / "dmesg-efi-1").write_text("Oops#1 Part1\nOops: 0002\n")
    (root / "console-ramoops-0").write_text("boot log")
    _, events = read_pstore(root)
    assert sorted(e.kind for e in events) == sorted([OOPS, RECORD])


def test_empty_directory_is_available_without_events(tmp_path):
    root = tmp_path / "pstore"
    root.mkdir()
    status, events = read_pstore(root)
    assert status.available and events == []


def test_missing_directory_is_unavailable_with_reason(tmp_path):
    status, events = read_pstore(tmp_path / "absent")
    assert not status.available and "does not exist" in status.reason and events == []


def test_source_files_are_unchanged(tmp_path):
    root = make_tree(tmp_path)
    before = snapshot(root)
    read_pstore(root)
    read_pstore(root)
    assert snapshot(root) == before


def test_config_default_path(monkeypatch):
    monkeypatch.delenv("HOSTWATCH_PSTORE", raising=False)
    assert Config().pstore.as_posix().endswith("host/pstore")
    monkeypatch.setenv("HOSTWATCH_PSTORE", "/x/p")
    assert Config().pstore.as_posix() == "/x/p"


def test_all_unreadable_is_unavailable(tmp_path, monkeypatch):
    root = make_tree(tmp_path)

    def deny(path):
        raise PermissionError("denied")
    monkeypatch.setattr(pstore_mod, "_read_file", deny)
    status, events = read_pstore(root)
    assert not status.available and "could not be read" in status.reason and events == []


def test_partially_unreadable_reports_count(tmp_path, monkeypatch):
    root = make_tree(tmp_path)
    (root / "dmesg-efi-2").write_text("Oops#1 Part1\n")
    real = pstore_mod._read_file

    def flaky(path):
        if path.name == "dmesg-efi-2":
            raise PermissionError("denied")
        return real(path)
    monkeypatch.setattr(pstore_mod, "_read_file", flaky)
    status, events = read_pstore(root)
    assert status.available and "1 record file(s)" in status.reason and len(events) == 1


def test_harmless_words_are_not_oops(tmp_path):
    root = tmp_path / "pstore"
    root.mkdir()
    (root / "dmesg-efi-1").write_text("oopsie happened\nmodule bugfix loaded\nno bug: here\n")
    _, (ev,) = read_pstore(root)
    assert ev.kind == RECORD and ev.severity == "warning"


def test_large_file_tail_panic_and_whole_content_key(tmp_path):
    root = tmp_path / "pstore"
    root.mkdir()
    f = root / "dmesg-efi-1"
    body = b"x" * (1024 * 1024 + 4096)
    f.write_bytes(body + b"\nKernel panic - not syncing: boom\n")
    _, (a,) = read_pstore(root)
    assert a.kind == PANIC and a.detail["truncated"] is True
    f.write_bytes(body + b"\nKernel panic - not syncing: bang\n")
    _, (b,) = read_pstore(root)
    assert a.dedup_key != b.dedup_key


def test_symlink_is_skipped(tmp_path):
    root = tmp_path / "pstore"
    root.mkdir()
    target = tmp_path / "outside"
    target.write_text("Kernel panic - not syncing\n")
    try:
        os.symlink(target, root / "dmesg-efi-1")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")
    status, events = read_pstore(root)
    assert status.available and events == []


def test_symlink_mode_is_skipped_without_real_link(tmp_path, monkeypatch):
    root = make_tree(tmp_path)
    real = type(root).lstat

    def fake_lstat(self, *args, **kwargs):
        st = real(self, *args, **kwargs)
        if self.name.startswith("dmesg-"):
            return os.stat_result((stat.S_IFLNK | 0o777,) + tuple(st)[1:])
        return st
    monkeypatch.setattr(type(root), "lstat", fake_lstat)
    status, events = read_pstore(root)
    assert status.available and events == []
