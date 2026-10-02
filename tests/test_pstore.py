"""pstore ingestion tests on fake trees."""

from __future__ import annotations

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
