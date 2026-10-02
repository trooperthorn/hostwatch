"""Boot classifier tests on fake data_dir, procfs and sysfs trees."""

from __future__ import annotations

import dataclasses
import json
import os
import time

from hostwatch.agent import Agent
from hostwatch.config import Config
from hostwatch.events import boot
from hostwatch.events.journal import ReaderError

OLD, NEW = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"


def make_cfg(tmp_path, boot_id=NEW):
    procfs, sysfs, data = tmp_path / "proc", tmp_path / "sys", tmp_path / "data"
    (procfs / "sys/kernel/random").mkdir(parents=True)
    (procfs / "sys/kernel/random/boot_id").write_text(boot_id + "\n")
    sysfs.mkdir()
    data.mkdir()
    return Config(procfs=procfs, sysfs=sysfs, data_dir=data, ingest_token="x" * 32, host_name="h",
                  journal=tmp_path / "journal", journal_volatile=tmp_path / "journal-volatile", pstore=tmp_path / "pstore")


def write_hb(cfg, boot_id=OLD, clean=False, ts=1000.0):
    (cfg.data_dir / boot.HEARTBEAT_FILE).write_text(
        json.dumps({"boot_id": boot_id, "ts": ts, "agent_stopped_cleanly": clean}))


def start(cfg):
    agent = Agent(cfg)
    agent.start_boot_check()
    return agent


def test_same_boot_id_gives_no_event(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg, boot_id=NEW)
    agent = start(cfg)
    assert agent.pending_events == []
    assert boot.classify(boot.load_heartbeat(cfg.data_dir), NEW, None) is None


def test_agent_stop_without_host_shutdown_evidence_is_agent_stopped(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg, clean=True)
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.agent_stopped"
    assert ev.dedup_key == f"boot:{NEW}"
    assert ev.detail["previous_boot_id"] == OLD
    assert ev.detail["agent_stopped_cleanly"] is True


def test_clean_shutdown_requires_host_shutdown_journal_evidence():
    hb = {"boot_id": OLD, "ts": 1000.0, "agent_stopped_cleanly": True}
    assert boot.classify(hb, NEW, None, {"host_shutdown": True}).kind == boot.CLEAN_SHUTDOWN
    assert boot.classify(hb, NEW, None, {}).kind == boot.AGENT_STOPPED
    unclean = {"boot_id": OLD, "ts": 1000.0, "agent_stopped_cleanly": False}
    assert boot.classify(unclean, NEW, None, {"host_shutdown": True}).kind == boot.UNKNOWN


def test_old_flag_name_in_existing_heartbeat_is_still_read(tmp_path):
    cfg = make_cfg(tmp_path)
    (cfg.data_dir / boot.HEARTBEAT_FILE).write_text(
        json.dumps({"boot_id": OLD, "ts": 1000.0, "clean_shutdown": True}))
    assert boot.load_heartbeat(cfg.data_dir)["agent_stopped_cleanly"] is True


def test_stale_heartbeat_with_pstore_gives_kernel_panic(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    (cfg.pstore).mkdir(parents=True)
    (cfg.pstore / "dmesg-efi-1").write_text("Kernel panic")
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.kernel_panic"
    assert ev.detail["pstore_fresh"] == ["dmesg-efi-1"]


def test_stale_pstore_record_is_not_evidence(tmp_path):
    cfg = make_cfg(tmp_path)
    hb_ts = time.time() - 3600
    write_hb(cfg, ts=hb_ts)
    rec = cfg.pstore / "dmesg-efi-0"
    rec.parent.mkdir(parents=True)
    rec.write_text("Kernel panic - not syncing")
    old = hb_ts - 86400
    os.utime(rec, (old, old))
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.unknown"
    assert ev.detail["pstore_stale"] == ["dmesg-efi-0"]
    assert ev.detail["pstore_fresh"] == []


def test_unreadable_pstore_is_reported_unavailable_not_empty(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    (ev,) = start(cfg).pending_events  # no fs/pstore directory at all
    assert ev.kind == "boot.unknown"
    assert "pstore unavailable" in ev.detail["pstore"]


def test_boot_event_has_boot_id_and_ts_of_previous_heartbeat(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg, ts=1234.5)
    (ev,) = start(cfg).pending_events
    assert ev.boot_id == NEW
    assert ev.ts == 1234.5
    assert ev.detail["detected_at"] > 1234.5


def test_heartbeat_failure_then_success_recovers_boot_source(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    agent = start(cfg)
    real = agent.heartbeat._write

    def boom(clean):
        raise OSError("disk full")
    monkeypatch.setattr(agent.heartbeat, "_write", boom)
    agent._beat()
    assert agent.status["boot"].available is False
    monkeypatch.setattr(agent.heartbeat, "_write", real)
    agent._beat()
    assert agent.status["boot"].available is True
    assert agent.status["boot"].reason == ""


def test_empty_pstore_is_not_evidence(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    (cfg.pstore).mkdir(parents=True)
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.unknown"


def test_stale_heartbeat_with_watchdog_hint(tmp_path):
    result = boot.classify({"boot_id": OLD, "ts": 1000.0, "agent_stopped_cleanly": False}, NEW,
                           False, {"watchdog": True}, now=1100.0)
    assert result.kind == boot.WATCHDOG_RESET
    assert result.detail["heartbeat_age_s"] == 100.0
    assert result.detail["journal_hints"] == {"watchdog": True}


def test_stale_heartbeat_without_evidence_is_unknown(tmp_path):
    result = boot.classify({"boot_id": OLD, "ts": 1000.0, "agent_stopped_cleanly": False}, NEW, False, {})
    assert result.kind == boot.UNKNOWN
    assert "cannot be told apart" in result.detail["reason"]


def test_abrupt_journal_end_without_witness_is_unknown_unclean_not_power_loss():
    result = boot.classify({"boot_id": OLD, "ts": 1.0, "agent_stopped_cleanly": False}, NEW, False,
                           {"abrupt_end": True})
    assert result.kind == boot.UNKNOWN_UNCLEAN
    assert not hasattr(boot, "POWER_LOSS")
    assert "without a witness" in result.detail["reason"]


def jline(n, message):
    return json.dumps({"__CURSOR": f"p{n}", "MESSAGE": message})


def with_prev_journal(cfg, agent_lines):
    """Give the agent a readable journal directory and a fake previous-boot reader."""
    cfg.journal.mkdir(parents=True, exist_ok=True)
    (cfg.journal / "system.journal").write_bytes(b"x")
    seen = []

    def reader(directory, boot_id):
        seen.append((directory, boot_id))
        if isinstance(agent_lines, Exception):
            raise agent_lines
        return agent_lines

    agent = Agent(cfg)
    agent.journal_watcher.previous_boot_reader = reader
    agent.prev_dirs = seen
    return agent


def test_previous_boot_journal_with_shutdown_target_gives_clean_shutdown(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg, clean=True)
    agent = with_prev_journal(cfg, [jline(1, "Started foo."), jline(2, "Reached target shutdown.target - System Shutdown."),
                                    jline(3, "systemd-journald[300]: Journal stopped")])
    agent.start_boot_check()
    (ev,) = agent.pending_events
    assert ev.kind == "boot.clean_shutdown"
    assert ev.detail["journal_hints"]["host_shutdown"] is True


def test_bootstatus_cardreset_bit_gives_watchdog_reset(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    bs = cfg.sysfs / "class/watchdog/watchdog0/bootstatus"
    bs.parent.mkdir(parents=True)
    bs.write_text("32\n")
    agent = with_prev_journal(cfg, ReaderError("no previous boot"))
    agent.start_boot_check()
    (ev,) = agent.pending_events
    assert ev.kind == "boot.watchdog_reset"
    assert ev.detail["watchdog_bootstatus"]["card_reset"] is True


def test_bootstatus_zero_is_not_watchdog_evidence(tmp_path):
    cfg = make_cfg(tmp_path)
    bs = cfg.sysfs / "class/watchdog/watchdog0/bootstatus"
    bs.parent.mkdir(parents=True)
    bs.write_text("0\n")
    assert boot.read_bootstatus(cfg.sysfs)["card_reset"] is False
    assert boot.read_bootstatus(tmp_path / "nowhere")["card_reset"] is None


def test_journal_watchdog_message_in_previous_boot_gives_watchdog_reset(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    agent = with_prev_journal(cfg, [jline(1, "watchdog: watchdog0: watchdog did not stop!")])
    agent.start_boot_check()
    assert agent.pending_events[0].kind == "boot.watchdog_reset"


def test_abrupt_end_of_previous_journal_gives_unknown_unclean(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    agent = with_prev_journal(cfg, [jline(1, "Started foo."), jline(2, "eth0: link up")])
    agent.start_boot_check()
    (ev,) = agent.pending_events
    assert ev.kind == "boot.unknown_unclean"
    assert ev.detail["journal_hints"]["abrupt_end"] is True


def test_missing_previous_boot_journal_gives_unknown_with_reason(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    agent = Agent(cfg)  # no journal directory at all
    agent.start_boot_check()
    (ev,) = agent.pending_events
    assert ev.kind == "boot.unknown"
    assert "does not exist" in ev.detail["journal_previous_boot"]
    assert "previous boot journal unavailable" in ev.detail["reason"]


def test_empty_previous_boot_journal_is_unavailable_not_abrupt(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    agent = with_prev_journal(cfg, [])
    agent.start_boot_check()
    (ev,) = agent.pending_events
    assert ev.kind == "boot.unknown"
    assert "no readable entries" in ev.detail["journal_previous_boot"]


def test_default_previous_boot_reader_command_is_read_only(monkeypatch, tmp_path):
    from hostwatch.events import journal
    calls = []
    monkeypatch.setattr(journal.shutil, "which", lambda name: "/usr/bin/journalctl")

    class Done:
        returncode, stdout, stderr = 0, "{}\n", ""
    monkeypatch.setattr(journal.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or Done())
    journal.default_previous_boot_reader(tmp_path, OLD)
    assert calls[0][1:] == [f"--directory={tmp_path}", "-o", "json", "--no-pager",
                            "_BOOT_ID=" + OLD.replace("-", ""), "-n", "200"]
    assert "-b" not in calls[0]


def test_missing_heartbeat_first_run_is_unknown_not_a_guess(tmp_path):
    cfg = make_cfg(tmp_path)
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.unknown"
    assert "no previous heartbeat" in ev.detail["reason"]
    assert boot.classify(None, NEW, True, {"watchdog": True}).kind == boot.UNKNOWN


def test_malformed_heartbeat_is_unknown(tmp_path):
    cfg = make_cfg(tmp_path)
    (cfg.data_dir / boot.HEARTBEAT_FILE).write_text("{not json")
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.unknown"


def test_event_is_emitted_once_and_deduplicated_across_restarts(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg, clean=True)
    agent = start(cfg)
    agent.heartbeat.beat()
    batch = agent.collect_once()
    assert len(batch.events) == 1
    agent.outbox.enqueue(batch)  # the marker is cleared only with the queued batch
    assert agent.collect_once().events == []
    again = start(cfg)  # agent restart inside the same boot
    assert again.pending_events == []


def test_heartbeat_is_atomic_and_clean_flag_sticks(tmp_path):
    cfg = make_cfg(tmp_path)
    hb = boot.Heartbeat(cfg.data_dir, NEW)
    hb.beat()
    assert boot.load_heartbeat(cfg.data_dir)["agent_stopped_cleanly"] is False
    hb.mark_clean()
    hb.beat()
    assert boot.load_heartbeat(cfg.data_dir)["agent_stopped_cleanly"] is True
    assert not (cfg.data_dir / (boot.HEARTBEAT_FILE + ".tmp")).exists()


def test_agent_stop_marks_clean(tmp_path):
    cfg = make_cfg(tmp_path)
    agent = start(cfg)
    agent.heartbeat.beat()
    agent.stop()
    assert boot.load_heartbeat(cfg.data_dir)["agent_stopped_cleanly"] is True


def test_unreadable_boot_id_reports_source_unavailable(tmp_path):
    cfg = make_cfg(tmp_path)
    (cfg.procfs / "sys/kernel/random/boot_id").unlink()
    agent = start(cfg)
    assert agent.status["boot"].available is False
    assert "boot_id" in agent.status["boot"].reason
    assert agent.pending_events == []


def test_boot_event_row_in_hub_store_has_boot_id_and_previous_heartbeat_ts(tmp_path):
    from hostwatch.schema import Batch
    from hostwatch.store import Store
    cfg = make_cfg(tmp_path)
    write_hb(cfg, ts=1234.5)
    (ev,) = start(cfg).pending_events
    store = Store(tmp_path / "hub.db")
    store.ingest_batch(Batch(agent_version="t", host="h", platform="x", sent_at=2000.0,
                             batch_id="b1", sources=[], samples=[], events=[ev]))
    (row,) = store.events(host="h")
    assert row["boot_id"] == NEW
    assert row["ts"] == 1234.5


def test_custom_pstore_root_with_fresh_panic_record_gives_kernel_panic(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg = dataclasses.replace(cfg, pstore=tmp_path / "custom-pstore")
    write_hb(cfg, ts=2000.0)
    hb = json.loads((cfg.data_dir / boot.HEARTBEAT_FILE).read_text())
    hb["first_ts"] = 1000.0
    (cfg.data_dir / boot.HEARTBEAT_FILE).write_text(json.dumps(hb))
    cfg.pstore.mkdir()
    rec = cfg.pstore / "dmesg-efi-7"
    rec.write_text("Kernel panic - not syncing")
    os.utime(rec, (1500.0, 1500.0))
    # The sysfs location must not be consulted.
    (cfg.sysfs / "fs/pstore").mkdir(parents=True)
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.kernel_panic"
    assert ev.detail["pstore_fresh"] == ["dmesg-efi-7"]


def test_previous_boot_journal_uses_heartbeat_boot_id_not_minus_one(tmp_path, monkeypatch):
    from hostwatch.events import journal
    cfg = make_cfg(tmp_path)
    write_hb(cfg, clean=True)
    cfg.journal.mkdir()
    (cfg.journal / "system.journal").write_bytes(b"x")
    other = "cccccccc0000000000000000000000cc"
    # A fake journal in which -b -1 is a different boot than the heartbeat's.
    by_boot = {OLD.replace("-", ""): [jline(1, "Reached target shutdown.target - System Shutdown.")],
               other: [jline(2, "eth0: link up")]}
    monkeypatch.setattr(journal.shutil, "which", lambda name: "/usr/bin/journalctl")

    class Done:
        returncode, stderr = 0, ""

        def __init__(self, out):
            self.stdout = "\n".join(out)

    def run(cmd, **kw):
        assert "-b" not in cmd
        match = [a for a in cmd if a.startswith("_BOOT_ID=")]
        return Done(by_boot.get(match[0].split("=", 1)[1], []))
    monkeypatch.setattr(journal.subprocess, "run", run)
    agent = Agent(cfg)
    agent.start_boot_check()
    (ev,) = agent.pending_events
    assert ev.kind == "boot.clean_shutdown"


def test_previous_boot_missing_from_journal_is_unavailable_with_reason(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    agent = with_prev_journal(cfg, [])
    agent.start_boot_check()
    (ev,) = agent.pending_events
    assert OLD in ev.detail["journal_previous_boot"]
    assert ev.detail["journal_hints"] == {}


def test_invalid_boot_id_is_rejected_before_journalctl(tmp_path):
    import pytest
    from hostwatch.events import journal
    with pytest.raises(ReaderError):
        journal.default_previous_boot_reader(tmp_path, "x; rm -rf /")


def test_pstore_record_older_than_previous_boot_start_is_stale_despite_skew(tmp_path):
    cfg = make_cfg(tmp_path)
    # Short boot: began at 1000, last heartbeat at 1030. The record is from 990,
    # inside the 60 s skew of the last heartbeat but before this boot began.
    (cfg.data_dir / boot.HEARTBEAT_FILE).write_text(
        json.dumps({"boot_id": OLD, "ts": 1030.0, "first_ts": 1000.0, "agent_stopped_cleanly": False}))
    cfg.pstore.mkdir()
    rec = cfg.pstore / "dmesg-efi-0"
    rec.write_text("Kernel panic - not syncing")
    os.utime(rec, (990.0, 990.0))
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.unknown"
    assert ev.detail["pstore_stale"] == ["dmesg-efi-0"]


def test_pstore_record_already_classified_in_earlier_boot_is_stale(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.pstore.mkdir()
    rec = cfg.pstore / "dmesg-efi-0"
    rec.write_text("Kernel panic - not syncing")
    os.utime(rec, (1500.0, 1500.0))
    (cfg.data_dir / boot.HEARTBEAT_FILE).write_text(
        json.dumps({"boot_id": OLD, "ts": 2000.0, "first_ts": 1000.0, "agent_stopped_cleanly": False}))
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.kernel_panic"
    # The next boot sees the same file still present (pstore not cleared).
    mid = "dddddddd-0000-0000-0000-000000000004"
    (cfg.procfs / "sys/kernel/random/boot_id").write_text(mid + "\n")
    (cfg.data_dir / boot.HEARTBEAT_FILE).write_text(
        json.dumps({"boot_id": NEW, "ts": 3000.0, "first_ts": 1400.0, "agent_stopped_cleanly": False}))
    (ev2,) = start(cfg).pending_events[-1:]
    assert ev2.kind == "boot.unknown"
    assert ev2.detail["pstore_stale"] == ["dmesg-efi-0"]
