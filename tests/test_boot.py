"""Boot classifier tests on fake data_dir, procfs and sysfs trees."""

from __future__ import annotations

import json
import os
import time

from hostwatch.agent import Agent
from hostwatch.config import Config
from hostwatch.events import boot

OLD, NEW = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"


def make_cfg(tmp_path, boot_id=NEW):
    procfs, sysfs, data = tmp_path / "proc", tmp_path / "sys", tmp_path / "data"
    (procfs / "sys/kernel/random").mkdir(parents=True)
    (procfs / "sys/kernel/random/boot_id").write_text(boot_id + "\n")
    sysfs.mkdir()
    data.mkdir()
    return Config(procfs=procfs, sysfs=sysfs, data_dir=data, ingest_token="x" * 32, host_name="h")


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
    (cfg.sysfs / "fs/pstore").mkdir(parents=True)
    (cfg.sysfs / "fs/pstore/dmesg-efi-1").write_text("Kernel panic")
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.kernel_panic"
    assert ev.detail["pstore_fresh"] == ["dmesg-efi-1"]


def test_stale_pstore_record_is_not_evidence(tmp_path):
    cfg = make_cfg(tmp_path)
    hb_ts = time.time() - 3600
    write_hb(cfg, ts=hb_ts)
    rec = cfg.sysfs / "fs/pstore/dmesg-efi-0"
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
    (cfg.sysfs / "fs/pstore").mkdir(parents=True)
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


def test_abrupt_journal_end_gives_power_loss():
    result = boot.classify({"boot_id": OLD, "ts": 1.0, "agent_stopped_cleanly": False}, NEW, False,
                           {"abrupt_end": True})
    assert result.kind == boot.POWER_LOSS


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
