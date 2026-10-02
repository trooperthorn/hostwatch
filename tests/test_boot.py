"""Boot classifier tests on fake data_dir, procfs and sysfs trees."""

from __future__ import annotations

import json

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
        json.dumps({"boot_id": boot_id, "ts": ts, "clean_shutdown": clean}))


def start(cfg):
    agent = Agent(cfg)
    agent.start_boot_check()
    return agent


def test_same_boot_id_gives_no_event(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg, boot_id=NEW)
    agent = start(cfg)
    assert agent.pending_events == []
    assert boot.classify(boot.load_heartbeat(cfg.data_dir), NEW, False) is None


def test_clean_flag_gives_clean_shutdown(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg, clean=True)
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.clean_shutdown"
    assert ev.dedup_key == f"boot:{NEW}"
    assert ev.detail["previous_boot_id"] == OLD


def test_stale_heartbeat_with_pstore_gives_kernel_panic(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    (cfg.sysfs / "fs/pstore").mkdir(parents=True)
    (cfg.sysfs / "fs/pstore/dmesg-efi-1").write_text("Kernel panic")
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.kernel_panic"
    assert ev.detail["pstore_present"] is True


def test_empty_pstore_is_not_evidence(tmp_path):
    cfg = make_cfg(tmp_path)
    write_hb(cfg)
    (cfg.sysfs / "fs/pstore").mkdir(parents=True)
    (ev,) = start(cfg).pending_events
    assert ev.kind == "boot.unknown"


def test_stale_heartbeat_with_watchdog_hint(tmp_path):
    result = boot.classify({"boot_id": OLD, "ts": 1000.0, "clean_shutdown": False}, NEW,
                           False, {"watchdog": True}, now=1100.0)
    assert result.kind == boot.WATCHDOG_RESET
    assert result.detail["heartbeat_age_s"] == 100.0
    assert result.detail["journal_hints"] == {"watchdog": True}


def test_stale_heartbeat_without_evidence_is_unknown(tmp_path):
    result = boot.classify({"boot_id": OLD, "ts": 1000.0, "clean_shutdown": False}, NEW, False, {})
    assert result.kind == boot.UNKNOWN
    assert "cannot be told apart" in result.detail["reason"]


def test_abrupt_journal_end_gives_power_loss():
    result = boot.classify({"boot_id": OLD, "ts": 1.0, "clean_shutdown": False}, NEW, False,
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
    assert len(agent.collect_once().events) == 1
    assert agent.collect_once().events == []
    again = start(cfg)  # agent restart inside the same boot
    assert again.pending_events == []


def test_heartbeat_is_atomic_and_clean_flag_sticks(tmp_path):
    cfg = make_cfg(tmp_path)
    hb = boot.Heartbeat(cfg.data_dir, NEW)
    hb.beat()
    assert boot.load_heartbeat(cfg.data_dir)["clean_shutdown"] is False
    hb.mark_clean()
    hb.beat()
    assert boot.load_heartbeat(cfg.data_dir)["clean_shutdown"] is True
    assert not (cfg.data_dir / (boot.HEARTBEAT_FILE + ".tmp")).exists()


def test_agent_stop_marks_clean(tmp_path):
    cfg = make_cfg(tmp_path)
    agent = start(cfg)
    agent.heartbeat.beat()
    agent.stop()
    assert boot.load_heartbeat(cfg.data_dir)["clean_shutdown"] is True


def test_unreadable_boot_id_reports_source_unavailable(tmp_path):
    cfg = make_cfg(tmp_path)
    (cfg.procfs / "sys/kernel/random/boot_id").unlink()
    agent = start(cfg)
    assert agent.status["boot"].available is False
    assert "boot_id" in agent.status["boot"].reason
    assert agent.pending_events == []
