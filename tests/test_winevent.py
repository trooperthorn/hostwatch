"""Windows Event Log boot classification and WHEA events, on fake event log records."""

from __future__ import annotations

import json

import pytest

from agent_helpers import drain_logs, event_cycle
from fakes_windows import FakeCimQuery, FakeCommandRunner, FakeEventLogReader, FakePipeStatusReader

from hostwatch.events import boot, winevent
from hostwatch.events.winevent import (PROVIDER_BUGCHECK, PROVIDER_EVENTLOG, PROVIDER_POWER, PROVIDER_WHEA,
                                       WinEventReader, classify_windows_boot)
from hostwatch.model import Event
from hostwatch.windows import WindowsSeam

T0 = 1_790_000_000.0
NOW = T0 + 10_000.0
_record = [0]


def rec(eid, provider, t, message="", level=2):
    _record[0] += 1
    return {"id": eid, "record": _record[0], "provider": provider, "level": level, "time": t, "message": message}


def kp41(t):
    return rec(41, PROVIDER_POWER, t, "The system has rebooted without cleanly shutting down first.", 1)


def el6008(t):
    return rec(6008, PROVIDER_EVENTLOG, t, "The previous system shutdown was unexpected.")


def el6006(t):
    return rec(6006, PROVIDER_EVENTLOG, t, "The Event log service was stopped.", 4)


def bc1001(t):
    return rec(1001, PROVIDER_BUGCHECK, t, "The computer has rebooted from a bugcheck. 0x0000009f", 2)


def whea(eid, t, message, level=3):
    return rec(eid, PROVIDER_WHEA, t, message, level)


def seam_for(logs):
    return WindowsSeam(events=FakeEventLogReader({"System": logs}), cim=FakeCimQuery({}),
                       pipe=FakePipeStatusReader({}), runner=FakeCommandRunner())


def reader(tmp_path, logs, now=NOW):
    return WinEventReader(seam_for(logs), tmp_path, clock=lambda: now)


def test_clean_shutdown_is_classified_clean():
    c = classify_windows_boot([el6006(T0)], NOW)
    assert c.kind == boot.CLEAN_SHUTDOWN and c.detail["boot_id"] == f"win-{int(T0)}"


def test_bugcheck_after_kernel_power_41_is_a_panic():
    c = classify_windows_boot([kp41(T0), bc1001(T0 + 120)], NOW)
    assert c.kind == boot.KERNEL_PANIC and "0x0000009f" in c.detail["bugcheck_message"]


def test_6008_alone_is_unknown_unclean_never_power_loss():
    c = classify_windows_boot([el6008(T0)], NOW)
    assert c.kind == boot.UNKNOWN_UNCLEAN and "power cut and a hang" in c.detail["reason"]


def test_conflicting_clean_record_is_noted():
    c = classify_windows_boot([el6006(T0), kp41(T0 + 5)], NOW)
    assert c.kind == boot.UNKNOWN_UNCLEAN and "6006" in c.detail["contradiction"]


def test_reader_emits_boot_events_through_boot_event(tmp_path):
    status, events = reader(tmp_path, [kp41(T0), el6008(T0 + 2), bc1001(T0 + 60)]).read()
    assert status.available
    (ev,) = events
    assert isinstance(ev, Event) and ev.kind == "boot.kernel_panic" and ev.severity == "critical"
    assert ev.source == "boot" and ev.dedup_key == f"boot:win-{int(T0)}" and ev.ts == T0


def test_group_is_held_back_until_it_has_settled(tmp_path):
    recent = NOW - 60
    r = reader(tmp_path, [kp41(recent)])
    _, events = r.read()
    assert events == []
    assert winevent.load_bookmark(tmp_path / "winevent") == recent
    r.clock = lambda: NOW + winevent.SETTLE_S
    _, later = r.read()
    assert [e.kind for e in later] == ["boot.unknown_unclean"]


def test_separate_shutdowns_are_separate_events(tmp_path):
    _, events = reader(tmp_path, [el6006(T0), kp41(T0 + 5000)]).read()
    assert [e.kind for e in events] == ["boot.clean_shutdown", "boot.unknown_unclean"]


def test_whea_corrected_and_fatal_match_the_rasdaemon_shape(tmp_path):
    logs = [whea(19, T0, "A corrected hardware error has occurred."),
            whea(18, T0 + 1, "A fatal hardware error has occurred.", 1)]
    _, events = reader(tmp_path, logs).read()
    corrected, fatal = events
    for ev in events:
        assert ev.kind == "hardware_error" and ev.source == "winevent"
        assert {"table", "err_type", "err_msg"} <= set(ev.detail)
    assert (corrected.severity, corrected.detail["err_type"]) == ("warning", "Corrected")
    assert (fatal.severity, fatal.detail["err_type"]) == ("critical", "Fatal")
    assert corrected.dedup_key != fatal.dedup_key


def test_other_providers_with_the_same_ids_are_ignored(tmp_path):
    logs = [rec(1, "SomethingElse", T0, "x"), rec(41, "SomethingElse", T0, "x")]
    status, events = reader(tmp_path, logs).read()
    assert status.available and events == []


def test_no_duplicates_after_restart(tmp_path):
    logs = [kp41(T0), whea(19, T0 + 3, "A corrected hardware error has occurred.")]
    _, first = reader(tmp_path, logs).read()
    assert len(first) == 2
    _, second = reader(tmp_path, logs).read()
    assert second == []
    assert boot.load_classified(tmp_path / "winevent")


def test_bookmark_is_persisted_and_used_as_since(tmp_path):
    logs = [el6006(T0)]
    r = reader(tmp_path, logs)
    r.read()
    r2 = reader(tmp_path, logs)
    r2.read()
    assert r2.seam.events.calls[-1][2] == T0
    assert r.seam.events.calls[0][2] == NOW - winevent.FIRST_RUN_LOOKBACK_S
    assert json.loads((tmp_path / "winevent" / winevent.BOOKMARK_FILE).read_text())["ts"] == T0


def test_unreadable_log_is_unavailable_with_a_reason(tmp_path):
    seam = WindowsSeam(events=FakeEventLogReader({}), cim=FakeCimQuery({}),
                       pipe=FakePipeStatusReader({}), runner=FakeCommandRunner())
    status, events = WinEventReader(seam, tmp_path, clock=lambda: NOW).read()
    assert not status.available and "cannot read the System event log" in status.reason and events == []
    assert winevent.load_bookmark(tmp_path / "winevent") is None


def test_malformed_records_are_skipped_and_reported(tmp_path):
    logs = [{"id": 41, "provider": PROVIDER_POWER, "time": float("inf")}, el6006(T0)]
    status, events = reader(tmp_path, logs).read()
    assert status.available and "1 record(s) skipped" in status.reason and len(events) == 1


def test_script_asks_for_the_record_id():
    from hostwatch.windows import event_log_script
    assert "record=$_.RecordId" in event_log_script("System", [41], None, 5)


def test_module_imports_no_windows_only_modules():
    import ast
    from pathlib import Path
    tree = ast.parse(Path(winevent.__file__).read_text(encoding="utf-8"))
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not names & {"win32evtlog", "win32api", "winreg", "ctypes", "pywintypes"}


def _agent_with_reader(tmp_path, logs, clock):
    import sqlite3  # noqa: F401
    from test_outbox import make_cfg

    from hostwatch.agent import Agent
    agent = Agent(make_cfg(tmp_path))
    r = WinEventReader(seam_for(logs), tmp_path / "data", clock=clock, markers=agent.outbox)
    agent.event_sources = {"winevent": r.read}
    return agent, r


def test_failed_send_then_retry_re_emits_the_same_events_once(tmp_path):
    import sqlite3
    logs = [whea(19, T0 + i, "A corrected hardware error has occurred.") for i in range(3)]
    agent, _ = _agent_with_reader(tmp_path, logs, lambda: NOW)
    real = agent.outbox.enqueue
    agent.outbox.enqueue = lambda *a: (_ for _ in ()).throw(sqlite3.OperationalError("disk full"))
    assert event_cycle(agent) is False
    assert winevent.load_bookmark(tmp_path / "data" / "winevent") is None
    agent.outbox.enqueue = real
    assert event_cycle(agent) is True
    first = drain_logs(agent)
    assert len([e for e in first if e["source"] == "winevent"]) == 3
    assert event_cycle(agent) is True
    assert [e for e in drain_logs(agent) if e["source"] == "winevent"] == []


def test_1200_events_are_all_delivered_across_cycles_in_order(tmp_path):
    logs = [whea(19, T0 + i, "A corrected hardware error has occurred.") for i in range(1200)]
    agent, _ = _agent_with_reader(tmp_path, logs, lambda: NOW)
    got = []
    for _ in range(6):
        assert event_cycle(agent) is True
        got.extend(e for e in drain_logs(agent) if e["source"] == "winevent")
    assert [e["ts"] for e in got] == pytest.approx([T0 + i for i in range(1200)])
    assert len({e["dedup_key"] for e in got}) == 1200


def test_capped_read_in_the_reader_alone_advances_only_to_the_newest_returned(tmp_path):
    logs = [whea(19, T0 + i, "A corrected hardware error has occurred.") for i in range(700)]
    r = reader(tmp_path, logs)
    _, first = r.read()
    assert len(first) == winevent.MAX_EVENTS
    assert winevent.load_bookmark(tmp_path / "winevent") == T0 + winevent.MAX_EVENTS - 1
    _, second = r.read()
    assert [e.ts for e in second] == [T0 + i for i in range(winevent.MAX_EVENTS, 700)]


@pytest.mark.parametrize("bad", [NOW + 10 * 86400, float("nan"), float("inf"), 1e300, -5.0, 0])
def test_corrupt_bookmark_recovers_with_a_lookback(tmp_path, bad, caplog):
    import logging
    state = tmp_path / "winevent"
    state.mkdir()
    (state / winevent.BOOKMARK_FILE).write_text(json.dumps({"log": "System", "ts": bad}), encoding="utf-8")
    r = reader(tmp_path, [whea(19, T0, "A corrected hardware error has occurred.")])
    with caplog.at_level(logging.WARNING, logger="hostwatch.events.winevent"):
        status, events = r.read()
        r.read()
    assert status.available and len(events) == 1
    assert r.seam.events.calls[0][2] == NOW - winevent.FIRST_RUN_LOOKBACK_S
    assert len([x for x in caplog.records if "bookmark" in x.getMessage()]) == 1
    assert winevent.load_bookmark(state) == T0


def test_clean_shutdown_then_bugcheck_600s_later_are_two_events(tmp_path):
    _, events = reader(tmp_path, [el6006(T0), kp41(T0 + 600), bc1001(T0 + 620)]).read()
    assert [e.kind for e in events] == ["boot.clean_shutdown", "boot.kernel_panic"]
