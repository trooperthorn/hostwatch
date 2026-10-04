"""Phase 8 exit criteria for the Windows event log source, mirroring the Phase 2 boot scenarios with
event fixtures: clean shutdown, BugCheck after 41, 6008 power loss or hang, WHEA corrected and fatal,
no duplicate after a restart, and unavailable when the log cannot be read."""

from __future__ import annotations

import time

from fakes_windows import FakeCimQuery, FakeCommandRunner, FakeEventLogReader, FakePipeStatusReader
from test_winevent import NOW, T0, bc1001, el6006, el6008, kp41, reader, whea

from hostwatch.events.winevent import WinEventReader
from hostwatch.schema import Batch
from hostwatch.windows import WindowsSeam


def kinds(tmp_path, logs):
    return [(e.kind, e.severity) for e in reader(tmp_path, logs).read()[1]]


def test_clean_shutdown(tmp_path):
    assert kinds(tmp_path, [el6006(T0)]) == [("boot.clean_shutdown", "info")]


def test_bugcheck_after_kernel_power_41(tmp_path):
    assert kinds(tmp_path, [kp41(T0), bc1001(T0 + 90)]) == [("boot.kernel_panic", "critical")]


def test_6008_power_loss_or_hang_is_unknown_unclean(tmp_path):
    (ev,) = reader(tmp_path, [el6008(T0), kp41(T0 + 1)]).read()[1]
    assert ev.kind == "boot.unknown_unclean" and "hang" in ev.detail["reason"]


def test_whea_corrected_and_fatal(tmp_path):
    logs = [whea(19, T0, "A corrected hardware error has occurred."),
            whea(18, T0 + 1, "A fatal hardware error has occurred.", 1)]
    assert kinds(tmp_path, logs) == [("hardware_error", "warning"), ("hardware_error", "critical")]


def test_no_duplicates_after_restart(tmp_path):
    logs = [kp41(T0), bc1001(T0 + 30), whea(19, T0 + 40, "A corrected hardware error has occurred.")]
    assert len(reader(tmp_path, logs).read()[1]) == 2
    assert reader(tmp_path, logs).read()[1] == []


def test_events_are_accepted_by_the_wire_schema(tmp_path):
    events = reader(tmp_path, [kp41(T0)]).read()[1]
    batch = Batch(agent_version="t", host="win-host", platform="windows", sent_at=time.time(), sources=[],
                  samples=[], events=events)
    assert Batch.model_validate_json(batch.model_dump_json()).events[0].kind == "boot.unknown_unclean"


def test_unavailable_when_the_log_cannot_be_read(tmp_path):
    seam = WindowsSeam(events=FakeEventLogReader({}), cim=FakeCimQuery({}), pipe=FakePipeStatusReader({}),
                       runner=FakeCommandRunner())
    status, events = WinEventReader(seam, tmp_path, clock=lambda: NOW).read()
    assert status.available is False and status.reason and events == []
