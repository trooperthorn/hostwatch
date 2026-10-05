"""hostwatch-control Windows executors, tested with a fake pipe client and a fake command runner."""

from __future__ import annotations

import io
import struct

import pytest

from hostwatch.control import actions_windows as aw
from hostwatch.control import config as cfgmod
from hostwatch.windows import CommandResult, SeamError

KEY = "ed25519:" + "A" * 43 + "="
RAW = {"observe_public_key": KEY, "host": "MediaIn-SVR",
       "fan": {"controller": "thermal-control-suite", "headers": ["fan1"], "allow_mode_change": True},
       "services": {"restart": ["hostwatch-agent", "Spooler"]},
       "reboot": {"allow": True, "delay_s": 90}}
FAN = {"Id": "fan1", "ControlSensorId": "/lpc/nct/control/0", "RpmSensorId": "/lpc/nct/fan/0",
       "Enabled": True, "ZoneIds": ["cpu"], "MinDutyPercent": 20.0, "MinRpm": 300.0}


def config(**over):
    return cfgmod.parse({**RAW, **over})


class FakePipe:
    def __init__(self, replies):
        self.calls, self.replies = [], list(replies)

    def request(self, pipe_name, payload, timeout_s=None):
        self.calls.append((pipe_name, payload))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class FakeRunner:
    def __init__(self, results=None):
        self.calls, self.results = [], list(results or [])

    def run(self, args, timeout_s):
        assert isinstance(args, list) and all(isinstance(a, str) for a in args)
        self.calls.append(list(args))
        return self.results.pop(0) if self.results else CommandResult(0, "ok")


def actions(pipe=None, runner=None, cfg=None):
    return aw.WindowsActions(cfg or config(), runner or FakeRunner(), pipe or FakePipe([]))


def test_set_floor_sends_get_fans_then_set_fan_mapping():
    pipe = FakePipe([{"Success": True, "Fans": [FAN]}, {"Success": True, "Persisted": True}])
    result = actions(pipe).execute({"action": "fan.set_floor", "params": {"header": "fan1", "min_duty": 35}})
    assert result.ok and result.status == "done"
    assert pipe.calls[0] == (aw.PIPE_NAME, {"Type": "GetFans"})
    assert pipe.calls[1] == (aw.PIPE_NAME, {"Type": "SetFanMapping", "FanId": "fan1", "Mapping": {
        "ZoneIds": ["cpu"], "ControlSensorId": "/lpc/nct/control/0", "RpmSensorId": "/lpc/nct/fan/0",
        "MinDutyPercent": 35.0, "MinRpm": 300.0}})


def test_set_floor_reports_an_ipc_refusal():
    pipe = FakePipe([{"Success": True, "Fans": [FAN]}, {"Success": False, "Error": "Caller is not authorized"}])
    result = actions(pipe).fan_set_floor("fan1", 35)
    assert not result.ok and result.status == "refused" and "not authorized" in result.output


def test_set_floor_reports_a_get_fans_refusal_and_stops():
    pipe = FakePipe([{"Success": False, "Error": "nope"}])
    result = actions(pipe).fan_set_floor("fan1", 35)
    assert result.status == "refused" and len(pipe.calls) == 1


def test_set_floor_reports_a_missing_pipe_and_an_unknown_fan():
    missing = FakePipe([SeamError("pipe ThermalControlSuite.Ipc does not exist")])
    assert actions(missing).fan_set_floor("fan1", 5).status == "failed"
    result = actions(FakePipe([{"Success": True, "Fans": [FAN]}])).fan_set_floor("fan9", 5)
    assert result.status == "failed" and "no fan" in result.output


def test_set_floor_notes_an_unsaved_change():
    pipe = FakePipe([{"Success": True, "Fans": [FAN]}, {"Success": True, "Persisted": False, "Warning": "disk full"}])
    result = actions(pipe).fan_set_floor("fan1", 35)
    assert result.ok and "not saved" in result.output and "disk full" in result.output


@pytest.mark.parametrize("header,duty", [("fan 1", 10), ("-x", 10), ("", 10), (None, 10), ("fan1", -1),
                                         ("fan1", 101), ("fan1", True), ("fan1", 5.5), ("fan1", "5")])
def test_set_floor_rejects_bad_parameters_before_any_call(header, duty):
    pipe = FakePipe([])
    result = actions(pipe).fan_set_floor(header, duty)
    assert result.status == "refused" and pipe.calls == []


def test_fan_actions_refuse_when_the_suite_is_not_the_configured_controller():
    cfg = config(fan={"controller": "thermalctl", "headers": ["pwm1"]})
    pipe = FakePipe([])
    assert actions(pipe, cfg=cfg).fan_set_floor("fan1", 10).status == "refused"
    assert actions(pipe, cfg=cfg).fan_set_mode("active").status == "refused"
    assert pipe.calls == []


def test_set_mode_is_refused_because_the_pipe_cannot_change_dry_run():
    pipe = FakePipe([])
    result = actions(pipe).execute({"action": "fan.set_mode", "params": {"mode": "active"}})
    assert result.status == "refused" and "dry run" in result.output and pipe.calls == []
    assert actions(pipe).fan_set_mode("fast").output == "mode must be dry_run or active"


def test_restart_service_uses_a_fixed_script_and_the_name_as_an_argument():
    runner = FakeRunner()
    result = actions(runner=runner).execute({"action": "service.restart", "params": {"name": "Spooler"}})
    assert result.ok and result.status == "done"
    assert runner.calls == [["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                             "-Command", aw.RESTART_SCRIPT, "Spooler"]]
    assert "Spooler" not in aw.RESTART_SCRIPT and "$Name" in aw.RESTART_SCRIPT


def test_restart_failure_and_runner_error_are_reported():
    runner = FakeRunner([CommandResult(1, "", "Cannot find any service")])
    assert actions(runner=runner).service_restart("Spooler").status == "failed"

    class Broken:
        def run(self, args, timeout_s):
            raise SeamError("powershell.exe timed out after 120 seconds")

    result = aw.WindowsActions(config(), Broken(), FakePipe([])).service_restart("Spooler")
    assert result.status == "failed" and "timed out" in result.output


@pytest.mark.parametrize("name", ["Spooler; Remove-Item C:\\", "Spooler'; calc", "$(calc)", "-Force", "a b",
                                  "Spooler\n", "..\\x", "a..b", "docker:Spooler", "svc@1", "", None, 5,
                                  "a" * 129, "`calc`", "x|y"])
def test_malicious_service_names_are_rejected_before_any_run(name):
    runner = FakeRunner()
    result = actions(runner=runner).service_restart(name)
    assert result.status == "refused" and runner.calls == []


def test_a_valid_name_that_is_not_in_the_local_list_is_refused():
    runner = FakeRunner()
    assert actions(runner=runner).service_restart("W32Time").status == "refused" and runner.calls == []


def test_reboot_and_cancel_argv():
    runner = FakeRunner()
    act = actions(runner=runner)
    result = act.execute({"action": "host.reboot", "params": {}})
    assert result.ok and result.status == "scheduled"
    cancel = act.cancel_reboot()
    assert cancel.ok and cancel.status == "cancelled"
    assert runner.calls == [["shutdown.exe", "/r", "/t", "90"], ["shutdown.exe", "/a"]]


def test_reboot_refused_when_not_allowed_and_failures_reported():
    runner = FakeRunner()
    assert actions(runner=runner, cfg=config(reboot={"allow": False})).reboot().status == "refused"
    assert runner.calls == []
    runner = FakeRunner([CommandResult(1, "", "Access is denied"), CommandResult(1116, "", "none in progress")])
    act = actions(runner=runner)
    assert act.reboot().status == "failed"
    assert act.cancel_reboot().status == "failed"


@pytest.mark.parametrize("configured, applied", [(0, "30"), (29, "30"), (30, "30"), (45, "45")])
def test_windows_reboot_delay_has_a_30_second_minimum(configured, applied):
    runner = FakeRunner()
    actions(runner=runner, cfg=config(reboot={"allow": True, "delay_s": configured})).reboot()
    assert runner.calls == [["shutdown.exe", "/r", "/t", applied]]


class FakeShutdownHost:
    """shutdown.exe on a host with a clock: /r /t N arms a reboot, /a disarms it, advance() lets time pass."""

    def __init__(self):
        self.now, self.due, self.rebooted = 0, None, False

    def run(self, args, timeout_s):
        if args[:2] == ["shutdown.exe", "/r"]:
            self.due = self.now + int(args[3])
        elif args == ["shutdown.exe", "/a"]:
            self.due = None
        return CommandResult(0, "ok")

    def advance(self, seconds):
        self.now += seconds
        if self.due is not None and self.now >= self.due:
            self.rebooted, self.due = True, None


def test_a_local_cancel_inside_the_delay_prevents_the_windows_reboot():
    host = FakeShutdownHost()
    act = actions(runner=host, cfg=config(reboot={"allow": True, "delay_s": 0}))
    act.reboot()
    host.advance(29)
    assert act.cancel_reboot().status == "cancelled"
    host.advance(600)
    assert host.rebooted is False


def test_without_a_cancel_the_windows_reboot_fires_after_the_delay():
    host = FakeShutdownHost()
    actions(runner=host, cfg=config(reboot={"allow": True, "delay_s": 45})).reboot()
    host.advance(44)
    assert host.rebooted is False
    host.advance(1)
    assert host.rebooted is True


def test_reboot_delay_is_capped():
    runner = FakeRunner()
    actions(runner=runner, cfg=config(reboot={"allow": True, "delay_s": 10**12})).reboot()
    assert runner.calls == [["shutdown.exe", "/r", "/t", "315360000"]]


def test_unknown_action_and_bad_params_are_refused():
    act = actions()
    assert act.execute({"action": "host.format", "params": {}}).status == "refused"
    assert act.execute({"action": "host.reboot", "params": []}).status == "refused"


class Stream(io.BytesIO):
    """A reply to read from, and a record of what was written."""

    def __init__(self, reply: bytes):
        super().__init__(reply)
        self.sent = b""

    def write(self, data):
        self.sent += bytes(data)
        return len(data)


def test_exchange_request_frames_and_parses():
    reply = b'{"Success": true, "Fans": []}'
    stream = Stream(struct.pack("<i", len(reply)) + reply)
    assert aw.exchange_request(stream, {"Type": "GetFans"}) == {"Success": True, "Fans": []}
    body = b'{"Type": "GetFans"}'
    assert stream.sent == struct.pack("<i", len(body)) + body


@pytest.mark.parametrize("raw", [b"", struct.pack("<i", 0), struct.pack("<i", 5) + b"ab",
                                 struct.pack("<i", 3) + b"[1]", struct.pack("<i", 3) + b"{x}"])
def test_exchange_request_rejects_bad_replies(raw):
    with pytest.raises(SeamError):
        aw.exchange_request(Stream(raw), {"Type": "GetFans"})


def test_real_pipe_client_refuses_other_pipes():
    with pytest.raises(SeamError):
        aw.NamedPipeClient().request("OtherPipe", {"Type": "GetFans"})
