"""hostwatch-control Linux executors, tested with a fake runner that records argument lists."""

from __future__ import annotations

import os
import re
import tomllib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from hostwatch.control import actions_linux as al
from hostwatch.control import config as cfgmod

ROOT = Path(__file__).resolve().parent.parent
KEY = "ed25519:" + "A" * 43 + "="
RAW = {"observe_public_key": KEY, "host": "MediaIn-SVR",
       "fan": {"controller": "thermalctl", "headers": ["pwm1", "pwm2"], "allow_mode_change": True},
       "services": {"restart": ["hostwatch-agent", "nut-monitor", "docker:scrutiny"]},
       "reboot": {"allow": True, "delay_s": 60},
       "update": {"agent": True, "control": True}}


def config(**over):
    return cfgmod.parse({**RAW, **over})


class FakeRunner:
    def __init__(self, results=None):
        self.calls = []
        self.results = list(results or [])

    def __call__(self, argv, timeout):
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        self.calls.append(list(argv))
        return self.results.pop(0) if self.results else al.RunResult(0, "ok")


NOW = 1_800_000_000
INSTALL = [al.THERMALCTL_BIN, "install-override"]


class FakeRoot:
    """The privileged side of a fan write. It plays `thermalctl install-override`: on success it replaces the
    overrides file under tmp_path with the standard input, and on failure it leaves the file alone. `fail` maps a
    program path to the RunResult it returns. `order` records every privileged step."""

    def __init__(self, overrides, fail=None):
        self.overrides, self.fail = overrides, dict(fail or {})
        self.order, self.writes = [], []

    @property
    def calls(self):
        return self.order

    @staticmethod
    def _bare(argv):
        argv = list(argv)
        return argv[2:] if argv[:2] == ["sudo", "-n"] else argv

    def write(self, argv, data, timeout):
        assert isinstance(data, bytes)
        argv = self._bare(argv)
        self.order.append(argv)
        self.writes.append((argv, data))
        if argv[0] in self.fail:
            return self.fail[argv[0]]
        self.overrides.write_bytes(data)
        return al.RunResult(0, "override installed")

    def run(self, argv, timeout):
        argv = self._bare(argv)
        self.order.append(argv)
        if argv[0] in self.fail:
            return self.fail[argv[0]]
        return al.RunResult(0, "ok")


def build(tmp_path, fail=None, cfg=None):
    path = tmp_path / "overrides.toml"
    root = FakeRoot(path, fail)
    actions = al.LinuxActions(cfg or config(), root.run, overrides_path=path, use_sudo=False, writer=root.write,
                              clock=lambda: NOW)
    return actions, root, path


@pytest.fixture
def setup(tmp_path):
    return build(tmp_path)


def test_set_floor_delivers_the_overrides_only_through_install_override_with_an_expiry(setup):
    actions, root, path = setup
    result = actions.execute({"action": "fan.set_floor", "expires_at": NOW + 600,
                              "params": {"controller": "thermalctl", "header": "pwm2", "min_duty": 25}})
    assert result.ok and result.status == "done"
    assert tomllib.loads(path.read_text()) == {"expires_at": NOW + 600, "headers": {"pwm2": {"min_duty": 25}}}
    assert root.order == [INSTALL]


def test_the_expiry_is_the_signed_commands_and_never_beyond_the_fixed_maximum(setup):
    actions, root, path = setup
    assert actions.execute({"action": "fan.set_floor", "expires_at": NOW + 100000,
                            "params": {"header": "pwm1", "min_duty": 25}}).ok
    assert tomllib.loads(path.read_text())["expires_at"] == NOW + al.MAX_OVERRIDE_S
    assert actions.execute({"action": "fan.set_floor", "params": {"header": "pwm1", "min_duty": 25}}).ok
    assert tomllib.loads(path.read_text())["expires_at"] == NOW + al.MAX_OVERRIDE_S
    # A command expiry that is not an integer is refused rather than replaced by a later cap.
    for bad in (True, 1.5e9 + 70000.5, "soon"):
        result = actions.execute({"action": "fan.set_floor", "expires_at": bad,
                                  "params": {"header": "pwm1", "min_duty": 25}})
        assert result.status == "refused", bad


def test_a_command_that_has_already_expired_installs_nothing(setup):
    actions, root, path = setup
    result = actions.execute({"action": "fan.set_floor", "expires_at": NOW - 1,
                              "params": {"header": "pwm1", "min_duty": 25}})
    assert result.status == "failed" and "expired" in result.output
    assert root.order == [] and not path.exists()


def test_the_overrides_text_goes_on_standard_input_never_on_a_command_line(setup):
    actions, root, path = setup
    assert actions.fan_set_floor("pwm2", 25).ok
    (argv, data), = root.writes
    assert argv == INSTALL and b"min_duty = 25" in data
    assert not any("min_duty" in part for step in root.order for part in step)


def test_the_executor_runs_the_privileged_steps_through_sudo_when_not_root(tmp_path):
    seen = []

    def run(argv, timeout):
        seen.append(list(argv))
        return al.RunResult(0, "ok")

    def write(argv, data, timeout):
        seen.append(list(argv))
        return al.RunResult(0, "")

    path = tmp_path / "overrides.toml"
    al.LinuxActions(config(), run, overrides_path=path, use_sudo=True, writer=write).fan_set_mode("active")
    assert seen == [["sudo", "-n", *INSTALL], ["sudo", "-n", al.SYSTEMCTL, "restart", "thermalctl"]]


def test_the_default_argv_is_exactly_the_sudoers_rule_with_no_extra_arguments():
    seen = []
    actions = al.LinuxActions(config(), lambda a, t: seen.append(" ".join(a)) or al.RunResult(0, "ok"),
                              use_sudo=True, writer=lambda a, d, t: seen.append(" ".join(a)) or al.RunResult(0, ""))
    actions._read_overrides = lambda: (None, None, {}, None)
    assert actions.fan_set_floor("pwm1", 30).ok
    assert seen == ["sudo -n /opt/thermalctl/venv/bin/thermalctl install-override"]
    assert seen[0].removeprefix("sudo -n ") in al.sudoers_commands(config())


def test_a_float_floor_survives_a_floor_change_on_another_header(setup):
    actions, root, path = setup
    path.write_text(f'expires_at = {NOW + 300}\n\n[headers.pwm1]\nmin_duty = 32.5\n\n[headers.pwm3]\nmin_duty = 41\n')
    assert actions.fan_set_floor("pwm2", 20, NOW + 60).ok
    assert tomllib.loads(path.read_text()) == {
        "expires_at": NOW + 60,
        "headers": {"pwm1": {"min_duty": 32.5}, "pwm2": {"min_duty": 20}, "pwm3": {"min_duty": 41}}}


def test_a_floor_change_never_extends_the_life_of_floors_already_in_the_file(setup):
    actions, root, path = setup
    path.write_text(f'expires_at = {NOW + 30}\n\n[headers.pwm1]\nmin_duty = 30\n')
    assert actions.fan_set_floor("pwm2", 20, NOW + 600).ok
    assert tomllib.loads(path.read_text())["expires_at"] == NOW + 30


def test_floors_whose_expiry_has_passed_are_dropped_not_renewed(setup):
    actions, root, path = setup
    path.write_text('expires_at = 1700000000\n\n[headers.pwm1]\nmin_duty = 32.5\n\n[headers.pwm3]\nmin_duty = 41\n')
    assert actions.fan_set_floor("pwm2", 20, NOW + 60).ok
    assert tomllib.loads(path.read_text()) == {"expires_at": NOW + 60, "headers": {"pwm2": {"min_duty": 20}}}


def test_a_floor_change_is_refused_when_the_file_holds_floors_without_an_expiry(setup):
    actions, root, path = setup
    old = '[headers.pwm1]\nmin_duty = 40\n'
    path.write_text(old)
    result = actions.fan_set_floor("pwm2", 25)
    assert result.status == "refused" and "without an expiry" in result.output
    assert root.order == [] and path.read_text() == old


def test_a_floor_change_is_refused_when_the_file_sets_a_mode(setup):
    actions, root, path = setup
    path.write_text('mode = "active"\n')
    result = actions.fan_set_floor("pwm1", 20, NOW + 60)
    assert result.status == "refused" and "mode" in result.output
    assert root.order == [] and path.read_text() == 'mode = "active"\n'


def test_a_mode_change_keeps_floors_that_have_no_expiry_and_keeps_float_values(setup):
    actions, root, path = setup
    path.write_text('[headers.pwm1]\nmin_duty = 32.0\n')
    assert actions.fan_set_mode("active").ok
    loaded = tomllib.loads(path.read_text())
    assert loaded == {"mode": "active", "headers": {"pwm1": {"min_duty": 32.0}}}
    assert isinstance(loaded["headers"]["pwm1"]["min_duty"], float)


def test_a_mode_change_is_refused_while_time_bounded_floors_exist(setup):
    actions, root, path = setup
    old = f'expires_at = {NOW + 300}\n\n[headers.pwm1]\nmin_duty = 30\n'
    path.write_text(old)
    result = actions.fan_set_mode("active")
    assert result.status == "refused" and "permanent" in result.output
    assert root.order == [] and path.read_text() == old


def test_a_datetime_expiry_is_read_like_epoch_seconds(setup):
    actions, root, path = setup
    when = datetime.fromtimestamp(NOW + 30, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.write_text(f'expires_at = {when}\n\n[headers.pwm1]\nmin_duty = 30\n')
    assert actions.fan_set_floor("pwm2", 20, NOW + 600).ok
    assert tomllib.loads(path.read_text())["expires_at"] == NOW + 30


def test_a_mode_change_is_refused_while_floors_have_a_datetime_expiry(setup):
    actions, root, path = setup
    old = f'expires_at = {datetime.fromtimestamp(NOW + 300, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}\n\n[headers.pwm1]\nmin_duty = 30\n'
    path.write_text(old)
    result = actions.fan_set_mode("active")
    assert result.status == "refused" and "permanent" in result.output
    assert root.order == [] and path.read_text() == old


def test_floors_with_a_passed_datetime_expiry_are_dropped_not_renewed(setup):
    actions, root, path = setup
    path.write_text('expires_at = 2020-01-01T00:00:00+00:00\n\n[headers.pwm1]\nmin_duty = 30\n')
    assert actions.fan_set_mode("active").ok
    assert tomllib.loads(path.read_text()) == {"mode": "active"}


@pytest.mark.parametrize("text", [
    'expires_at = 2030-01-01T00:00:00\n\n[headers.pwm1]\nmin_duty = 30\n',
    'expires_at = "soon"\n\n[headers.pwm1]\nmin_duty = 30\n',
    f'expires_at = {NOW + 300}\n\n[headers.pwm1]\nmin_duty = "30"\n',
    f'expires_at = {NOW + 300}\n\n[headers]\npwm1 = 30\n',
])
def test_an_overrides_file_that_cannot_be_kept_whole_is_refused_not_rewritten(setup, text):
    actions, root, path = setup
    path.write_text(text)
    for result in (actions.fan_set_floor("pwm2", 20, NOW + 60), actions.fan_set_mode("active")):
        assert result.status == "failed" and "cannot read the existing overrides" in result.output
    assert root.order == [] and path.read_text() == text


def test_a_header_id_outside_the_basic_multilingual_plane_is_written_so_toml_reads_it_back():
    name = "fan-😀-" + chr(127)
    out = al.LinuxActions._render(None, {name: 30}, NOW + 60)
    assert tomllib.loads(out.decode("utf-8"))["headers"] == {name: {"min_duty": 30}}


def test_a_mode_change_drops_floors_whose_expiry_has_passed(setup):
    actions, root, path = setup
    path.write_text('expires_at = 1700000000\n\n[headers.pwm1]\nmin_duty = 30\n')
    assert actions.fan_set_mode("active").ok
    assert tomllib.loads(path.read_text()) == {"mode": "active"}


def test_floors_on_header_ids_outside_the_command_pattern_are_preserved(setup):
    actions, root, path = setup
    long_id = "h" * 40
    path.write_text(f'expires_at = {NOW + 300}\n\n[headers."fan.1 a"]\nmin_duty = 30\n\n[headers.{long_id}]\nmin_duty = 35.5\n')
    assert actions.fan_set_floor("pwm2", 20, NOW + 60).ok
    assert tomllib.loads(path.read_text())["headers"] == {
        "fan.1 a": {"min_duty": 30}, long_id: {"min_duty": 35.5}, "pwm2": {"min_duty": 20}}


def test_set_mode_restarts_the_service_and_sets_no_expiry(setup):
    actions, root, path = setup
    result = actions.execute({"action": "fan.set_mode", "expires_at": NOW + 60,
                              "params": {"controller": "thermalctl", "mode": "active"}})
    assert result.ok
    assert tomllib.loads(path.read_text()) == {"mode": "active"}
    assert root.order == [INSTALL, [al.SYSTEMCTL, "restart", "thermalctl"]]


def test_a_refused_install_reports_failed_with_thermalctls_message_and_leaves_nothing_behind(tmp_path):
    msg = "thermalctl: override not installed, the live file is unchanged: min_duty 5 is below the allowed minimum 20"
    actions, root, path = build(tmp_path, {al.THERMALCTL_BIN: al.RunResult(1, msg)})
    old = f"expires_at = {NOW + 300}\n\n[headers.pwm1]\nmin_duty = 32.5\n".encode()
    path.write_bytes(old)
    result = actions.fan_set_floor("pwm2", 5)
    assert not result.ok and result.status == "failed"
    assert "below the allowed minimum 20" in result.output and "fans were not changed" in result.output
    assert path.read_bytes() == old
    assert root.order == [INSTALL], "no reload, restart or cleanup step follows a refused install"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["overrides.toml"]


def test_a_refused_mode_install_does_not_restart_the_service(tmp_path):
    actions, root, path = build(tmp_path, {al.THERMALCTL_BIN: al.RunResult(1, "mode needs a restart")})
    result = actions.fan_set_mode("active")
    assert result.status == "failed" and "mode needs a restart" in result.output and not path.exists()
    assert root.order == [INSTALL]


def test_an_install_that_cannot_even_start_is_reported_failed(tmp_path):
    actions, root, path = build(tmp_path, {al.THERMALCTL_BIN: al.RunResult(127, "FileNotFoundError: sudo")})
    result = actions.fan_set_mode("active")
    assert result.status == "failed" and not path.exists()
    assert not any(step[0] == al.SYSTEMCTL for step in root.order)


def test_a_failed_restart_after_a_mode_install_is_reported_not_hidden(tmp_path):
    actions, root, path = build(tmp_path, {al.SYSTEMCTL: al.RunResult(1, "no such unit")})
    result = actions.fan_set_mode("dry_run")
    assert not result.ok and "not restarted" in result.output


def test_an_unreadable_existing_file_fails_before_any_call(tmp_path):
    actions, root, path = build(tmp_path)
    path.write_text("not [toml")
    assert actions.fan_set_floor("pwm1", 20).status == "failed"
    assert root.order == [] and path.read_text() == "not [toml"


def test_the_real_writer_never_uses_a_shell_and_sends_the_data_on_stdin():
    import inspect
    src = inspect.getsource(al.subprocess_writer)
    assert "shell=False" in src and "shell=True" not in src and "input=data" in src


@pytest.mark.parametrize("header", ["", "pwm 1", "../x", "a;b", "$(id)", "-pwm1", "pw@m", "a" * 40, 5, None])
def test_bad_header_names_are_rejected_before_any_call(setup, header):
    actions, runner, path = setup
    assert actions.fan_set_floor(header, 20).status == "refused"
    assert runner.calls == [] and not path.exists()


@pytest.mark.parametrize("duty", [-1, 101, True, "20", 20.5, None])
def test_bad_duty_is_rejected_before_any_call(setup, duty):
    actions, runner, path = setup
    assert actions.fan_set_floor("pwm1", duty).status == "refused"
    assert runner.calls == [] and not path.exists()


def test_bad_mode_is_rejected(setup):
    actions, runner, path = setup
    assert actions.fan_set_mode("turbo\nmode").status == "refused"
    assert runner.calls == []


def test_service_restart_argument_lists(setup):
    actions, runner, _ = setup
    assert actions.service_restart("hostwatch-agent").ok
    assert actions.service_restart("docker:scrutiny").ok
    assert runner.calls == [[al.SYSTEMCTL, "restart", "hostwatch-agent"], [al.DOCKER, "restart", "scrutiny"]]


BAD_NAMES = ["a b", "a..b", "..", "a;b", "a$(id)", "a`id`", "unit@x", "-rf", "docker:-x", "docker:a b",
             "docker:a;b", "docker:$(id)", "docker:", "a\nb", "a|b", "a&b", "a/b", 7, None]


@pytest.mark.parametrize("name", BAD_NAMES)
def test_malicious_names_are_rejected_before_any_call(name):
    # Even if a hostile name were somehow in the local list, the executor refuses it.
    runner = FakeRunner()
    actions = al.LinuxActions(config(), runner, use_sudo=False)
    object.__setattr__(actions.config, "restart", (name,))
    assert actions.service_restart(name).status == "refused"
    assert runner.calls == []


def test_unlisted_name_is_refused(setup):
    actions, runner, _ = setup
    assert actions.service_restart("sshd").status == "refused"
    assert runner.calls == []


def test_config_rejects_hostile_names():
    for name in ("unit@x", "a..b", "-x", "docker:a b"):
        with pytest.raises(cfgmod.ConfigError):
            cfgmod.parse({**RAW, "services": {"restart": [name]}})


def test_sudo_prefix_when_not_root(tmp_path):
    runner = FakeRunner()
    actions = al.LinuxActions(config(), runner, overrides_path=tmp_path / "o.toml", use_sudo=True)
    actions.service_restart("nut-monitor")
    actions.reboot()
    assert runner.calls == [["sudo", "-n", al.SYSTEMCTL, "restart", "nut-monitor"],
                            ["sudo", "-n", *al._reboot_argv(60)]]


def test_reboot_schedule_and_cancel():
    runner = FakeRunner()
    actions = al.LinuxActions(config(reboot={"allow": True, "delay_s": 150}), runner, use_sudo=False)
    scheduled = actions.execute({"action": "host.reboot", "params": {}})
    assert scheduled.ok and scheduled.status == "scheduled"
    cancelled = actions.cancel_reboot()
    assert cancelled.ok and cancelled.status == "cancelled"
    assert runner.calls == [al._reboot_argv(150), al._cancel_argv()]
    assert scheduled.output.startswith("reboot in 150 second(s)")


@pytest.mark.parametrize("configured, applied", [(0, 30), (1, 30), (29, 30), (30, 30), (45, 45), (61, 61)])
def test_linux_reboot_delay_is_exact_seconds_with_a_30_second_minimum(configured, applied):
    runner = FakeRunner()
    actions = al.LinuxActions(config(reboot={"allow": True, "delay_s": configured}), runner, use_sudo=False)
    assert actions.reboot().output.startswith(f"reboot in {applied} second(s)")
    assert runner.calls == [[al.SYSTEMD_RUN, "--unit=hostwatch-reboot", f"--on-active={applied}s",
                             al.SYSTEMCTL, "reboot"]]
    assert not any("shutdown" in part for part in runner.calls[0])


def test_linux_reboot_delay_below_the_minimum_is_raised_even_without_the_config_parser():
    runner = FakeRunner()
    policy = cfgmod.RebootPolicy(True, 0)
    cfg = cfgmod.ControlConfig(public_key=b"", host="h", reboot=policy)
    al.LinuxActions(cfg, runner, use_sudo=False).reboot()
    assert runner.calls[0][2] == "--on-active=30s"


class FakeHost:
    """A host with one pending reboot. `advance` runs the clock, and a reboot fires when its time arrives
    unless a cancel removed it first. It understands both the Linux timer and the Windows shutdown argv."""

    def __init__(self):
        self.now, self.due, self.rebooted = 0, None, False

    def __call__(self, argv, timeout):
        argv = list(argv)
        if argv[0] == al.SYSTEMD_RUN:
            self.due = self.now + int(argv[2].removeprefix("--on-active=").removesuffix("s"))
        elif argv[:2] == [al.SYSTEMCTL, "stop"]:
            self.due = None
        return al.RunResult(0, "ok")

    def advance(self, seconds):
        self.now += seconds
        if self.due is not None and self.now >= self.due:
            self.rebooted, self.due = True, None


def test_a_local_cancel_inside_the_delay_prevents_the_linux_reboot():
    host = FakeHost()
    actions = al.LinuxActions(config(reboot={"allow": True, "delay_s": 0}), host, use_sudo=False)
    actions.reboot()
    host.advance(29)  # the whole minimum delay minus one second is still cancellable
    assert actions.cancel_reboot().status == "cancelled"
    host.advance(600)
    assert host.rebooted is False


def test_without_a_cancel_the_linux_reboot_fires_after_the_delay():
    host = FakeHost()
    al.LinuxActions(config(reboot={"allow": True, "delay_s": 45}), host, use_sudo=False).reboot()
    host.advance(44)
    assert host.rebooted is False
    host.advance(1)
    assert host.rebooted is True


def test_reboot_failure_and_disallowed():
    failing = al.LinuxActions(config(), FakeRunner([al.RunResult(1, "denied")]), use_sudo=False)
    assert failing.reboot().status == "failed"
    runner = FakeRunner()
    off = al.LinuxActions(config(reboot={"allow": False}), runner, use_sudo=False)
    assert off.reboot().status == "refused" and runner.calls == []


def test_unknown_action_and_bad_params(setup):
    actions, runner, _ = setup
    assert actions.execute({"action": "rm.rf", "params": {}}).status == "refused"
    assert actions.execute({"action": "host.reboot", "params": []}).status == "refused"
    assert runner.calls == []


def test_real_runner_never_uses_a_shell():
    import inspect
    src = inspect.getsource(al.subprocess_runner)
    assert "shell=False" in src and "shell=True" not in src


# sudoers ------------------------------------------------------------------------------------

NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
ALLOWED = [
    re.compile(re.escape(f"{al.THERMALCTL_BIN} install-override")),
    re.compile(re.escape(f"{al.SYSTEMCTL} restart ") + NAME),
    re.compile(re.escape(f"{al.DOCKER} restart ") + NAME),
    re.compile(re.escape(f"{al.SYSTEMD_RUN} --unit={al.REBOOT_UNIT} --on-active=") + r"(\[0-9\]){2,6}"
               + re.escape(f"s {al.SYSTEMCTL} reboot")),
    re.compile(re.escape(f"{al.SYSTEMCTL} stop {al.REBOOT_UNIT}.timer")),
    # agent.update: one fixed image, two fixed container names, one fixed pip spec and one fixed restart.
    re.compile(re.escape(f"{al.DOCKER} inspect --type container {al.AGENT_CONTAINER}")),
    re.compile(re.escape(f"{al.DOCKER} pull {al.sudoers_literal(al.AGENT_IMAGE)}")),
    re.compile(re.escape(f"{al.DOCKER} image inspect {al.sudoers_literal(al.AGENT_IMAGE)}")),
    re.compile(re.escape(f"{al.DOCKER} stop {al.AGENT_CONTAINER}")),
    re.compile(re.escape(f"{al.DOCKER} start {al.AGENT_CONTAINER}")),
    re.compile(re.escape(f"{al.DOCKER} rm -f ") + f"({al.AGENT_CONTAINER}|{al.AGENT_PREV_CONTAINER})"),
    re.compile(re.escape(f"{al.DOCKER} rename ") + f"({al.AGENT_CONTAINER} {al.AGENT_PREV_CONTAINER}|"
               f"{al.AGENT_PREV_CONTAINER} {al.AGENT_CONTAINER})"),
    re.compile(re.escape(f"{al.DOCKER} run --detach --name {al.AGENT_CONTAINER} *")),
    re.compile(re.escape(f"{al.CONTROL_PIP} " + " ".join(al.sudoers_literal(a) for a in al.PIP_INSTALL_ARGS))),
    re.compile(re.escape(f"{al.SYSTEMD_RUN} --on-active={al.CONTROL_RESTART_DELAY_S} {al.SYSTEMCTL} restart "
                         f"{al.CONTROL_UNIT}")),
]
# The one rule that carries a wildcard: the run arguments are copied from the old container at run time.
RUN_RULE = f"{al.DOCKER} run --detach --name {al.AGENT_CONTAINER} *"


def _rules(text):
    out = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        m = re.fullmatch(r"([a-z_][a-z0-9_-]*) ALL=\(root\) NOPASSWD: (.+)", line)
        assert m, f"unexpected sudoers line: {line!r}"
        out.append(m.group(2))
    return out


def test_sudoers_snippet_lists_only_allowlisted_shapes():
    text = (ROOT / "deploy" / "hostwatch-control.sudoers").read_text(encoding="utf-8")
    assert "\r" not in text
    rules = _rules(text)
    assert rules
    for rule in rules:
        assert any(p.fullmatch(rule) for p in ALLOWED), rule
        assert "," not in rule and "ALL" not in rule
        assert "*" not in rule or rule == RUN_RULE, rule
    assert "NOPASSWD: ALL" not in text and "SETENV" not in text


def test_sudoers_snippet_matches_the_renderer_for_the_example_config():
    text = (ROOT / "deploy" / "hostwatch-control.sudoers").read_text(encoding="utf-8")
    assert text == al.render_sudoers(config())


def test_sudoers_covers_every_privileged_call_the_executors_make(tmp_path):
    cfg = config()
    actions, root, overrides = build(tmp_path, cfg=cfg)
    runner = FakeRunner()
    other = al.LinuxActions(cfg, runner, overrides_path=overrides, use_sudo=False)
    actions.fan_set_floor("pwm1", 30)
    actions.fan_set_mode("active")
    for name in cfg.restart:
        other.service_restart(name)
    other.reboot()
    other.cancel_reboot()
    rules = al.sudoers_commands(cfg)
    for call in root.order + runner.calls:
        line = " ".join(call)
        if line.startswith(al.SYSTEMD_RUN):
            line = re.sub(r"--on-active=(\d+)s", lambda m: "--on-active=" + "[0-9]" * len(m.group(1)) + "s", line)
        assert line in rules, line
    assert " ".join(INSTALL) in rules


# The example rule copied from thermal-control-linux, branch staged/fixes-oct, commit 9c44934,
# file packaging/sudoers.d/hostwatch-control. It is the contract for what the account may run as root.
EXAMPLE = ROOT / "tests" / "fixtures" / "thermalctl_sudoers_example"
EXAMPLE_COMMIT = "9c44934"


def test_the_shipped_sudoers_grants_thermalctl_exactly_the_example_rule_and_nothing_older():
    example = EXAMPLE.read_text(encoding="utf-8")
    assert "\r" not in example
    example_rules = _rules(example)
    assert example_rules == ["/opt/thermalctl/venv/bin/thermalctl install-override"]
    shipped = (ROOT / "deploy" / "hostwatch-control.sudoers").read_text(encoding="utf-8")
    shipped_lines = [l for l in shipped.splitlines() if not l.startswith("#") and l.strip()]
    example_lines = [l for l in example.splitlines() if not l.startswith("#") and l.strip()]
    assert example_lines[0] in shipped_lines, f"the rule differs from thermal-control-linux {EXAMPLE_COMMIT}"
    thermalctl_lines = [l for l in shipped_lines if "thermalctl" in l and "systemctl" not in l]
    assert thermalctl_lines == example_lines
    for gone in ("/usr/bin/tee", "/usr/bin/mv", "/usr/bin/rm", "check-config", "kill -s HUP", ".candidate"):
        assert gone not in shipped, gone


def test_the_executor_argv_equals_the_example_rule_with_the_account_removed():
    rule = _rules(EXAMPLE.read_text(encoding="utf-8"))[0]
    assert " ".join(INSTALL) == rule


def test_sudoers_renders_nothing_for_disabled_actions_and_rejects_bad_account():
    cfg = cfgmod.parse({"observe_public_key": KEY, "host": "h"})
    assert _rules(al.render_sudoers(cfg)) == []
    with pytest.raises(ValueError):
        al.render_sudoers(cfg, "bad user; ALL")


# controller selection ------------------------------------------------------------------------


@pytest.mark.parametrize("controller", ["thermal-control-suite"])
def test_thermalctl_fan_actions_are_refused_under_another_controller(tmp_path, controller):
    runner = FakeRunner()
    raw = {**RAW, "fan": {**RAW["fan"], "controller": controller}}
    path = tmp_path / "overrides.toml"
    actions = al.LinuxActions(cfgmod.parse(raw), runner, overrides_path=path, use_sudo=False)
    for result in (actions.execute({"action": "fan.set_floor", "params": {"header": "pwm1", "min_duty": 30}}),
                   actions.execute({"action": "fan.set_mode", "params": {"mode": "active"}})):
        assert not result.ok and result.status == "refused" and "thermalctl" in result.output
    assert runner.calls == [] and not path.exists()


def test_thermalctl_fan_actions_are_refused_without_a_fan_section(tmp_path):
    runner = FakeRunner()
    cfg = cfgmod.parse({"observe_public_key": KEY, "host": "h"})
    actions = al.LinuxActions(cfg, runner, overrides_path=tmp_path / "o.toml", use_sudo=False)
    assert actions.fan_set_floor("pwm1", 30).status == "refused"
    assert actions.fan_set_mode("active").status == "refused"
    assert runner.calls == []


def test_the_shipped_unit_lets_install_override_open_its_lock_under_run_and_pip_write_the_venv():
    unit = (ROOT / "deploy" / "hostwatch-control.service").read_text(encoding="utf-8")
    paths = [l.removeprefix("ReadWritePaths=") for l in unit.splitlines() if l.startswith("ReadWritePaths=")]
    assert len(paths) == 1
    assert paths[0].split() == ["-/etc/thermalctl", "-/run/thermalctl", f"-{al.CONTROL_VENV}"]


def test_the_docs_name_the_exact_example_rule_command():
    rule = _rules(EXAMPLE.read_text(encoding="utf-8"))[0]
    for doc in ("README.md", "docs/deploy-agents.md"):
        text = (ROOT / doc).read_text(encoding="utf-8")
        assert "install-override" in text, doc
    assert rule in (ROOT / "docs" / "deploy-agents.md").read_text(encoding="utf-8")
    assert "hostwatch-control ALL=(root) NOPASSWD: " + rule in (ROOT / "README.md").read_text(encoding="utf-8")
