"""hostwatch-control Linux executors, tested with a fake runner that records argument lists."""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path

import pytest

from hostwatch.control import actions_linux as al
from hostwatch.control import config as cfgmod

ROOT = Path(__file__).resolve().parent.parent
KEY = "ed25519:" + "A" * 43 + "="
RAW = {"observe_public_key": KEY, "host": "MediaIn-SVR",
       "fan": {"controller": "thermalctl", "headers": ["pwm1", "pwm2"], "allow_mode_change": True},
       "services": {"restart": ["hostwatch-agent", "nut-monitor", "docker:scrutiny"]},
       "reboot": {"allow": True, "delay_s": 60}}


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


class FakeRoot:
    """The privileged side of a fan write. It plays `tee`, `mv -f` and `rm -f` on real files under tmp_path
    and answers check-config and systemctl from `fail`, a map from program path to the RunResult it returns.
    `order` records every privileged step, so a test can see what ran and in which order."""

    def __init__(self, fail=None):
        self.fail = dict(fail or {})
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
        Path(argv[1]).write_bytes(data)
        return al.RunResult(0, "")

    def run(self, argv, timeout):
        argv = self._bare(argv)
        self.order.append(argv)
        if argv[0] in self.fail:
            return self.fail[argv[0]]
        if argv[0] == al.MV:
            os.replace(argv[2], argv[3])
        elif argv[0] == al.RM:
            Path(argv[2]).unlink(missing_ok=True)
        return al.RunResult(0, "ok")


def build(tmp_path, fail=None, cfg=None):
    root = FakeRoot(fail)
    path = tmp_path / "overrides.toml"
    actions = al.LinuxActions(cfg or config(), root.run, overrides_path=path, use_sudo=False, writer=root.write)
    return actions, root, path


@pytest.fixture
def setup(tmp_path):
    return build(tmp_path)


CHECK = [al.THERMALCTL_BIN, "check-config", al.THERMALCTL_CONFIG, "--overrides"]


def cand(path):
    return path.with_name(path.name + al.CANDIDATE_SUFFIX)


def test_set_floor_stages_checks_installs_and_reloads_with_the_exact_argv(setup):
    actions, root, path = setup
    result = actions.execute({"action": "fan.set_floor",
                              "params": {"controller": "thermalctl", "header": "pwm2", "min_duty": 25}})
    assert result.ok and result.status == "done"
    assert tomllib.loads(path.read_text()) == {"headers": {"pwm2": {"min_duty": 25}}}
    assert root.order == [[al.TEE, str(cand(path))], CHECK + [str(cand(path))],
                          [al.MV, "-f", str(cand(path)), str(path)],
                          [al.SYSTEMCTL, "kill", "-s", "HUP", "thermalctl"]]
    assert not cand(path).exists()


def test_the_candidate_text_goes_on_standard_input_never_on_a_command_line(setup):
    actions, root, path = setup
    assert actions.fan_set_floor("pwm2", 25).ok
    (argv, data), = root.writes
    assert argv == [al.TEE, str(cand(path))] and b"min_duty = 25" in data
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
    assert seen == [["sudo", "-n", al.TEE, str(cand(path))],
                    ["sudo", "-n", *CHECK, str(cand(path))],
                    ["sudo", "-n", al.MV, "-f", str(cand(path)), str(path)],
                    ["sudo", "-n", al.SYSTEMCTL, "restart", "thermalctl"]]


def test_the_default_paths_give_exactly_the_argv_the_sudoers_rule_allows():
    seen = []
    actions = al.LinuxActions(config(), lambda a, t: seen.append(" ".join(a)) or al.RunResult(0, "ok"),
                              use_sudo=True, writer=lambda a, d, t: seen.append(" ".join(a)) or al.RunResult(0, ""))
    actions._read_overrides = lambda: (None, None, {})
    assert actions.fan_set_floor("pwm1", 30).ok
    rules = al.sudoers_commands(config())
    assert len(seen) == 4
    for line in seen:
        # Path() turns the slashes into backslashes on a Windows development machine only.
        assert line.replace("\\", "/").removeprefix("sudo -n ") in rules, line


def test_set_floor_merges_with_existing_overrides(setup):
    actions, root, path = setup
    path.write_text('mode = "dry_run"\n\n[headers.pwm1]\nmin_duty = 30\n')
    assert actions.fan_set_floor("pwm2", 20).ok
    assert tomllib.loads(path.read_text()) == {"mode": "dry_run",
                                               "headers": {"pwm1": {"min_duty": 30}, "pwm2": {"min_duty": 20}}}


def test_set_mode_restarts_the_service(setup):
    actions, root, path = setup
    result = actions.execute({"action": "fan.set_mode", "params": {"controller": "thermalctl", "mode": "active"}})
    assert result.ok
    assert tomllib.loads(path.read_text()) == {"mode": "active"}
    assert root.order[-1] == [al.SYSTEMCTL, "restart", "thermalctl"]


def test_a_write_failure_reports_failed_and_touches_neither_the_file_nor_the_fans(tmp_path):
    actions, root, path = build(tmp_path, {al.TEE: al.RunResult(1, "tee: Read-only file system")})
    old = b"[headers.pwm1]\nmin_duty = 30\n"
    path.write_bytes(old)
    result = actions.fan_set_floor("pwm2", 5)
    assert not result.ok and result.status == "failed"
    assert "Read-only file system" in result.output and "fans were not changed" in result.output
    assert path.read_bytes() == old and not cand(path).exists()
    assert all(step[0] in (al.TEE, al.RM) for step in root.order), "no check, install or reload after a failed write"


def test_a_write_that_cannot_even_start_is_reported_failed(tmp_path):
    actions, root, path = build(tmp_path, {al.TEE: al.RunResult(127, "FileNotFoundError: sudo")})
    result = actions.fan_set_mode("active")
    assert result.status == "failed" and not path.exists()
    assert not any(step[0] == al.SYSTEMCTL for step in root.order)


def test_an_install_failure_reports_failed_removes_the_candidate_and_leaves_the_fans_alone(tmp_path):
    actions, root, path = build(tmp_path, {al.MV: al.RunResult(1, "mv: cannot move")})
    old = b"[headers.pwm1]\nmin_duty = 30\n"
    path.write_bytes(old)
    result = actions.fan_set_floor("pwm2", 5)
    assert not result.ok and result.status == "failed" and "cannot install" in result.output
    assert path.read_bytes() == old
    assert root.order[-1] == [al.RM, "-f", str(cand(path))]
    assert not any(step[0] == al.SYSTEMCTL for step in root.order)


def test_check_config_failure_keeps_the_previous_file_and_skips_the_reload(tmp_path):
    actions, root, path = build(tmp_path, {al.THERMALCTL_BIN: al.RunResult(1, "header pwm2 below limit")})
    old = b"[headers.pwm1]\nmin_duty = 30\n"
    path.write_bytes(old)
    result = actions.fan_set_floor("pwm2", 5)
    assert not result.ok and result.status == "failed"
    assert "not changed" in result.output and "below limit" in result.output
    assert path.read_bytes() == old and not cand(path).exists()
    assert [step[0] for step in root.order] == [al.TEE, al.THERMALCTL_BIN, al.RM]


def test_check_config_failure_never_exposes_the_candidate_at_the_real_path(tmp_path):
    path = tmp_path / "overrides.toml"
    old = b"[headers.pwm1]\nmin_duty = 30\n"
    path.write_bytes(old)
    seen = []
    root = FakeRoot()

    def run(argv, timeout):
        if argv[0] == al.THERMALCTL_BIN:
            # While thermalctl checks the candidate, the real file must still hold the old bytes and
            # the check must be pointed at the candidate, not at the real path.
            seen.append((path.read_bytes(), argv[-1], cand(path).read_bytes()))
            return al.RunResult(1, "rejected")
        return root.run(argv, timeout)

    actions = al.LinuxActions(config(), run, overrides_path=path, use_sudo=False, writer=root.write)
    assert not actions.fan_set_floor("pwm2", 5).ok
    (real_during, checked, candidate), = seen
    assert real_during == old and checked == str(cand(path)) and checked != str(path)
    assert b"pwm2" in candidate
    assert path.read_bytes() == old and not cand(path).exists()


def test_check_config_failure_leaves_no_file_when_there_was_none(tmp_path):
    actions, root, path = build(tmp_path, {al.THERMALCTL_BIN: al.RunResult(1, "bad")})
    assert not actions.fan_set_mode("active").ok
    assert not path.exists()


def test_failed_reload_is_reported_not_hidden(tmp_path):
    actions, root, path = build(tmp_path, {al.SYSTEMCTL: al.RunResult(1, "no such unit")})
    result = actions.fan_set_floor("pwm1", 40)
    assert not result.ok and "not reloaded" in result.output


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
    re.compile(re.escape(f"{al.THERMALCTL_BIN} check-config {al.THERMALCTL_CONFIG} --overrides {al.OVERRIDES_PATH}{al.CANDIDATE_SUFFIX}")),
    re.compile(re.escape(f"{al.TEE} {al.OVERRIDES_PATH}{al.CANDIDATE_SUFFIX}")),
    re.compile(re.escape(f"{al.MV} -f {al.OVERRIDES_PATH}{al.CANDIDATE_SUFFIX} {al.OVERRIDES_PATH}")),
    re.compile(re.escape(f"{al.RM} -f {al.OVERRIDES_PATH}{al.CANDIDATE_SUFFIX}")),
    re.compile(re.escape(f"{al.SYSTEMCTL} kill -s HUP thermalctl")),
    re.compile(re.escape(f"{al.SYSTEMCTL} restart ") + NAME),
    re.compile(re.escape(f"{al.DOCKER} restart ") + NAME),
    re.compile(re.escape(f"{al.SYSTEMD_RUN} --unit={al.REBOOT_UNIT} --on-active=") + r"(\[0-9\]){2,6}"
               + re.escape(f"s {al.SYSTEMCTL} reboot")),
    re.compile(re.escape(f"{al.SYSTEMCTL} stop {al.REBOOT_UNIT}.timer")),
]


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
        assert "," not in rule and "ALL" not in rule and "*" not in rule
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
        line = " ".join(call).replace(str(overrides), al.OVERRIDES_PATH)
        if line.startswith(al.SYSTEMD_RUN):
            line = re.sub(r"--on-active=(\d+)s", lambda m: "--on-active=" + "[0-9]" * len(m.group(1)) + "s", line)
        assert line in rules, line
    used = {" ".join(c).replace(str(overrides), al.OVERRIDES_PATH) for c in root.order}
    for rule in rules:
        if rule.startswith((al.TEE, al.MV)):
            assert rule in used, rule


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
    assert runner.calls == [] and not path.exists() and not cand(path).exists()


def test_thermalctl_fan_actions_are_refused_without_a_fan_section(tmp_path):
    runner = FakeRunner()
    cfg = cfgmod.parse({"observe_public_key": KEY, "host": "h"})
    actions = al.LinuxActions(cfg, runner, overrides_path=tmp_path / "o.toml", use_sudo=False)
    assert actions.fan_set_floor("pwm1", 30).status == "refused"
    assert actions.fan_set_mode("active").status == "refused"
    assert runner.calls == []
