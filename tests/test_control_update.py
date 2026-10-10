"""agent.update: the allowlist stanza, the sudoers rules, and the container and daemon update flows.

The flows run the real `subprocess_runner` against `tests/fake_docker.py`, a stand-in for docker, pip, the
venv python and systemd-run that records every call in a state file and moves containers between names the
way docker does. Nothing here touches a real docker socket, package index or systemd.
"""

from __future__ import annotations

import fnmatch
import json
import os
import sys
from pathlib import Path

import pytest

from hostwatch.control import actions_linux as al
from hostwatch.control import actions_windows as aw
from hostwatch.control import config as cfgmod
from hostwatch.control import installed
from hostwatch.control import verify as v

KEY = "ed25519:" + "A" * 43 + "="
BASE = {"observe_public_key": KEY, "host": "MediaIn-SVR"}
OLD_ID = "sha256:" + "a" * 64
NEW_ID = "sha256:" + "b" * 64
INGEST_KEY = "wpi_" + "s3cretvalue0" * 3
# The container the Observe installer creates (observe/scripts.py install_agent), as docker inspect shows it.
INSPECT = {
    "Id": "1" * 64, "Name": "/hostwatch-agent", "Image": OLD_ID,
    "State": {"Running": True, "Status": "running"},
    "Config": {"Image": al.AGENT_IMAGE, "User": "10001:10001",
               "Env": ["HOSTWATCH_ROLE=agent", f"HOSTWATCH_INGEST_KEY={INGEST_KEY}", "HOSTWATCH_HOST_NAME=MediaIn-SVR",
                       "HOSTWATCH_JOURNAL_GID=102", "PATH=/usr/local/bin:/usr/bin"],
               "Labels": {al.VERSION_LABEL: "0.1.0"}},
    "HostConfig": {"NetworkMode": "host", "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
                   "ReadonlyRootfs": True, "Tmpfs": {"/tmp": ""}, "CapDrop": ["ALL"], "CapAdd": None,
                   "SecurityOpt": ["no-new-privileges:true"], "GroupAdd": ["102"]},
    "Mounts": [{"Type": "bind", "Source": "/sys", "Destination": "/host/sys", "RW": False},
               {"Type": "volume", "Name": "hostwatch-agent-data",
                "Source": "/var/lib/docker/volumes/hostwatch-agent-data/_data", "Destination": "/data", "RW": True},
               {"Type": "bind", "Source": "/var/log/journal", "Destination": "/host/journal", "RW": False}],
}
# Every option the installer's `docker run` passes, which the rebuilt command must carry again.
INSTALLER_OPTIONS = ["--detach", "--name", "--restart", "--network", "--user", "--read-only", "--tmpfs",
                     "--cap-drop", "--security-opt", "--env-file", "--volume", "--group-add"]
RUN_ARGV = [al.DOCKER, "run", "--detach", "--name", "hostwatch-agent", "--restart", "unless-stopped",
            "--network", "host", "--user", "10001:10001", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--group-add", "102", "--env", "HOSTWATCH_JOURNAL_GID=102",
            "--env-file", "/etc/hostwatch/agent.env", "--volume", "/sys:/host/sys:ro",
            "--volume", "hostwatch-agent-data:/data", "--volume", "/var/log/journal:/host/journal:ro", al.AGENT_IMAGE]


def config(**over):
    return cfgmod.parse({**BASE, **over})


def both():
    return config(update={"agent": True, "control": True})


# --- control.toml ---------------------------------------------------------------------------

@pytest.mark.parametrize("stanza, agent, control", [
    (None, False, False), ({}, False, False), ({"agent": True}, True, False), ({"control": True}, False, True),
    ({"agent": True, "control": True}, True, True), ({"agent": False, "control": False}, False, False)])
def test_the_update_stanza_defaults_to_neither_and_reads_each_flag(stanza, agent, control):
    cfg = config() if stanza is None else config(update=stanza)
    assert cfg.update == cfgmod.UpdatePolicy(agent, control)


@pytest.mark.parametrize("stanza", [{"agent": "yes"}, {"control": 1}, {"agent": None}, "all", ["agent"]])
def test_a_bad_update_stanza_is_a_config_error(stanza):
    with pytest.raises(cfgmod.ConfigError):
        config(update=stanza)


# --- the allowlist check --------------------------------------------------------------------

def _cmd(params):
    return {"action": "agent.update", "params": params}


@pytest.mark.parametrize("params", [{}, {"component": "agent", "extra": 1}, {"component": "hub"},
                                    {"component": 1}, {"component": None}, {"component": ["agent"]},
                                    {"component": "Agent"}, {"component": "agent "}])
def test_params_must_be_exactly_a_known_component(params):
    decision = v.check_allowlist(both(), _cmd(params))
    assert not decision and decision.reason == v.BAD_PARAMS


@pytest.mark.parametrize("stanza, component, missing", [
    (None, "agent", "update.agent is false"),
    (None, "control", "update.control is false"),
    (None, "all", "update.agent and update.control are false"),
    ({"agent": True}, "control", "update.control is false"),
    ({"agent": True}, "all", "update.control is false"),
    ({"control": True}, "agent", "update.agent is false"),
    ({"control": True}, "all", "update.agent is false"),
])
def test_a_refusal_names_the_flag_that_is_false(stanza, component, missing):
    cfg = config() if stanza is None else config(update=stanza)
    decision = v.check_allowlist(cfg, _cmd({"component": component}))
    assert not decision and decision.reason == v.UPDATE_NOT_ALLOWED and decision.detail == missing


@pytest.mark.parametrize("stanza, component", [
    ({"agent": True}, "agent"), ({"control": True}, "control"), ({"agent": True, "control": True}, "all"),
    ({"agent": True, "control": True}, "agent")])
def test_an_allowed_component_is_accepted(stanza, component):
    assert v.check_allowlist(config(update=stanza), _cmd({"component": component}))


def test_the_action_is_in_the_catalogue_and_the_reason_code_is_stable():
    assert "agent.update" in v.ACTIONS and v.UPDATE_NOT_ALLOWED == "update_not_allowed"
    assert v.UPDATE_COMPONENTS == al.UPDATE_COMPONENTS == ("agent", "control", "all")


# --- sudoers -------------------------------------------------------------------------------

AGENT_RULES = [
    f"{al.DOCKER} inspect --type container hostwatch-agent",
    f"{al.DOCKER} pull ghcr.io/trooperthorn/hostwatch\\:edge",
    f"{al.DOCKER} image inspect ghcr.io/trooperthorn/hostwatch\\:edge",
    f"{al.DOCKER} rm -f hostwatch-agent-prev",
    f"{al.DOCKER} stop hostwatch-agent",
    f"{al.DOCKER} rename hostwatch-agent hostwatch-agent-prev",
    f"{al.DOCKER} run --detach --name hostwatch-agent *",
    f"{al.DOCKER} rm -f hostwatch-agent",
    f"{al.DOCKER} rename hostwatch-agent-prev hostwatch-agent",
    f"{al.DOCKER} start hostwatch-agent",
]
CONTROL_RULES = [
    "/opt/hostwatch-control/venv/bin/pip install --quiet --upgrade hostwatch\\[control\\] @ "
    "git+https\\://github.com/trooperthorn/hostwatch.git",
    "/usr/bin/systemd-run --on-active=5 /usr/bin/systemctl restart hostwatch-control",
]


def _rules(text):
    return [line.split("NOPASSWD: ", 1)[1] for line in text.splitlines() if line and not line.startswith("#")]


def _as_fnmatch(rule: str) -> str:
    """A sudoers argument pattern as Python's fnmatch reads it. libc fnmatch, which sudo uses, takes a
    backslash as an escape; Python's does not, so an escaped wildcard becomes a one-character class and an
    escaped grammar character becomes itself."""
    out, i = [], 0
    while i < len(rule):
        ch = rule[i]
        if ch == "\\" and i + 1 < len(rule):
            nxt = rule[i + 1]
            out.append(f"[{nxt}]" if nxt in "[]*?" else nxt)
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


@pytest.mark.parametrize("agent, control", [(False, False), (True, False), (False, True), (True, True)])
def test_sudoers_rules_follow_each_flag_combination_and_render_deterministically(agent, control):
    cfg = config(update={"agent": agent, "control": control})
    expected = (AGENT_RULES if agent else []) + (CONTROL_RULES if control else [])
    assert _rules(al.render_sudoers(cfg)) == expected
    assert al.sudoers_commands(cfg) == expected
    assert al.render_sudoers(cfg) == al.render_sudoers(cfg)
    text = al.render_sudoers(cfg)
    assert "\r" not in text and text.endswith("\n")
    wildcards = [r for r in _rules(text) if "*" in r or "?" in r]
    assert wildcards == ([f"{al.DOCKER} run --detach --name hostwatch-agent *"] if agent else [])


def test_update_rules_come_after_the_other_rules_and_never_widen_them():
    cfg = cfgmod.parse({**BASE, "services": {"restart": ["docker:scrutiny"]}, "reboot": {"allow": True},
                        "update": {"agent": True, "control": True}})
    rules = al.sudoers_commands(cfg)
    assert rules[-len(AGENT_RULES) - len(CONTROL_RULES):] == AGENT_RULES + CONTROL_RULES
    assert f"{al.DOCKER} restart scrutiny" in rules
    for rule in rules:
        assert "," not in rule and " ALL" not in rule


@pytest.mark.parametrize("raw, escaped", [
    ("ghcr.io/trooperthorn/hostwatch:edge", "ghcr.io/trooperthorn/hostwatch\\:edge"),
    ("hostwatch[control] @ git+https://x", "hostwatch\\[control\\] @ git+https\\://x"),
    ("a,b", "a\\,b"), ("back\\slash", "back\\\\slash"), ("star*q?", "star\\*q\\?"),
    ("--on-active=5", "--on-active=5"), ("plain-word.txt", "plain-word.txt")])
def test_sudoers_literal_escapes_the_grammar_and_wildcard_characters(raw, escaped):
    assert al.sudoers_literal(raw) == escaped


def test_the_pip_rule_is_the_contract_command_and_the_escaped_text_matches_the_literal_argument():
    """sudo matches the joined arguments with fnmatch, so the escaped rule must match the real argument list."""
    spec_rule = CONTROL_RULES[0].split(" ", 1)[1]
    argv = " ".join(al.PIP_INSTALL_ARGS)
    assert argv == 'install --quiet --upgrade hostwatch[control] @ git+https://github.com/trooperthorn/hostwatch.git'
    assert spec_rule.replace("\\", "") == argv
    assert fnmatch.fnmatchcase(argv, _as_fnmatch(spec_rule))
    assert not fnmatch.fnmatchcase("install --quiet --upgrade hostwatchc @ git+https://github.com/trooperthorn/hostwatch.git",
                                   _as_fnmatch(spec_rule))
    assert not fnmatch.fnmatchcase(argv + " evil", _as_fnmatch(spec_rule))
    assert fnmatch.fnmatchcase(" ".join(RUN_ARGV[1:]), "run --detach --name hostwatch-agent *")
    assert not fnmatch.fnmatchcase("run --detach --name hostwatch-agent-prev x", "run --detach --name hostwatch-agent *")


# --- rebuilding the run command ---------------------------------------------------------------

def test_the_run_command_is_rebuilt_from_inspect_with_every_installer_option_and_the_env_file():
    argv = al.agent_run_argv(INSPECT, al.AGENT_IMAGE)
    assert argv == RUN_ARGV
    for option in INSTALLER_OPTIONS:
        assert option in argv, option
    assert INGEST_KEY not in " ".join(argv) and "HOSTWATCH_INGEST_KEY" not in " ".join(argv)
    assert "HOSTWATCH_ROLE" not in " ".join(argv) and "PATH=" not in " ".join(argv)


def test_the_run_command_handles_a_bare_container_and_an_on_failure_policy():
    bare = {"Config": {"Image": al.AGENT_IMAGE}, "HostConfig": {"RestartPolicy": {"Name": "on-failure",
                                                                                    "MaximumRetryCount": 3}}}
    argv = al.agent_run_argv(bare, al.AGENT_IMAGE)
    assert argv == [al.DOCKER, "run", "--detach", "--name", "hostwatch-agent", "--restart", "on-failure:3",
                    "--network", "default", "--env-file", "/etc/hostwatch/agent.env", al.AGENT_IMAGE]
    assert al.agent_run_argv({}, al.AGENT_IMAGE)[5:10] == ["--restart", "no", "--network", "default", "--env-file"]


@pytest.mark.parametrize("patch", [
    {"HostConfig": {**INSPECT["HostConfig"], "NetworkMode": "--privileged"}},
    {"HostConfig": {**INSPECT["HostConfig"], "SecurityOpt": ["a b"]}},
    {"HostConfig": {**INSPECT["HostConfig"], "GroupAdd": ["102\n--privileged"]}},
    {"Config": {**INSPECT["Config"], "User": "-root"}},
    {"Mounts": [{"Type": "bind", "Source": "/ -v /:/host", "Destination": "/x", "RW": True}]},
    {"Config": {**INSPECT["Config"], "Env": ["HOSTWATCH_JOURNAL_GID=102 --privileged"]}},
])
def test_a_value_that_could_be_read_as_another_option_is_refused_before_anything_runs(patch):
    with pytest.raises(ValueError):
        al.agent_run_argv({**INSPECT, **patch}, al.AGENT_IMAGE)


# --- the fake programs ------------------------------------------------------------------------

STUB = Path(__file__).with_name("fake_docker.py")


def _program(folder: Path, name: str) -> str:
    """A wrapper that runs the fake with this interpreter, as a .cmd on Windows and a shell script elsewhere."""
    if os.name == "nt":
        path = folder / f"{name}.cmd"
        path.write_text(f'@"{sys.executable}" "{STUB}" {name} %*\r\n', encoding="ascii")
    else:
        path = folder / name
        path.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{STUB}" {name} "$@"\n', encoding="ascii")
        path.chmod(0o755)
    return str(path)


class Fake:
    def __init__(self, folder: Path, monkeypatch):
        self.state_path = folder / "state.json"
        monkeypatch.setenv("HOSTWATCH_FAKE_STATE", str(self.state_path))
        self.programs = {name: _program(folder, name) for name in ("docker", "pip", "python", "systemd-run")}
        monkeypatch.setattr(al, "DOCKER", self.programs["docker"])
        monkeypatch.setattr(al, "CONTROL_PIP", self.programs["pip"])
        monkeypatch.setattr(al, "CONTROL_PYTHON", self.programs["python"])
        monkeypatch.setattr(al, "SYSTEMD_RUN", self.programs["systemd-run"])
        monkeypatch.setattr(al, "UPDATE_SETTLE_S", 0.0)
        self.set(scenario={"pull": "unchanged"})

    def set(self, scenario, containers=None, images=None):
        if containers is None:
            containers = {"hostwatch-agent": json.loads(json.dumps(INSPECT))}
        if images is None:
            images = {al.AGENT_IMAGE: {"Id": OLD_ID, "Config": {"Labels": {al.VERSION_LABEL: "0.1.0"}}}}
        self.state_path.write_text(json.dumps({"scenario": scenario, "containers": containers, "images": images,
                                               "calls": []}), encoding="utf-8")

    def state(self) -> dict:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def calls(self) -> list[list[str]]:
        return self.state()["calls"]

    def docker_calls(self) -> list[list[str]]:
        return [c[1:] for c in self.calls() if c[0] == "docker"]


@pytest.fixture
def fake(tmp_path, monkeypatch):
    return Fake(tmp_path, monkeypatch)


def actions(cfg=None, **kw):
    return al.LinuxActions(cfg or both(), use_sudo=False, sleep=lambda s: None, **kw)


def run(component="agent", cfg=None):
    return actions(cfg).execute({"action": "agent.update", "params": {"component": component}})


def body(result) -> dict:
    data = json.loads(result.output)
    assert set(data) == {"component", "old_image_id", "new_image_id", "old_version", "new_version", "note"}
    assert len(result.output) < 2000
    return data


# --- the container flow ---------------------------------------------------------------------

def test_an_unchanged_image_is_reported_done_and_already_current_without_touching_the_container(fake):
    result = run()
    assert result.ok and result.status == "done" and result.after_report is None
    data = body(result)
    assert data == {"component": "agent", "old_image_id": "sha256:aaaaaaaaaaaa", "new_image_id": "sha256:aaaaaaaaaaaa",
                    "old_version": "0.1.0", "new_version": "0.1.0", "note": "already current"}
    assert fake.docker_calls() == [["inspect", "--type", "container", "hostwatch-agent"],
                                   ["pull", al.AGENT_IMAGE], ["image", "inspect", al.AGENT_IMAGE]]
    assert fake.state()["containers"]["hostwatch-agent"]["State"]["Running"] is True


def test_a_changed_image_recreates_the_container_with_the_installers_arguments_and_removes_the_old_one(fake):
    fake.set({"pull": "changed", "pulled_id": NEW_ID, "pulled_labels": {al.VERSION_LABEL: "0.2.0"}})
    result = run()
    assert result.ok and result.status == "done"
    data = body(result)
    assert data["old_image_id"] == "sha256:aaaaaaaaaaaa" and data["new_image_id"] == "sha256:bbbbbbbbbbbb"
    assert data["old_version"] == "0.1.0" and data["new_version"] == "0.2.0"
    assert data["note"] == "container recreated from the new image"
    calls = fake.docker_calls()
    run_call = next(c for c in calls if c[0] == "run")
    assert run_call == RUN_ARGV[1:]
    assert calls == [["inspect", "--type", "container", "hostwatch-agent"], ["pull", al.AGENT_IMAGE],
                     ["image", "inspect", al.AGENT_IMAGE], ["rm", "-f", "hostwatch-agent-prev"],
                     ["stop", "hostwatch-agent"], ["rename", "hostwatch-agent", "hostwatch-agent-prev"], run_call,
                     ["inspect", "--type", "container", "hostwatch-agent"], ["rm", "-f", "hostwatch-agent-prev"]]
    containers = fake.state()["containers"]
    assert set(containers) == {"hostwatch-agent"}
    assert containers["hostwatch-agent"]["Image"] == NEW_ID and containers["hostwatch-agent"]["State"]["Running"]
    assert INGEST_KEY not in result.output


def test_handling_the_update_twice_is_harmless_because_the_second_run_sees_already_current(fake):
    fake.set({"pull": "changed", "pulled_id": NEW_ID})
    assert body(run())["note"] == "container recreated from the new image"
    again = run()
    assert again.ok and body(again)["note"] == "already current"
    assert body(again)["old_image_id"] == body(again)["new_image_id"] == "sha256:bbbbbbbbbbbb"
    assert [c for c in fake.docker_calls() if c[0] in ("stop", "rename", "run")] == [
        ["stop", "hostwatch-agent"], ["rename", "hostwatch-agent", "hostwatch-agent-prev"],
        next(c for c in fake.docker_calls() if c[0] == "run")]


@pytest.mark.parametrize("scenario, reason", [("fail", "did not start"), ("exits", "exited right after starting")])
def test_a_new_container_that_does_not_run_is_removed_and_the_old_one_is_put_back(fake, scenario, reason):
    fake.set({"pull": "changed", "pulled_id": NEW_ID, "run": scenario})
    result = run()
    assert not result.ok and result.status == "failed"
    data = body(result)
    assert reason in data["note"] and "the old container was put back and is running" in data["note"]
    assert data["old_image_id"] == "sha256:aaaaaaaaaaaa" and data["new_image_id"] == "sha256:bbbbbbbbbbbb"
    calls = fake.docker_calls()
    assert calls[-3:] == [["rm", "-f", "hostwatch-agent"], ["rename", "hostwatch-agent-prev", "hostwatch-agent"],
                          ["start", "hostwatch-agent"]]
    containers = fake.state()["containers"]
    assert set(containers) == {"hostwatch-agent"}
    assert containers["hostwatch-agent"]["Image"] == OLD_ID and containers["hostwatch-agent"]["State"]["Running"]


def test_a_rollback_whose_start_fails_says_so_instead_of_claiming_the_agent_runs(fake):
    fake.set({"pull": "changed", "pulled_id": NEW_ID, "run": "fail", "start_prev": "fail"})
    data = body(run())
    assert "renamed back but did not start" in data["note"]
    containers = fake.state()["containers"]
    assert set(containers) == {"hostwatch-agent"} and containers["hostwatch-agent"]["State"]["Running"] is False


def test_a_failed_pull_leaves_the_running_agent_untouched(fake):
    fake.set({"pull": "fail"})
    result = run()
    assert not result.ok and result.status == "failed"
    data = body(result)
    assert "docker pull" in data["note"] and "not touched" in data["note"] and "manifest" in data["note"]
    assert data["old_image_id"] == "sha256:aaaaaaaaaaaa" and data["new_image_id"] is None
    assert [c[0] for c in fake.docker_calls()] == ["inspect", "pull"]
    assert fake.state()["containers"]["hostwatch-agent"]["State"]["Running"] is True


def test_a_pull_that_hangs_is_cut_off_by_the_timeout_and_reported_failed(fake, monkeypatch):
    monkeypatch.setattr(al, "UPDATE_PULL_TIMEOUT_S", 1.0)
    fake.set({"pull": "hang", "hang_s": 6})
    result = run()
    assert not result.ok and "TimeoutExpired" in body(result)["note"]
    assert [c[0] for c in fake.docker_calls()] == ["inspect", "pull"]
    assert fake.state()["containers"]["hostwatch-agent"]["State"]["Running"] is True


def test_the_pull_and_start_timeouts_are_the_contract_values_and_the_runner_gets_them(monkeypatch):
    assert al.UPDATE_PULL_TIMEOUT_S == 600.0 and al.UPDATE_START_TIMEOUT_S == 60.0
    seen = []

    def runner(argv, timeout):
        seen.append((argv[1] if len(argv) > 1 else argv[0], timeout))
        if argv[1:4] == ["inspect", "--type", "container"]:
            return al.RunResult(0, json.dumps([INSPECT]))
        if argv[1] == "image":
            return al.RunResult(0, json.dumps([{"Id": NEW_ID, "Config": {"Labels": {}}}]))
        return al.RunResult(0, "ok")

    actions(runner=runner).agent_update("agent")
    by_sub = {sub: t for sub, t in seen}
    assert by_sub["pull"] == 600.0 and by_sub["run"] == 60.0 and by_sub["stop"] == 120.0


def test_no_container_or_a_container_from_another_image_fails_before_any_pull(fake):
    fake.set({"pull": "changed", "pulled_id": NEW_ID}, containers={})
    data = body(run())
    assert "no hostwatch-agent container" in data["note"] and [c[0] for c in fake.docker_calls()] == ["inspect"]
    other = json.loads(json.dumps(INSPECT))
    other["Config"]["Image"] = "ghcr.io/someone/else:latest"
    fake.set({"pull": "changed", "pulled_id": NEW_ID}, containers={"hostwatch-agent": other})
    data = body(run())
    assert "ghcr.io/someone/else:latest" in data["note"] and "not touched" in data["note"]
    assert [c[0] for c in fake.docker_calls()] == ["inspect"]


def test_a_container_created_from_an_image_id_falls_back_to_the_fixed_image(fake):
    by_id = json.loads(json.dumps(INSPECT))
    by_id["Config"]["Image"] = OLD_ID
    fake.set({"pull": "unchanged"}, containers={"hostwatch-agent": by_id})
    data = body(run())
    assert data["note"].startswith("the running container was not created from a repository tag")
    assert ["pull", al.AGENT_IMAGE] in fake.docker_calls()


def test_a_leftover_prev_container_from_an_earlier_failure_is_removed_first(fake):
    prev = json.loads(json.dumps(INSPECT))
    prev["Name"] = "/hostwatch-agent-prev"
    fake.set({"pull": "changed", "pulled_id": NEW_ID},
             containers={"hostwatch-agent": json.loads(json.dumps(INSPECT)), "hostwatch-agent-prev": prev})
    assert run().ok
    assert set(fake.state()["containers"]) == {"hostwatch-agent"}


# --- the daemon flow ------------------------------------------------------------------------

def test_a_control_update_runs_pip_then_hands_back_the_restart_to_run_after_the_result_is_reported(fake, monkeypatch):
    monkeypatch.setattr(installed, "describe", lambda: "0.1.0 (82e1564a0000)")
    fake.set({"pip": "ok", "pip_version": "0.2.0 (c9f10270b1d2)"})
    result = run("control")
    assert result.ok and result.status == "done" and callable(result.after_report)
    data = body(result)
    assert data == {"component": "control", "old_image_id": None, "new_image_id": None,
                    "old_version": "0.1.0 (82e1564a0000)", "new_version": "0.2.0 (c9f10270b1d2)",
                    "note": "control installed; the service restarts 5 s after this result is reported"}
    assert fake.calls() == [["pip", "install", "--quiet", "--upgrade", al.CONTROL_SPEC],
                            ["python", "-m", "hostwatch.control.installed"]]
    assert fake.state().get("restart_scheduled") is None, "nothing restarts before the result is reported"
    outcome = result.after_report()
    assert outcome.returncode == 0
    assert fake.state()["restart_scheduled"] == ["--on-active=5", al.SYSTEMCTL, "restart", "hostwatch-control"]
    assert fake.calls()[-1] == ["systemd-run", "--on-active=5", al.SYSTEMCTL, "restart", "hostwatch-control"]


def test_a_failed_pip_install_is_reported_failed_and_schedules_no_restart(fake, monkeypatch):
    monkeypatch.setattr(installed, "describe", lambda: "0.1.0")
    fake.set({"pip": "fail"})
    result = run("control")
    assert not result.ok and result.status == "failed" and result.after_report is None
    data = body(result)
    assert "pip install failed" in data["note"] and "OSError" in data["note"]
    assert data["old_version"] == "0.1.0" and data["new_version"] is None
    assert [c[0] for c in fake.calls()] == ["pip"]


def test_without_systemd_run_the_control_update_fails_before_pip_runs(fake, monkeypatch, tmp_path):
    monkeypatch.setattr(al, "SYSTEMD_RUN", str(tmp_path / "missing" / "systemd-run"))
    result = run("control")
    assert not result.ok and result.status == "failed" and result.after_report is None
    assert "systemd-run is not available" in body(result)["note"]
    assert fake.calls() == []


def test_all_updates_the_container_then_the_daemon_and_reports_both(fake, monkeypatch):
    monkeypatch.setattr(installed, "describe", lambda: "0.1.0")
    fake.set({"pull": "changed", "pulled_id": NEW_ID, "pulled_labels": {al.VERSION_LABEL: "0.2.0"},
              "pip": "ok", "pip_version": "0.2.0"})
    result = run("all")
    assert result.ok and callable(result.after_report)
    data = body(result)
    assert data["component"] == "all" and data["new_image_id"] == "sha256:bbbbbbbbbbbb"
    assert data["old_version"] == "agent 0.1.0; control 0.1.0" and data["new_version"] == "agent 0.2.0; control 0.2.0"
    assert "container recreated" in data["note"] and "control installed" in data["note"]
    programs = [c[0] for c in fake.calls()]
    assert programs.index("pip") > programs.index("docker") and "systemd-run" not in programs


def test_all_stops_after_a_failed_container_update_and_leaves_the_daemon_alone(fake):
    fake.set({"pull": "fail", "pip": "ok"})
    result = run("all")
    assert not result.ok and result.after_report is None
    assert [c[0] for c in fake.calls()] == ["docker", "docker"]
    assert body(result)["component"] == "all"


# --- refusals, privilege and output -----------------------------------------------------------

@pytest.mark.parametrize("component", ["hub", None, 1, "", "Agent"])
def test_an_unknown_component_is_refused_before_any_call(fake, component):
    result = actions().agent_update(component)
    assert result.status == "refused" and fake.calls() == []


@pytest.mark.parametrize("stanza, component, text", [
    ({}, "agent", "update.agent is false"), ({"agent": True}, "control", "update.control is false"),
    ({}, "all", "update.agent and update.control are false")])
def test_the_executor_refuses_what_the_stanza_does_not_allow_even_if_the_verifier_let_it_through(fake, stanza, component, text):
    result = actions(config(update=stanza)).agent_update(component)
    assert result.status == "refused" and result.output == text and fake.calls() == []


def test_privileged_steps_go_through_sudo_but_the_version_probe_does_not(monkeypatch):
    monkeypatch.setattr(al, "SYSTEMD_RUN", sys.executable)  # any file that exists; the fake runner records it
    seen = []

    def runner(argv, timeout):
        seen.append(list(argv))
        if argv[-3:] == ["inspect", "--type", "container"] or argv[-4:-1] == ["inspect", "--type", "container"]:
            return al.RunResult(0, json.dumps([INSPECT]))
        if "image" in argv:
            return al.RunResult(0, json.dumps([{"Id": OLD_ID, "Config": {}}]))
        return al.RunResult(0, "0.2.0" if argv[0] == al.CONTROL_PYTHON else "ok")

    acts = al.LinuxActions(both(), runner, use_sudo=True, sleep=lambda s: None)
    result = acts.agent_update("all")
    assert result.ok
    result.after_report()
    for call in seen:
        if call[0] == al.CONTROL_PYTHON:
            assert call == [al.CONTROL_PYTHON, "-m", "hostwatch.control.installed"]
        else:
            assert call[:2] == ["sudo", "-n"], call


def test_every_privileged_call_of_the_update_flows_matches_a_rendered_sudoers_rule(fake, monkeypatch):
    monkeypatch.setattr(installed, "describe", lambda: "0.1.0")
    cfg = both()
    rules = [_as_fnmatch(r) for r in AGENT_RULES + CONTROL_RULES]  # rendered from the real paths
    fake.set({"pull": "changed", "pulled_id": NEW_ID, "run": "fail", "pip": "ok", "pip_version": "0.2.0"})
    run("agent", cfg)  # the rollback path
    fake.set({"pull": "changed", "pulled_id": NEW_ID, "pip": "ok", "pip_version": "0.2.0"})
    result = run("all", cfg)
    result.after_report()
    real = {"docker": "/usr/bin/docker", "pip": "/opt/hostwatch-control/venv/bin/pip",
            "systemd-run": "/usr/bin/systemd-run"}
    for program, *args in fake.calls():
        if program == "python":
            continue  # unprivileged
        line = " ".join([real[program], *args])
        assert any(fnmatch.fnmatchcase(line, rule) for rule in rules), line


def test_the_result_note_is_masked_and_bounded_so_the_json_survives_both_redactions():
    report = al.UpdateReport("agent")
    report.old_image_id = al.short_image_id(OLD_ID)
    report.fail(f"docker said: token={INGEST_KEY} " + "x" * 5000)
    result = report.result(False)
    data = json.loads(result.output)
    assert INGEST_KEY not in result.output and "[redacted]" in data["note"]
    assert data["note"].endswith("...[truncated]") and len(result.output) < 2000
    assert al.redact(result.output) == result.output.strip()  # the daemon's own pass changes nothing more
    assert al.short_image_id(OLD_ID) == "sha256:aaaaaaaaaaaa" and al.short_image_id("abc") == "abc"


def test_the_short_image_id_is_not_masked_by_the_hex_run_rule():
    assert al.redact("old sha256:aaaaaaaaaaaa new sha256:bbbbbbbbbbbb") == "old sha256:aaaaaaaaaaaa new sha256:bbbbbbbbbbbb"
    assert "[redacted]" in al.redact("old " + OLD_ID)


def test_installed_describe_reads_the_version_and_the_recorded_commit(monkeypatch):
    class Dist:
        version = "1.2.3"

        def __init__(self, direct):
            self.direct = direct

        def read_text(self, name):
            return self.direct if name == "direct_url.json" else None

    monkeypatch.setattr(installed.importlib.metadata, "distribution",
                        lambda name: Dist(json.dumps({"url": "https://github.com/trooperthorn/hostwatch.git",
                                                      "vcs_info": {"vcs": "git", "commit_id": "c9f10270b1d2e3f4"}})))
    assert installed.describe() == "1.2.3 (c9f10270b1d2)"
    monkeypatch.setattr(installed.importlib.metadata, "distribution", lambda name: Dist(None))
    assert installed.describe() == "1.2.3"
    monkeypatch.setattr(installed.importlib.metadata, "distribution", lambda name: Dist("not json"))
    assert installed.describe() == "1.2.3"

    def missing(name):
        raise installed.importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(installed.importlib.metadata, "distribution", missing)
    assert installed.describe() is None


def test_the_windows_executor_refuses_the_action_with_a_plain_reason():
    cfg = cfgmod.parse({**BASE, "update": {"agent": True, "control": True}})
    calls = []

    class Runner:
        def run(self, args, timeout_s):
            calls.append(args)
            raise AssertionError("nothing may run")

    acts = aw.WindowsActions(cfg, Runner(), pipe=object())
    for component in ("agent", "control", "all"):
        result = acts.execute({"action": "agent.update", "params": {"component": component}})
        assert result.status == "refused" and "not supported on Windows" in result.output
    assert acts.execute({"action": "agent.update", "params": {"component": "hub"}}).status == "refused"
    assert calls == []
