"""hostwatch-control pull loop, results outbox, entry point, service files and import isolation.

A fake watchpost (an httpx mock transport) serves the pull route and takes results. Commands are
signed with a throwaway key made in the test. Executors are fakes or the real Linux executor with a
fake runner, so nothing here runs a program, opens a socket or touches a real service.
"""

from __future__ import annotations

import ast
import base64
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from hostwatch import cli  # noqa: E402
from hostwatch.config import Config  # noqa: E402
from hostwatch.control import config as cfgmod  # noqa: E402
from hostwatch.control import daemon as d  # noqa: E402
from hostwatch.control import service as csvc  # noqa: E402
from hostwatch.control import verify as v  # noqa: E402
from hostwatch.control.actions_linux import ActionResult, LinuxActions, RunResult  # noqa: E402
from hostwatch.control.outbox import ResultOutbox  # noqa: E402
from hostwatch.control.signing import canonical_json  # noqa: E402
from hostwatch.control.state import STATE_FILE  # noqa: E402
from test_control_verify import HOST, NOW, TOML, make_cmd, pub_text, sign  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
URL = "http://watchpost.test"
KEY = "wpc_" + "k3yvalue" * 4


@pytest.fixture
def signer():
    return Ed25519PrivateKey.generate()


class FakeWatchpost:
    """The pull route and the results route. `online` and `results_ok` switch failures on and off."""

    def __init__(self):
        self.queue: list[dict] = []
        self.results: list[dict] = []
        self.attempts: list[dict] = []
        self.requests: list[httpx.Request] = []
        self.online = True
        self.results_status = 200
        self.pull_status = 200
        self.on_request = None

    def add(self, signer, **over):
        cmd = make_cmd(**over)
        self.queue.append({"command": cmd, "signature": sign(signer, cmd)})
        return cmd

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.on_request:
            self.on_request(request)
        if not self.online:
            raise httpx.ConnectError("watchpost is down", request=request)
        if request.headers.get("authorization") != f"Bearer {KEY}":
            return httpx.Response(401)
        if request.method == "GET" and request.url.path == d.COMMANDS_PATH:
            assert request.url.params["host"] == HOST
            if self.pull_status != 200:
                return httpx.Response(self.pull_status)
            return httpx.Response(200, json={"host": HOST, "commands": list(self.queue)})
        if request.method == "POST" and request.url.path == d.RESULTS_PATH:
            body = json.loads(request.content)
            self.attempts.append(body)
            status = self.results_status(body) if callable(self.results_status) else self.results_status
            if status != 200:
                return httpx.Response(status)
            self.results.append(body)
            self.queue = [i for i in self.queue if i["command"]["id"] != body["id"]]
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


class FakeExecutor:
    def __init__(self, result=None, error=None):
        self.calls, self.result, self.error = [], result or ActionResult(True, "done", "ok"), error

    def execute(self, command):
        self.calls.append(command)
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def env(tmp_path, signer):
    cfg_path = tmp_path / "control.toml"
    cfg_path.write_text(TOML.format(key=pub_text(signer)), encoding="utf-8")
    if os.name == "posix":
        cfg_path.chmod(0o644)
    data = tmp_path / "data"
    settings = d.Settings(URL, KEY, cfg_path, data, 5.0)
    wp = FakeWatchpost()

    class Env:
        pass

    e = Env()
    e.settings, e.wp, e.data, e.signer = settings, wp, data, signer

    def build(actions=None, wp_=None):
        w = wp_ or wp
        return d.build_daemon(settings, client=w.client(), actions=actions or FakeExecutor(), clock=lambda: NOW)

    e.build = build
    return e


# --- pull, verify, execute, report --------------------------------------------------------

def test_a_command_is_pulled_verified_executed_and_its_result_posted(env, tmp_path):
    ran = []

    def runner(argv, timeout):
        ran.append(list(argv))
        return RunResult(0, "restarted")

    actions = LinuxActions(cfgmod.load(env.settings.config_path), runner, use_sudo=False,
                           overrides_path=tmp_path / "overrides.toml")
    cmd = env.wp.add(env.signer, action="service.restart", params={"name": "hostwatch-agent"})
    daemon = env.build(actions)
    daemon.cycle()
    assert ran == [["/usr/bin/systemctl", "restart", "hostwatch-agent"]]
    assert len(env.wp.results) == 1
    result = env.wp.results[0]
    assert result["id"] == cmd["id"] and result["host"] == HOST and result["action"] == "service.restart"
    assert result["status"] == "done" and result["ok"] is True and result["reason"] == ""
    assert result["output"] == "restarted" and result["seq"] == cmd["seq"]
    assert result["received_at"] <= result["started_at"] <= result["finished_at"]
    pull = env.wp.requests[0]
    assert pull.method == "GET" and pull.url.path == d.COMMANDS_PATH and pull.headers["authorization"] == f"Bearer {KEY}"
    assert daemon.outbox.depth() == 0


def test_a_fan_command_writes_overrides_through_the_real_executor_with_a_fake_runner(env, tmp_path):
    ran = []
    actions = LinuxActions(cfgmod.load(env.settings.config_path),
                           lambda argv, timeout: ran.append(list(argv)) or RunResult(0, "ok"),
                           use_sudo=False, overrides_path=tmp_path / "overrides.toml")
    env.wp.add(env.signer)
    env.build(actions).cycle()
    assert env.wp.results[0]["status"] == "done"
    assert "min_duty = 25" in (tmp_path / "overrides.toml").read_text(encoding="utf-8")
    assert any(a[:2] == ["/opt/thermalctl/venv/bin/thermalctl", "check-config"] for a in ran)


def test_commands_run_one_at_a_time_in_seq_order(env):
    exe = FakeExecutor()
    env.wp.add(env.signer, id="b", seq=2, action="host.reboot", params={})
    env.wp.add(env.signer, id="a", seq=1, action="service.restart", params={"name": "hostwatch-agent"})
    env.build(exe).cycle()
    assert [c["id"] for c in exe.calls] == ["a", "b"]
    assert [r["id"] for r in env.wp.results] == ["a", "b"]
    posts = [r for r in env.wp.requests if r.method == "POST"]
    assert len(posts) == 2  # each result is delivered before the next command starts


def test_an_executor_that_raises_is_reported_failed_and_the_next_command_still_runs(env):
    class Flaky(FakeExecutor):
        def execute(self, command):
            self.calls.append(command)
            if command["id"] == "a":
                raise RuntimeError("boom")
            return ActionResult(True, "done", "fine")

    exe = Flaky()
    env.wp.add(env.signer, id="a", seq=1, action="service.restart", params={"name": "hostwatch-agent"})
    env.wp.add(env.signer, id="b", seq=2, action="service.restart", params={"name": "hostwatch-agent"})
    env.build(exe).cycle()
    by_id = {r["id"]: r for r in env.wp.results}
    assert by_id["a"]["status"] == "failed" and by_id["a"]["reason"] == "action_failed" and "boom" in by_id["a"]["output"]
    assert by_id["b"]["status"] == "done"


def test_a_failed_action_reports_its_output_and_reason(env):
    exe = FakeExecutor(ActionResult(False, "failed", "check-config rejected the overrides"))
    env.wp.add(env.signer)
    env.build(exe).cycle()
    r = env.wp.results[0]
    assert (r["status"], r["ok"], r["reason"]) == ("failed", False, "action_failed")
    assert "rejected" in r["output"]


# --- refusals -----------------------------------------------------------------------------

def _refusal_cases(signer):
    good = make_cmd(action="service.restart", params={"name": "hostwatch-agent"})
    forged = {"command": good, "signature": sign(Ed25519PrivateKey.generate(), good)}
    other_host = make_cmd(host="Other-Host")
    expired = make_cmd(expires_at=NOW - 500)
    return [
        ("bad_signature", forged),
        ("wrong_host", {"command": other_host, "signature": sign(signer, other_host)}),
        ("expired", {"command": expired, "signature": sign(signer, expired)}),
        ("unit_not_allowed", None),
        ("header_not_allowed", None),
        ("floor_below_min", None),  # these three are built from parameters in the test
    ]


@pytest.mark.parametrize("reason", ["bad_signature", "wrong_host", "expired", "unit_not_allowed",
                                    "header_not_allowed", "floor_below_min"])
def test_a_refused_command_is_not_run_and_reports_its_reason(env, reason):
    item = dict(_refusal_cases(env.signer))[reason]
    if item is None:
        over = {"unit_not_allowed": dict(action="service.restart", params={"name": "sshd"}),
                "header_not_allowed": dict(params={"controller": "thermalctl", "header": "pwm9", "min_duty": 30}),
                "floor_below_min": dict(params={"controller": "thermalctl", "header": "pwm1", "min_duty": 5})}[reason]
        env.wp.add(env.signer, **over)
    else:
        env.wp.queue.append(item)
    exe = FakeExecutor()
    env.build(exe).cycle()
    assert exe.calls == []
    assert len(env.wp.results) == 1
    r = env.wp.results[0]
    assert (r["status"], r["ok"], r["reason"]) == ("refused", False, reason)
    assert r["id"]


def test_a_replayed_command_is_refused_and_the_state_survives_a_restart(env):
    exe = FakeExecutor()
    cmd = env.wp.add(env.signer, action="service.restart", params={"name": "hostwatch-agent"})
    first = env.build(exe)
    first.cycle()
    first.close()
    env.wp.queue.append({"command": cmd, "signature": sign(env.signer, cmd)})
    second = env.build(exe)
    second.cycle()
    assert len(exe.calls) == 1
    assert [r["status"] for r in env.wp.results] == ["done", "refused"]
    assert env.wp.results[1]["reason"] == "replayed_id"


def test_a_replay_refusal_never_hides_a_result_that_is_still_queued(env):
    exe = FakeExecutor()
    cmd = env.wp.add(env.signer, action="service.restart", params={"name": "hostwatch-agent"})
    env.wp.results_status = 503
    daemon = env.build(exe)
    with pytest.raises(d.DeliveryError):
        daemon.cycle()
    with pytest.raises(d.DeliveryError):
        daemon.cycle()  # the queue still holds the command, so it is pulled again and refused as a replay
    assert len(exe.calls) == 1 and daemon.outbox.depth() == 1
    env.wp.results_status = 200
    daemon.cycle()
    assert [r["status"] for r in env.wp.results] == ["done"] and env.wp.results[0]["id"] == cmd["id"]


def test_a_pulled_item_without_an_id_is_ignored(env):
    env.wp.queue.append({"command": {"action": "host.reboot"}, "signature": "AA=="})
    env.wp.queue.append("not an object")
    exe = FakeExecutor()
    env.build(exe).cycle()
    assert exe.calls == [] and env.wp.results == []


def test_an_unreadable_state_file_refuses_every_command(env):
    env.data.mkdir(parents=True)
    (env.data / STATE_FILE).write_text("{not json", encoding="utf-8")
    exe = FakeExecutor()
    env.wp.add(env.signer, action="service.restart", params={"name": "hostwatch-agent"})
    env.build(exe).cycle()
    assert exe.calls == [] and env.wp.results[0]["reason"] == v.STATE_UNAVAILABLE


# --- offline results ----------------------------------------------------------------------

def test_results_posted_while_offline_are_replayed_after_a_restart(env):
    exe = FakeExecutor()
    cmd = env.wp.add(env.signer, action="service.restart", params={"name": "hostwatch-agent"})

    def drop_results(request):
        if request.method == "POST":
            env.wp.online = False

    env.wp.on_request = drop_results
    first = env.build(exe)
    with pytest.raises(d.DeliveryError):
        first.cycle()
    assert env.wp.results == [] and first.outbox.depth() == 1 and len(exe.calls) == 1
    first.close()

    env.wp.on_request, env.wp.online = None, True
    env.wp.queue.clear()
    second = env.build(exe)  # a new process: new verifier, new outbox object, same files
    assert second.outbox.depth() == 1
    second.cycle()
    assert [r["id"] for r in env.wp.results] == [cmd["id"]] and env.wp.results[0]["status"] == "done"
    assert second.outbox.depth() == 0 and len(exe.calls) == 1


@pytest.mark.parametrize("status", [401, 403, 404, 408, 425, 429, 500, 503])
def test_results_stay_queued_when_the_route_is_missing_or_the_failure_may_pass(env, status):
    exe = FakeExecutor()
    env.wp.add(env.signer, id="a", seq=1, action="service.restart", params={"name": "hostwatch-agent"})
    env.wp.results_status = status
    daemon = env.build(exe)
    with pytest.raises(d.DeliveryError):
        daemon.cycle()
    assert daemon.outbox.depth() == 1 and daemon.outbox.parked() == [] and len(exe.calls) == 1


@pytest.mark.parametrize("status", [400, 413, 422])
def test_a_permanent_4xx_parks_the_result_with_its_reason_and_the_next_one_is_delivered(env, status):
    env.wp.add(env.signer, id="a", seq=1, action="service.restart", params={"name": "hostwatch-agent"})
    env.wp.add(env.signer, id="b", seq=2, action="service.restart", params={"name": "hostwatch-agent"})
    env.wp.results_status = lambda body: status if body["id"] == "a" else 200
    daemon = env.build(FakeExecutor())
    daemon.cycle()  # no DeliveryError: nothing is stuck
    assert [r["id"] for r in env.wp.results] == ["b"]
    assert daemon.outbox.depth() == 0
    assert daemon.outbox.parked() == [("a", f"watchpost answered HTTP {status}")]
    assert [r["id"] for r in env.wp.attempts] == ["a", "b"]  # the parked result is not sent again
    daemon.cycle()
    assert [r["id"] for r in env.wp.attempts] == ["a", "b"]


def test_a_parked_result_is_kept_across_a_restart_and_a_replay_does_not_requeue_it(env):
    first = env.build(FakeExecutor())
    first.outbox.add("a", {"id": "a", "status": "done"})
    first.outbox.park(first.outbox.peek()[0], "watchpost answered HTTP 422")
    first.close()
    second = env.build(FakeExecutor())
    assert second.outbox.parked() == [("a", "watchpost answered HTTP 422")]
    assert second.outbox.has("a")
    second.outbox.add("a", {"id": "a", "status": "refused"})
    assert second.outbox.depth() == 0


def test_a_409_means_watchpost_has_the_result_and_the_copy_is_dropped(env):
    env.wp.add(env.signer, id="a", seq=1, action="service.restart", params={"name": "hostwatch-agent"})
    env.wp.results_status = 409
    daemon = env.build(FakeExecutor())
    daemon.cycle()
    assert daemon.outbox.depth() == 0


def test_a_flush_error_is_not_replaced_by_a_pull_error(env):
    daemon = env.build(FakeExecutor())
    daemon.outbox.add("x", {"id": "x", "status": "done"})
    env.wp.results_status = 503
    env.wp.pull_status = 502
    with pytest.raises(d.DeliveryError, match="result post answered HTTP 503"):
        daemon.cycle()


def test_pull_failures_are_delivery_errors_and_the_key_is_never_logged(env, caplog):
    daemon = env.build()
    env.wp.pull_status = 403
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(d.DeliveryError, match="control key"):
            daemon.cycle()
        env.wp.pull_status, env.wp.online = 200, False
        with pytest.raises(d.DeliveryError, match="pull failed"):
            daemon.cycle()
    assert KEY not in caplog.text and KEY not in repr(env.settings)


def test_a_malformed_pull_answer_is_a_delivery_error(env):
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"commands": "no"})))
    daemon = d.build_daemon(env.settings, client=client, actions=FakeExecutor(), clock=lambda: NOW)
    with pytest.raises(d.DeliveryError, match="not a command list"):
        daemon.cycle()


# --- the loop -----------------------------------------------------------------------------

def test_run_polls_until_stopped_without_sleeping(env):
    daemon = env.build()
    env.wp.on_request = lambda request: daemon.stop() if request.method == "GET" else None
    daemon.run()
    assert [r.method for r in env.wp.requests] == ["GET"]


def test_run_backs_off_after_a_failure_and_keeps_going(env):
    daemon = env.build()
    env.wp.online = False
    env.wp.on_request = lambda request: daemon.stop()
    daemon.run()
    assert daemon._failures == 1 and daemon._backoff() == 10.0


class _RecordingEvent:
    """A stop event that records each wait and ends the loop after a set number of cycles."""

    def __init__(self, cycles):
        self.waits, self.cycles = [], cycles

    def is_set(self):
        return len(self.waits) >= self.cycles

    def set(self):
        self.cycles = 0

    def wait(self, seconds):
        self.waits.append(seconds)


def test_polling_stays_at_the_normal_interval_while_results_are_pending(env):
    daemon = env.build(FakeExecutor())
    daemon.outbox.add("a", {"id": "a", "status": "done"})
    env.wp.results_status = 503  # the result cannot be delivered, but pulls are answered
    daemon.stop_event = _RecordingEvent(cycles=4)
    daemon.run()
    assert daemon.outbox.depth() == 1
    assert len(daemon.stop_event.waits) == 4
    assert all(0 < w <= env.settings.interval_s for w in daemon.stop_event.waits)
    assert daemon._failures == 0
    assert [r.method for r in env.wp.requests].count("GET") == 4


def test_polling_still_backs_off_when_watchpost_cannot_be_reached_for_the_pull(env):
    daemon = env.build(FakeExecutor())
    daemon.outbox.add("a", {"id": "a", "status": "done"})
    env.wp.online = False
    daemon.stop_event = _RecordingEvent(cycles=3)
    daemon.run()
    assert daemon._failures == 3 and max(daemon.stop_event.waits) > env.settings.interval_s


def test_backoff_is_capped():
    s = d.Settings(URL, KEY, Path("x"), Path("y"), 5.0)
    daemon = d.ControlDaemon(s, None, None, None, None, None)
    daemon._failures = 50
    assert daemon._backoff() == d.MAX_BACKOFF_S


# --- redaction ----------------------------------------------------------------------------

PEM = ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n"
       "c2gtZWQyNTUxOQAAACAxyz\n-----END OPENSSH PRIVATE KEY-----")
B64 = "dGhpcyBpcyBhIHNlY3JldCB0aGF0IGlzIGxvbmcgZW5vdWdoIHRvIG1hdGNo0123Zx=="
HEX = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
SECRET_SHAPES = [
    ("wpc key", KEY, KEY),
    ("wpi key", "ingest wpi_0123456789abcdefXYZ here", "wpi_0123456789abcdefXYZ"),
    ("wpf key", "feed wpf_0123456789abcdefXYZ here", "wpf_0123456789abcdefXYZ"),
    ("hw key", "agent hw_0123456789abcdef here", "hw_0123456789abcdef"),
    ("bearer", "sent Bearer abc.def-ghi_jkl ok", "abc.def-ghi_jkl"),
    ("lowercase bearer", "sent bearer tok-en.v4lue ok", "tok-en.v4lue"),
    ("authorization header", "Authorization: Basic dXNlcjpwYXNz\nnext line", "dXNlcjpwYXNz"),
    ("authorization custom", "authorization=Token s3cretvalue", "s3cretvalue"),
    ("password pair", "login password=hunter2 done", "hunter2"),
    ("password quoted", 'login password="correct horse battery" done', "correct horse"),
    ("token pair", "api token: s3cr3tt0ken here", "s3cr3tt0ken"),
    ("token json", '{"token": "abc123def456"}', "abc123def456"),
    ("pem block", "key follows\n" + PEM + "\nafter", "c2gtZWQyNTUxOQAAACAxyz"),
    ("truncated pem", "key follows\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA", "MIIEowIBAAKCAQEA"),
    ("base64 run", "blob " + B64 + " end", B64[:40]),
    ("hex run", "digest " + HEX + " end", HEX),
]


@pytest.mark.parametrize("name, text, secret", SECRET_SHAPES, ids=[c[0] for c in SECRET_SHAPES])
def test_each_secret_shape_is_masked(name, text, secret):
    out = d.redact(text)
    assert secret not in out and "[redacted]" in out


def test_ordinary_output_is_not_masked():
    text = "restarted hostwatch-agent in /opt/hostwatch-control/venv/lib/python3.12/site-packages OK, pid 4242"
    assert d.redact(text) == text


def test_output_is_clipped():
    assert len(d.redact("x y " * 2000)) < 2100


def test_masking_happens_before_truncation_so_a_secret_at_the_cut_is_not_half_shown():
    from hostwatch.control import actions_linux as al
    secret = "wpc_" + "Ab3" * 12
    text = "x" * (2000 - 10) + " " + secret + " tail"
    assert "wpc_" not in d.redact(text) and "wpc_" not in al._clip(text)
    text = "y" * (2000 - 10) + " password=hunter2hunter2"
    assert "hunter" not in d.redact(text) and "hunter" not in al._clip(text)


def test_a_result_posted_to_watchpost_carries_masked_output(env):
    env.wp.add(env.signer, id="a", seq=1, action="service.restart", params={"name": "hostwatch-agent"})
    daemon = env.build(FakeExecutor(ActionResult(True, "done", f"ok {KEY} password=hunter2")))
    daemon.cycle()
    sent = env.wp.results[0]["output"]
    assert KEY not in sent and "hunter2" not in sent


# --- settings and entry point -------------------------------------------------------------

def _env(**over):
    base = {"HOSTWATCH_CONTROL_URL": URL + "/", "HOSTWATCH_CONTROL_KEY": KEY}
    base.update(over)
    return {k: v_ for k, v_ in base.items() if v_ is not None}


def test_settings_load_with_platform_defaults():
    s = d.load_settings(_env(), platform="linux")
    assert s.url == URL and s.interval_s == 5.0 and s.data_dir == d.LINUX_DATA_DIR and s.config_path == d.LINUX_CONFIG
    w = d.load_settings(_env(), platform="win32")
    assert w.data_dir == d.WINDOWS_DATA_DIR and w.config_path == d.WINDOWS_DATA_DIR / "control.toml"


@pytest.mark.parametrize("over,message", [
    ({"HOSTWATCH_CONTROL_URL": None}, "HOSTWATCH_CONTROL_URL"),
    ({"HOSTWATCH_CONTROL_URL": "watchpost.test"}, "HOSTWATCH_CONTROL_URL"),
    ({"HOSTWATCH_CONTROL_KEY": None}, "HOSTWATCH_CONTROL_KEY"),
    ({"HOSTWATCH_CONTROL_KEY": "wpi_" + "x" * 20}, "HOSTWATCH_CONTROL_KEY"),
    ({"HOSTWATCH_CONTROL_KEY": "wpc_"}, "HOSTWATCH_CONTROL_KEY"),
    ({"HOSTWATCH_CONTROL_INTERVAL_S": "1"}, "INTERVAL"),
    ({"HOSTWATCH_CONTROL_INTERVAL_S": "999"}, "INTERVAL"),
    ({"HOSTWATCH_CONTROL_INTERVAL_S": "fast"}, "INTERVAL"),
])
def test_settings_reject_bad_values_without_echoing_the_key(over, message):
    with pytest.raises(d.SettingsError, match=message) as info:
        d.load_settings(_env(**over), platform="linux")
    assert KEY not in str(info.value)


def test_build_daemon_refuses_a_writable_allowlist(env):
    if os.name != "posix":
        pytest.skip("permission bits are only enforced on POSIX")
    env.settings.config_path.chmod(0o666)
    with pytest.raises(d.SettingsError, match="writable"):
        env.build()


def test_build_daemon_refuses_a_missing_allowlist(env, tmp_path):
    settings = d.Settings(URL, KEY, tmp_path / "missing.toml", env.data)
    with pytest.raises(d.SettingsError, match="cannot read"):
        d.build_daemon(settings, client=env.wp.client())


def test_run_foreground_reports_a_settings_error_and_runs_a_built_daemon(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "environ", {})
    assert d.run_foreground(None, str(tmp_path)) == 1
    assert "HOSTWATCH_CONTROL_URL" in capsys.readouterr().err

    monkeypatch.setattr(os, "environ", {"HOSTWATCH_CONTROL_URL": URL, "HOSTWATCH_CONTROL_KEY": KEY})
    ran = []

    class Fake:
        def run(self):
            ran.append("run")

        def stop(self):
            ran.append("stop")

        def close(self):
            ran.append("close")

    assert d.run_foreground(None, str(tmp_path), None, daemon_factory=lambda s: ran.append(s.data_dir) or Fake()) == 0
    assert ran == [tmp_path, "run", "close"]


def test_env_file_seeds_settings_without_overriding_the_environment(tmp_path, monkeypatch):
    (tmp_path / d.ENV_FILE_NAME).write_text(f"HOSTWATCH_CONTROL_URL={URL}\nHOSTWATCH_CONTROL_KEY={KEY}\n", encoding="utf-8")
    monkeypatch.setattr(os, "environ", {"HOSTWATCH_CONTROL_URL": "http://other.test"})
    s = d.settings_from_files(tmp_path)
    assert s.url == "http://other.test" and s.key == KEY and s.data_dir == tmp_path


def test_the_cli_routes_control_commands_to_the_daemon_module(monkeypatch):
    seen = []
    monkeypatch.setattr(d, "run_foreground", lambda *a: seen.append(("run", a)) or 0)
    monkeypatch.setattr(d, "run_cancel", lambda *a: seen.append(("cancel", a)) or 0)
    assert cli.run(["control", "run", "--config", "c.toml", "--data-dir", "dd", "--env-file", "e"], Config()) == 0
    assert cli.run(["control", "cancel", "--config", "c.toml"], Config()) == 0
    assert seen == [("run", ("c.toml", "dd", "e")), ("cancel", ("c.toml",))]
    assert "control" in cli.COMMANDS


def test_cancel_runs_the_executor_cancel(env, capsys):
    class A:
        def cancel_reboot(self):
            return ActionResult(True, "cancelled", "scheduled reboot cancelled")

    assert d.run_cancel(str(env.settings.config_path), lambda cfg: A()) == 0
    assert "cancelled" in capsys.readouterr().out
    assert d.run_cancel(str(env.settings.config_path.with_name("none.toml"))) == 1


# --- the results outbox -------------------------------------------------------------------

def test_outbox_survives_reopening_and_keeps_the_first_result_per_command(tmp_path):
    path = tmp_path / "o.db"
    box = ResultOutbox(path)
    box.add("a", {"id": "a", "status": "done"})
    box.add("a", {"id": "a", "status": "refused"})
    box.add("b", {"id": "b"})
    box.close()
    again = ResultOutbox(path)
    assert again.depth() == 2 and again.has("a") and not again.has("c")
    seq, payload = again.peek()
    assert payload["status"] == "done"
    again.ack(seq)
    assert again.peek()[1]["id"] == "b"


def test_a_real_result_replaces_a_queued_refusal_but_not_another_real_result(tmp_path):
    box = ResultOutbox(tmp_path / "o.db")
    box.add("a", {"id": "a", "status": "refused"})
    box.add("a", {"id": "a", "status": "done"})
    box.add("a", {"id": "a", "status": "failed"})
    box.add("b", {"id": "b", "status": "done"})
    box.add("b", {"id": "b", "status": "refused"})
    assert box.depth() == 2
    assert box.peek()[1]["status"] == "done"


def test_outbox_cap_drops_the_oldest_and_counts_it(tmp_path):
    box = ResultOutbox(tmp_path / "o.db", max_results=2)
    for name in "abc":
        box.add(name, {"id": name})
    assert box.depth() == 2 and box.dropped_total() == 1 and box.peek()[1]["id"] == "b"


def test_outbox_moves_a_corrupt_file_aside_and_starts_fresh(tmp_path):
    path = tmp_path / "o.db"
    path.write_bytes(b"this is not a sqlite database at all, just text " * 20)
    box = ResultOutbox(path)
    assert box.depth() == 0 and box.recovered_from is not None and box.recovered_from.exists()


# --- import isolation ---------------------------------------------------------------------

def _module_level_imports(tree: ast.AST):
    """Import nodes that run at import time: everything not inside a function body."""
    stack = [tree]
    while stack:
        node = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                yield child
            stack.append(child)


def test_no_collector_module_imports_the_control_package_at_import_time():
    offenders = []
    for path in (ROOT / "hostwatch").rglob("*.py"):
        rel = path.relative_to(ROOT / "hostwatch")
        if rel.parts[0] == "control":
            continue
        package = ["hostwatch", *rel.parts[:-1]]
        for node in _module_level_imports(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            else:
                base = package[: len(package) - node.level + 1] if node.level else []
                module = ".".join(base + ([node.module] if node.module else []))
                names = [module] + [f"{module}.{a.name}" for a in node.names]
            if any(n == "hostwatch.control" or n.startswith("hostwatch.control.") for n in names):
                offenders.append(f"{rel}:{node.lineno}")
    assert offenders == []


def test_importing_every_collector_entry_does_not_load_the_control_package():
    code = ("import sys, hostwatch.__main__, hostwatch.agent, hostwatch.hub, hostwatch.cli, hostwatch.store, "
            "hostwatch.windows.service as s; hostwatch.cli._parser(); "
            "print(sorted(m for m in sys.modules if m.startswith('hostwatch.control')))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.stdout.strip() == "[]", out.stderr


def test_the_control_daemon_imports_without_win32_modules_and_opens_no_socket():
    code = ("import sys\nfor n in ('win32service','win32serviceutil','servicemanager','win32api'): sys.modules[n]=None\n"
            "import hostwatch.control.daemon, hostwatch.control.service as s\n"
            "print(s.SERVICE_NAME)\n")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.stdout.strip() == "hostwatch-control", out.stderr
    source = (ROOT / "hostwatch/control/daemon.py").read_text(encoding="utf-8")
    assert not re.search(r"\.listen\(|bind\(|uvicorn|socketserver|http\.server", source)


# --- the service files, checked statically ------------------------------------------------

UNIT = DEPLOY / "hostwatch-control.service"
SUDOERS = DEPLOY / "hostwatch-control.sudoers"
SCRIPTS = [DEPLOY / "windows" / "install-control.ps1", DEPLOY / "windows" / "uninstall-control.ps1"]


def _unit() -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    for line in UNIT.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            sections.setdefault(key.strip(), []).append(value.strip())
    return sections


def test_the_systemd_unit_runs_the_daemon_as_its_own_account_with_sudo_still_working():
    u = _unit()
    assert u["User"] == ["hostwatch-control"] and u["Group"] == ["hostwatch-control"]
    assert u["User"][0] not in ("root", "hostwatch")
    assert u["ExecStart"] == ["/opt/hostwatch-control/venv/bin/python -m hostwatch control run"]
    assert "NoNewPrivileges" not in u  # it would stop the sudo rules from working
    assert u["ProtectSystem"] == ["strict"] and u["StateDirectory"] == ["hostwatch-control"]
    assert u["EnvironmentFile"] == ["/etc/hostwatch/control.env"]
    assert u["Environment"] == [f"HOSTWATCH_CONTROL_DATA_DIR={d.LINUX_DATA_DIR.as_posix()}"]
    assert u["Restart"] == ["on-failure"] and u["WantedBy"] == ["multi-user.target"]
    assert "Listen" not in UNIT.read_text(encoding="utf-8")


def test_the_unit_and_the_sudoers_snippet_name_the_same_account_and_paths():
    rules = [l for l in SUDOERS.read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")]
    assert rules and all(l.startswith("hostwatch-control ALL=(root) NOPASSWD: ") for l in rules)
    assert not any("ALL=(ALL)" in l or "NOPASSWD: ALL" in l or "sh" == l.split()[-1] for l in rules)
    assert d.LINUX_CONFIG.as_posix() == "/etc/hostwatch/control.toml"
    assert _unit()["ConditionPathExists"] == [d.LINUX_CONFIG.as_posix()]


def test_the_env_example_holds_no_key_and_only_known_settings():
    text = (DEPLOY / "hostwatch-control.env.example").read_text(encoding="utf-8")
    assert re.search(r"^HOSTWATCH_CONTROL_KEY=$", text, re.M)
    assert not re.search(r"wpc_[0-9A-Za-z]{8,}", text)
    source = (ROOT / "hostwatch/control/daemon.py").read_text(encoding="utf-8")
    for name in set(re.findall(r"HOSTWATCH_[A-Z0-9_]+", text)):
        assert name in source, name


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_control_scripts_use_lf_ascii_and_no_em_dashes(script):
    raw = script.read_bytes()
    assert b"\r" not in raw and not raw.startswith(b"\xef\xbb\xbf")
    raw.decode("ascii")
    assert chr(0x2014) not in raw.decode("utf-8")


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_control_scripts_parse_when_powershell_is_available(script):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("no PowerShell on this machine")
    command = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
               "$env:HW_SCRIPT,[ref]$t,[ref]$e);if($e.Count){$e|ForEach-Object{$_.Message};exit 1}")
    out = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True,
                         text=True, timeout=120, env={**os.environ, "HW_SCRIPT": str(script)})
    assert out.returncode == 0, out.stdout + out.stderr


def test_install_script_never_prints_or_logs_the_control_key():
    text = SCRIPTS[0].read_text(encoding="utf-8")
    secrets_ = ("$ControlKey", "$secret", "$bstr")
    for number, line in enumerate(text.splitlines(), start=1):
        if re.search(r"Write-(Host|Output|Verbose|Debug|Warning|Error)|Out-String|\becho\b|Start-Transcript", line):
            assert not any(name in line for name in secrets_), f"line {number} may print the key"
        if line.startswith("Invoke-Native") or "sc.exe" in line:
            assert not any(name in line for name in secrets_)
    assert "-AsSecureString" in text and "[securestring]$ControlKey" in text and "Start-Transcript" not in text


def test_install_script_locks_the_files_and_registers_a_separate_service():
    text = SCRIPTS[0].read_text(encoding="utf-8")
    assert "*S-1-5-18" in text and "*S-1-5-32-544" in text
    assert not re.search(r"S-1-5-32-545|S-1-1-0|Everyone|Users:|S-1-5-11", text)
    assert text.index("icacls.exe' @($EnvFile") < text.index("WriteAllText")  # locked before the key is written
    assert text.index("icacls.exe' @($ConfigPath") < text.index("WriteAllText")
    assert "'LocalSystem'" in text and "restart/5000/restart/30000/restart/60000" in text and "'failureflag'" in text
    assert "[windows,control]" in text and "hostwatch.control.service" in text
    assert "control-venv" in text and "hostwatch-agent" not in text
    assert "$DryRun" in text and "-DryRun" in text and "wpc_" in text
    assert "Start-Service" in text


def test_uninstall_script_removes_only_control_files_and_only_when_asked():
    text = SCRIPTS[1].read_text(encoding="utf-8")
    assert "$RemoveControlData" in text and "Stop-Service" in text and "hostwatch.control.service remove" in text
    assert "-Recurse" in text and text.count("-Recurse") == 1 and "$Venv -Recurse" in text  # never the data folder
    assert "hostwatch-agent" not in text and "agent.env" not in text and "outbox.db'" not in text.replace("control-outbox.db'", "")


def test_service_registration_names_agree_across_module_scripts_and_pyproject():
    assert csvc.SERVICE_NAME == "hostwatch-control" and csvc.SERVICE_NAME != "hostwatch-agent"
    for script in SCRIPTS:
        assert f"'{csvc.SERVICE_NAME}'" in script.read_text(encoding="utf-8")
    assert csvc.SERVICE_CLASS_STRING == "hostwatch.control.service.HostwatchControlService"
    text = SCRIPTS[0].read_text(encoding="utf-8")
    key = re.search(r'\$ParamKey = "HKLM:[\\]+(.+?)"', text).group(1).replace("$ServiceName", csvc.SERVICE_NAME)
    name = re.search(r"Set-ItemProperty -Path \$ParamKey -Name '(\w+)' -Value \$DataDir", text).group(1)
    assert (key, name) == (csvc.REGISTRY_PARAMETERS_KEY, csvc.REGISTRY_DATA_DIR_VALUE)
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^control = \["cryptography>=\d+"\]$', pyproject, re.M)


def test_the_service_data_folder_comes_from_the_registry_then_the_environment(tmp_path, monkeypatch):
    chosen = tmp_path / "custom"
    registry = {(csvc.REGISTRY_PARAMETERS_KEY, csvc.REGISTRY_DATA_DIR_VALUE): str(chosen)}
    monkeypatch.delenv("HOSTWATCH_CONTROL_DATA_DIR", raising=False)
    assert csvc.service_data_dir(lambda k, n: registry.get((k, n))) == chosen
    monkeypatch.setenv("HOSTWATCH_CONTROL_DATA_DIR", str(tmp_path / "env"))
    assert csvc.service_data_dir(lambda k, n: None) == tmp_path / "env"
    monkeypatch.delenv("HOSTWATCH_CONTROL_DATA_DIR")
    assert csvc.service_data_dir(lambda k, n: None) == d.WINDOWS_DATA_DIR


def test_the_service_class_is_built_lazily_and_pywin32_is_not_imported_at_import():
    code = ("import sys; sys.modules['win32service']=None; sys.modules['servicemanager']=None\n"
            "import hostwatch.control.service as s\n"
            "try:\n s.HostwatchControlService\nexcept ImportError: print('needs pywin32')\n")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.stdout.strip() == "needs pywin32", out.stderr
    with pytest.raises(AttributeError):
        csvc.NoSuchThing


def test_canonical_json_is_what_the_fake_watchpost_signs(signer):
    cmd = make_cmd()
    raw = base64.b64decode(sign(signer, cmd))
    signer.public_key().verify(raw, canonical_json(cmd))
