"""The Windows agent run mode and service host, on fakes only. No service is registered, no pipe or
PowerShell is touched, and pywin32 is never imported."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from fakes_windows import FakeCimQuery, FakeCommandRunner, FakeEventLogReader, FakePipeStatusReader
from test_winevent import bc1001, kp41

from hostwatch import cli
from hostwatch.config import Config
from hostwatch.schema import Batch
from hostwatch.windows import WindowsSeam
from hostwatch.windows import service as svc

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy" / "windows"
SCRIPTS = [DEPLOY / "install.ps1", DEPLOY / "uninstall.ps1"]
KEY = "hw_" + "k" * 40


def seam(logs=None) -> WindowsSeam:
    return WindowsSeam(events=FakeEventLogReader({"System": logs or []}), cim=FakeCimQuery({}),
                       pipe=FakePipeStatusReader({}), runner=FakeCommandRunner())


def agent_cfg(tmp_path, **kw) -> Config:
    return Config(role="agent", data_dir=tmp_path / "data", host_name="win-host", interval_s=1.0,
                  hub_url="http://hub.test", ingest_key=KEY, **kw)


class FakeHub:
    """A hub that records what it receives and can be told to refuse."""

    def __init__(self) -> None:
        self.up = True
        self.batches: list[Batch] = []
        self.auth: list[str] = []

    def client(self) -> httpx.Client:
        def handler(request: httpx.Request) -> httpx.Response:
            if not self.up:
                return httpx.Response(503)
            self.auth.append(request.headers["Authorization"])
            self.batches.append(Batch.model_validate_json(request.content))
            return httpx.Response(200, json={"accepted": True})
        return httpx.Client(transport=httpx.MockTransport(handler))


def test_one_cycle_reaches_the_hub_with_the_unchanged_wire_schema(tmp_path):
    import time
    now = time.time()
    hub = FakeHub()
    agent = svc.build_agent(agent_cfg(tmp_path), seam([kp41(now - 3600), bc1001(now - 3500)]))
    agent.detect()
    assert agent.safe_cycle() is True
    with hub.client() as client:
        agent.flush(client)
    (batch,) = hub.batches
    assert hub.auth == [f"Bearer {KEY}"]
    assert batch.platform == "windows" and batch.host == "win-host"
    assert {s.source for s in batch.sources} >= {"winevent", "outbox"}
    assert not {"pstore", "rasdaemon", "journal"} & {s.source for s in batch.sources}
    assert [e.kind for e in batch.events] == ["boot.kernel_panic"]
    assert Batch.model_validate_json(batch.model_dump_json()) == batch
    assert agent.outbox.depth() == 0


def test_outbox_replays_in_order_after_a_hub_outage_and_a_restart(tmp_path):
    hub = FakeHub()
    cfg = agent_cfg(tmp_path)
    first = svc.build_agent(cfg, seam())
    first.detect()
    hub.up = False
    first.safe_cycle()
    first.safe_cycle()
    with hub.client() as client, pytest.raises(httpx.HTTPStatusError):
        first.flush(client)
    assert first.outbox.depth() == 2 and hub.batches == []
    queued = [first.outbox.peek()[1].batch_id]
    # A new process finds the same file under the data directory and replays it.
    second = svc.build_agent(cfg, seam())
    assert second.outbox.depth() == 2
    hub.up = True
    with hub.client() as client:
        second.flush(client)
    assert len(hub.batches) == 2 and second.outbox.depth() == 0
    assert hub.batches[0].sent_at <= hub.batches[1].sent_at
    assert hub.batches[0].batch_id == queued[0]


def test_the_agent_never_reports_linux_only_sources_or_a_boot_id_failure(tmp_path):
    agent = svc.build_agent(agent_cfg(tmp_path), seam())
    assert set(agent.event_sources) == {"winevent"}
    agent._guarded_boot_check()
    assert "boot" not in agent.status and agent.heartbeat is None


def test_stop_flushes_the_outbox_through_the_service_host(tmp_path):
    hub = FakeHub()
    host = svc.AgentHost(agent_cfg(tmp_path), seam(), client_factory=hub.client)
    host.agent.detect()
    host.agent.safe_cycle()
    assert host.agent.outbox.depth() == 1
    host.stop()          # what the service stop handler calls
    host.run()           # the loop ends at once and the outbox is flushed on the way out
    assert len(hub.batches) == 1 and host.agent.outbox.depth() == 0


def test_stop_with_the_hub_down_keeps_the_batch_queued_and_does_not_raise(tmp_path):
    hub = FakeHub()
    hub.up = False
    host = svc.AgentHost(agent_cfg(tmp_path), seam(), client_factory=hub.client)
    host.agent.detect()
    host.agent.safe_cycle()
    host.stop()
    host.run()
    assert host.agent.outbox.depth() == 1


def test_flush_runs_even_when_the_loop_raises(tmp_path):
    calls = []

    class Boom:
        outbox = type("O", (), {"depth": staticmethod(lambda: 0)})()

        def run(self):
            raise RuntimeError("loop failed")

        def flush(self, client, **kwargs):
            calls.append("flush")

        def stop(self):
            calls.append("stop")

    host = svc.AgentHost(agent_cfg(tmp_path), None, client_factory=FakeHub().client,
                         agent_factory=lambda cfg, seam: Boom())
    with pytest.raises(RuntimeError):
        host.run()
    host.stop()
    assert calls == ["flush", "stop"]


def test_importing_the_service_module_never_needs_pywin32():
    code = ("import sys; sys.modules['win32serviceutil']=None; sys.modules['servicemanager']=None; "
            "sys.modules['win32service']=None; import hostwatch.windows.service as s; print(s.SERVICE_NAME)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, timeout=60)
    assert out.returncode == 0 and out.stdout.strip() == "hostwatch-agent", out.stderr


def test_env_file_loads_without_overriding_and_rejects_bad_lines(tmp_path):
    path = tmp_path / "agent.env"
    path.write_text(f"# note\n\nHOSTWATCH_HUB_URL=http://file.test\nHOSTWATCH_INGEST_KEY=\"{KEY}\"\n", encoding="utf-8")
    env = {"HOSTWATCH_HUB_URL": "http://set.test"}
    assert svc.load_env_file(path, env) == ["HOSTWATCH_INGEST_KEY"]
    assert env["HOSTWATCH_HUB_URL"] == "http://set.test" and env["HOSTWATCH_INGEST_KEY"] == KEY
    path.write_text(f"PATH={KEY}\n", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        svc.load_env_file(path, {})
    assert KEY not in str(exc.value) and "line 1" in str(exc.value)


def test_build_config_reads_the_env_file_and_forces_the_agent_role(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    (data / "agent.env").write_text(f"HOSTWATCH_ROLE=hub\nHOSTWATCH_HUB_URL=http://hub.test\n"
                                    f"HOSTWATCH_INGEST_KEY={KEY}\n", encoding="utf-8")
    monkeypatch.setattr(os, "environ", {})
    cfg = svc.build_config(data)
    assert cfg.role == "agent" and cfg.data_dir == data and cfg.agent_credential == KEY
    assert cfg.hub_url == "http://hub.test"


def test_build_config_defaults_the_data_directory_and_requires_a_credential(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "environ", {})
    monkeypatch.setattr(svc, "DEFAULT_DATA_DIR", tmp_path / "ProgramData" / "hostwatch")
    with pytest.raises(ValueError, match="credential"):
        svc.build_config()
    monkeypatch.setattr(os, "environ", {"HOSTWATCH_INGEST_TOKEN": "t" * 40})
    assert svc.build_config().data_dir == tmp_path / "ProgramData" / "hostwatch"


def test_the_windows_run_command_is_wired_and_uses_the_service_runner(tmp_path, monkeypatch, capsys):
    seen = {}
    monkeypatch.setattr(svc, "run_foreground", lambda data_dir, env_file: seen.update(d=data_dir, e=env_file) or 0)
    assert cli.run(["windows", "run", "--data-dir", str(tmp_path), "--env-file", "x.env"], Config()) == 0
    assert seen == {"d": str(tmp_path), "e": "x.env"}
    assert not (tmp_path / "hostwatch.db").exists()  # the agent never opens the hub database


def test_run_foreground_reports_a_bad_configuration_without_starting(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "environ", {})
    started = []
    code = svc.run_foreground(str(tmp_path), None, host_factory=lambda cfg: started.append(cfg))
    assert code == 1 and started == [] and "credential" in capsys.readouterr().err


def test_run_foreground_runs_the_host_and_leaves_the_outbox_in_the_data_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "environ", {"HOSTWATCH_INGEST_KEY": KEY})
    ran = []

    class Host:
        def __init__(self, cfg):
            ran.append(cfg)

        def run(self):
            ran.append("run")

        def stop(self):
            ran.append("stop")

    assert svc.run_foreground(str(tmp_path / "d"), None, host_factory=Host) == 0
    assert ran[1] == "run" and ran[0].data_dir == tmp_path / "d" and ran[0].role == "agent"


# Static checks of the install scripts. They are never run.

@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_scripts_use_lf_ascii_and_no_em_dashes(script):
    raw = script.read_bytes()
    assert b"\r" not in raw and not raw.startswith(b"\xef\xbb\xbf")
    raw.decode("ascii")  # Windows PowerShell 5.1 reads a file without a BOM as ANSI
    assert chr(0x2014) not in raw.decode("utf-8")


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_scripts_parse_when_powershell_is_available(script):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("no PowerShell on this machine")
    command = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
               "$env:HW_SCRIPT,[ref]$t,[ref]$e);if($e.Count){$e|ForEach-Object{$_.Message};exit 1}")
    out = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True,
                         text=True, timeout=120, env={**os.environ, "HW_SCRIPT": str(script)})
    assert out.returncode == 0, out.stdout + out.stderr


def test_install_script_never_prints_or_logs_the_token():
    text = (DEPLOY / "install.ps1").read_text(encoding="utf-8")
    secrets_ = ("$IngestKey", "$secret", "$bstr")
    for number, line in enumerate(text.splitlines(), start=1):
        if re.search(r"Write-(Host|Output|Verbose|Debug|Warning|Error)|Out-String|\becho\b|Start-Transcript", line):
            assert not any(name in line for name in secrets_), f"line {number} may print the token"
    assert "-AsSecureString" in text and "[securestring]$IngestKey" in text
    assert "Start-Transcript" not in text
    # The key is never an argument to a native command.
    for line in text.splitlines():
        if line.startswith("Invoke-Native") or "sc.exe" in line:
            assert not any(name in line for name in secrets_)


def test_install_script_limits_the_acl_and_registers_the_service():
    text = (DEPLOY / "install.ps1").read_text(encoding="utf-8")
    assert "*S-1-5-18" in text and "*S-1-5-32-544" in text
    assert text.count("'/inheritance:r'") == 2 and text.count("'/grant:r'") == 2
    assert not re.search(r"S-1-5-32-545|S-1-1-0|Everyone|Users:|S-1-5-11", text)
    assert text.index("icacls.exe' @($EnvFile") < text.index("WriteAllText")  # locked before the secret is written
    assert "'LocalSystem'" in text and "restart/5000/restart/30000/restart/60000" in text
    assert "'failureflag'" in text and "[windows]" in text and "hostwatch.windows.service" in text
    assert "-DryRun" in text and "$DryRun" in text


def test_uninstall_script_keeps_the_data_unless_asked():
    text = (DEPLOY / "uninstall.ps1").read_text(encoding="utf-8")
    assert "$RemoveData" in text and "Stop-Service" in text and "hostwatch.windows.service remove" in text


def test_service_name_and_extra_match_the_scripts_and_pyproject():
    assert svc.SERVICE_NAME == "hostwatch-agent"
    for script in SCRIPTS:
        assert f"'{svc.SERVICE_NAME}'" in script.read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r"^windows = \[\"pywin32>=\d+; sys_platform == 'win32'\"\]$", pyproject, re.M)
    assert "pywin32" not in (ROOT / "requirements.lock").read_text(encoding="utf-8")


# Documents.

DOC_FILES = ["README.md", "docs/ARCHITECTURE.md", "docs/deploy-agents.md", "PLAN.md", "UNVERIFIED.md"]


@pytest.mark.parametrize("name", DOC_FILES)
def test_phase_8_docs_say_the_destination_will_move_to_watchpost(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    assert "hostwatch-agent" in text or name in ("PLAN.md", "UNVERIFIED.md"), name
    if name != "UNVERIFIED.md":
        assert "watchpost" in text, name


def test_docs_name_real_commands_files_and_no_em_dashes():
    for name in DOC_FILES + ["deploy/windows/install.ps1"]:
        assert chr(0x2014) not in (ROOT / name).read_text(encoding="utf-8"), name
    guide = (ROOT / "docs/deploy-agents.md").read_text(encoding="utf-8")
    for rel in ("deploy/windows/install.ps1", "deploy/windows/uninstall.ps1"):
        assert rel in guide and (ROOT / rel).is_file()
    assert "python -m hostwatch windows run" in guide
    assert "pywin32" in (ROOT / "UNVERIFIED.md").read_text(encoding="utf-8")
    assert svc.SERVICE_NAME in guide


def test_the_registered_class_string_imports_to_the_service_class(monkeypatch):
    import importlib
    import types

    class Framework:
        def __init__(self, args):
            self.args = args

    util = types.SimpleNamespace(ServiceFramework=Framework)
    for name, mod in (("win32serviceutil", util), ("win32service", types.SimpleNamespace()),
                      ("servicemanager", types.SimpleNamespace())):
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.setattr(svc, "_service_class_cache", [])
    module_name, _, class_name = svc.SERVICE_CLASS_STRING.rpartition(".")
    cls = getattr(importlib.import_module(module_name), class_name)
    assert module_name == "hostwatch.windows.service" and issubclass(cls, Framework)
    assert cls._svc_name_ == svc.SERVICE_NAME and cls.__module__ == module_name
    with pytest.raises(AttributeError):
        svc.not_a_service_class  # noqa: B018
    assert "HandleCommandLine(cls, serviceClassString=SERVICE_CLASS_STRING" in Path(svc.__file__).read_text(encoding="utf-8")


def test_service_exe_name_prefers_the_environment_copy(tmp_path):
    assert svc.service_exe_name(tmp_path) is None
    exe = tmp_path / "Lib" / "site-packages" / "win32" / "pythonservice.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"")
    assert svc.service_exe_name(tmp_path) == str(exe)


def test_a_custom_data_dir_round_trips_from_the_install_script_to_the_service(tmp_path, monkeypatch):
    text = (DEPLOY / "install.ps1").read_text(encoding="utf-8")
    key = re.search(r'\$ParamKey = "HKLM:[\\]+(.+?)"', text).group(1).replace("$ServiceName", svc.SERVICE_NAME)
    name = re.search(r"Set-ItemProperty -Path \$ParamKey -Name '(\w+)' -Value \$DataDir", text).group(1)
    assert (key, name) == (svc.REGISTRY_PARAMETERS_KEY, svc.REGISTRY_DATA_DIR_VALUE)
    chosen = tmp_path / "custom data"
    registry = {(key, name): str(chosen)}
    monkeypatch.delenv("HOSTWATCH_DATA_DIR", raising=False)
    assert svc.service_data_dir(lambda k, n: registry.get((k, n))) == chosen
    monkeypatch.setenv("HOSTWATCH_DATA_DIR", str(tmp_path / "env"))
    assert svc.service_data_dir(lambda k, n: None) == tmp_path / "env"
    monkeypatch.delenv("HOSTWATCH_DATA_DIR")
    assert svc.service_data_dir(lambda k, n: None) == svc.DEFAULT_DATA_DIR
    (chosen).mkdir()
    (chosen / svc.ENV_FILE_NAME).write_text(f"HOSTWATCH_HUB_URL=http://hub.test\nHOSTWATCH_INGEST_KEY={KEY}\n")
    monkeypatch.delenv("HOSTWATCH_HUB_URL", raising=False)
    monkeypatch.delenv("HOSTWATCH_INGEST_KEY", raising=False)
    cfg = svc.build_config(svc.service_data_dir(lambda k, n: registry.get((k, n))))
    assert cfg.data_dir == chosen and cfg.hub_url == "http://hub.test"


class SlowClient:
    """A client whose sends wait for their timeout and then fail, like a hub that never answers."""

    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def post(self, url, content=None, headers=None, timeout=None):
        import threading
        self.timeouts.append(timeout)
        threading.Event().wait(timeout)
        raise httpx.ReadTimeout("slow")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _queue_batches(host, count):
    host.agent.detect()
    for _ in range(count):
        host.agent.safe_cycle()
    assert host.agent.outbox.depth() == count


def test_stop_during_a_slow_send_returns_within_the_bound_and_keeps_the_batch(tmp_path):
    import time
    client = SlowClient()
    host = svc.AgentHost(agent_cfg(tmp_path), seam(), client_factory=lambda: client)
    _queue_batches(host, 3)
    host.stop()
    started = time.monotonic()
    assert host.flush_outbox(bound_s=0.4) is False
    assert time.monotonic() - started < 2.0
    assert host.agent.outbox.depth() == 3
    assert client.timeouts and all(t <= 0.4 for t in client.timeouts)


def test_a_stop_ends_the_normal_flush_between_sends(tmp_path):
    hub = FakeHub()
    host = svc.AgentHost(agent_cfg(tmp_path), seam(), client_factory=hub.client)
    _queue_batches(host, 2)
    host.stop()
    host.agent.flush(hub.client())
    assert hub.batches == [] and host.agent.outbox.depth() == 2
    from hostwatch.agent import SEND_TIMEOUT_S
    assert 0 < SEND_TIMEOUT_S <= 5 and 0 < svc.FINAL_FLUSH_BOUND_S <= 10


def test_windows_agent_reports_linux_only_sources_as_not_present(tmp_path):
    agent = svc.build_agent(agent_cfg(tmp_path), seam())
    agent.detect()
    status = {s.source: s for s in agent.status.values()}
    for source in ("rapl", "hwmon", "mdraid", "zfs", "rpi", "thermalctl"):
        assert status[source].present is False and status[source].available is False, source
        assert "not present on Windows" in status[source].reason
    assert status["cpu"].present is True and status["win_storage"].present is True
    batch = agent.collect_once()
    assert not [s for s in batch.samples if s.source in ("rapl", "hwmon", "mdraid", "zfs", "rpi", "thermalctl")]
