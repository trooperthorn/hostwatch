"""Windows platform seam: importable on Linux, fakes only, no real reader ever constructed."""

from __future__ import annotations

import ast
import importlib
import json
import sys
from pathlib import Path

import pytest
from fakes_windows import FakeCommandRunner, fake_seam

import hostwatch.windows as win
from hostwatch import agent
from hostwatch.collectors import build_collectors
from hostwatch.collectors.base import Collector
from hostwatch.config import Config
from hostwatch.windows import CommandResult, SeamError

SubprocessRunnerReal = win.SubprocessRunner
EventReaderReal = win.PowerShellEventLogReader

REAL_CLASSES = ("SubprocessRunner", "PowerShellEventLogReader", "PowerShellCimQuery", "NamedPipeStatusReader")


@pytest.fixture(autouse=True)
def no_real_readers(monkeypatch):
    """Any construction of a real reader or a real subprocess during these tests fails loudly."""
    def refuse(*_a, **_k):
        raise AssertionError("a real Windows reader was constructed under test")
    for name in REAL_CLASSES:
        monkeypatch.setattr(win, name, type(name, (), {"__init__": refuse}))
    monkeypatch.setattr(win, "real_seam", refuse)


def test_every_windows_module_imports_without_windows_modules():
    for name in ("hostwatch.windows", "hostwatch.collectors", "hostwatch.agent", "fakes_windows"):
        importlib.import_module(name)
    # Other libraries may load winreg or msvcrt on Windows, so check this package's own imports.
    banned = {"win32api", "win32evtlog", "win32pipe", "win32file", "pywintypes", "wmi", "winreg", "msvcrt", "ctypes"}
    for path in (Path(win.__file__),):
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.Import):
                names = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {(node.module or "").split(".")[0]}
            else:
                continue
            assert not names & banned, (path, names)


def test_fakes_satisfy_the_protocols():
    seam = fake_seam()
    assert isinstance(seam.events, win.EventLogReader)
    assert isinstance(seam.cim, win.CimQuery)
    assert isinstance(seam.pipe, win.PipeStatusReader)
    assert isinstance(seam.runner, win.CommandRunner)


def test_fakes_serve_the_json_fixture():
    seam = fake_seam()
    ids = [e["id"] for e in seam.events.read("System")]
    assert ids == [41, 6008]
    assert [e["id"] for e in seam.events.read("System", event_ids=[6008])] == [6008]
    assert seam.events.read("System", since=1789999500)[0]["id"] == 41
    assert seam.cim.query("Win32_OperatingSystem", ["Caption"]) == [{"Caption": "Microsoft Windows 11 Pro"}]
    assert seam.pipe.read("ThermalControlSvc")["ts"] == 1790000000
    with pytest.raises(SeamError):
        seam.events.read("Nope")
    with pytest.raises(SeamError):
        seam.pipe.read("Nope")


def test_detect_platform_reports_windows_without_touching_sysfs(monkeypatch):
    def boom(self, *a, **k):
        raise AssertionError("sysfs or procfs was touched")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(Path, "read_text", boom)
    assert agent.detect_platform(Path("/nonexistent/sys")) == "windows"
    assert agent.detect_platform() == "windows"


def test_detect_platform_unchanged_off_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(agent._platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **k: (_ for _ in ()).throw(OSError("none")))
    assert agent.detect_platform(tmp_path) == "x86"


def test_collector_accepts_the_seam_without_paths():
    seam = fake_seam()

    class Probe(Collector):
        id = "probe"

    c = Probe(seam=seam)
    assert c.seam is seam and c.sysfs is None and c.procfs is None
    assert Probe(Path("/s"), Path("/p")).seam is None


def test_build_collectors_and_agent_carry_the_seam(tmp_path):
    seam = fake_seam()
    cfg = Config(data_dir=tmp_path, sysfs=tmp_path / "sys", procfs=tmp_path / "proc")
    assert all(c.seam is seam for c in build_collectors(cfg, seam))
    assert all(c.seam is None for c in build_collectors(cfg))
    assert agent.Agent(cfg, seam).seam is seam
    assert agent.Agent(cfg).seam is None


def test_event_log_script_is_built_from_validated_values():
    script = win.event_log_script("System", [41, 6008], 1790000000, 50)
    assert "Get-WinEvent" in script and "ConvertTo-Json" in script
    assert "LogName='System'" in script and "Id=41,6008" in script and "-MaxEvents 50" in script
    assert "FromUnixTimeSeconds(1790000000)" in script
    assert "NoMatchingEventsFound" in script
    assert "-MaxEvents 1000" in win.event_log_script("System", None, None, 10**6)
    for bad in ("System'; calc; '", "A\nB", ""):
        with pytest.raises(SeamError):
            win.event_log_script(bad, None, None, 1)


def test_cim_script_is_built_from_validated_values():
    script = win.cim_script("Win32_OperatingSystem", ["Caption", "FreePhysicalMemory"], "root/cimv2")
    assert "Get-CimInstance -ClassName Win32_OperatingSystem -Namespace 'root/cimv2'" in script
    assert "Select-Object Caption,FreePhysicalMemory" in script and "ConvertTo-Json" in script
    for args in (("Win32_X; calc", None, None), ("Win32_X", ["a b"], None), ("Win32_X", None, "x'; y")):
        with pytest.raises(SeamError):
            win.cim_script(*args)


def test_parse_json_list_shapes():
    assert win.parse_json_list("") == []
    assert win.parse_json_list("﻿{\"a\": 1}") == [{"a": 1}]
    assert win.parse_json_list('[{"a": 1}, {"a": 2}]') == [{"a": 1}, {"a": 2}]
    for bad in ("not json", "[1, 2]", '"text"'):
        with pytest.raises(SeamError):
            win.parse_json_list(bad)


def test_run_powershell_uses_a_timeout_and_no_shell():
    runner = FakeCommandRunner([CommandResult(0, "[]")])
    assert win.run_powershell(runner, "Get-Date", 7.5) == "[]"
    args, timeout = runner.calls[0]
    assert timeout == 7.5
    assert args[0] == "powershell.exe" and "-NoProfile" in args and "-NonInteractive" in args
    assert args[-2:] == ["-Command", "Get-Date"]


def test_run_powershell_reports_failure_with_the_first_line():
    runner = FakeCommandRunner([CommandResult(1, "", "boom\nmore")])
    with pytest.raises(SeamError, match="exited 1: boom"):
        win.run_powershell(runner, "x", 1)
    with pytest.raises(SeamError):
        win.run_powershell(FakeCommandRunner(), "x", 1)


def test_fixture_is_valid_json():
    json.loads((Path(__file__).parent / "fixtures" / "windows" / "seam.json").read_text(encoding="utf-8"))


def test_the_guard_really_blocks_real_readers():
    with pytest.raises(AssertionError):
        win.PowerShellCimQuery(FakeCommandRunner())
    with pytest.raises(AssertionError):
        win.real_seam()


def test_event_log_script_reads_oldest_first_only_when_asked():
    assert "-Oldest" in win.event_log_script("System", [41], None, 50, oldest_first=True)
    assert "-Oldest" not in win.event_log_script("System", [41], None, 50)


class _BytesRunner:
    """A runner that returns what SubprocessRunner would: raw bytes decoded by the seam's decoder."""

    def __init__(self, stdout: bytes) -> None:
        self.stdout = stdout

    def run(self, args, timeout_s):
        return CommandResult(0, win.decode_output(self.stdout))


def test_localized_utf8_event_text_decodes_correctly():
    payload = json.dumps([{"id": 41, "message": "Das System wurde neu gestartet: Größe, Übung"},
                          {"id": 6008, "message": "予期しないシャットダウン"}], ensure_ascii=False)
    rows = EventReaderReal(_BytesRunner(payload.encode("utf-8"))).read("System")
    assert rows[0]["message"] == "Das System wurde neu gestartet: Größe, Übung"
    assert rows[1]["message"] == "予期しないシャットダウン"


def test_invalid_bytes_are_replaced_and_the_cycle_continues():
    raw = b'[{"id": 1, "message": "bad \xff\xfe byte"}]'
    rows = EventReaderReal(_BytesRunner(raw)).read("System")
    assert rows == [{"id": 1, "message": "bad \ufffd\ufffd byte"}]
    assert win.decode_output(None) == ""


def test_subprocess_runner_decodes_bytes_with_replacement(monkeypatch):
    import subprocess

    class Done:
        returncode, stdout, stderr = 0, b"\xe6\x97\xa5 \xff", b"\xff"

    seen = {}

    def fake_run(args, **kwargs):
        seen.update(kwargs)
        return Done()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = SubprocessRunnerReal().run(["powershell.exe"], 5)
    assert result.stdout == "日 \ufffd" and result.stderr == "\ufffd"
    assert seen["timeout"] == 5 and seen["shell"] is False and "text" not in seen


def test_every_script_sets_utf8_output_encoding():
    scripts = [win.event_log_script("System", None, None, 10), win.event_log_script("System", [41], 5.0, 1, True),
               win.cim_script("Win32_Processor", None, None), win.cim_script("MSFT_PhysicalDisk", ["A"], "root/x")]
    for script in scripts:
        assert script.startswith("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;")
