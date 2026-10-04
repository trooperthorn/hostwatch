"""Windows platform seam: small interfaces for everything a Windows collector reads.

Windows collectors never touch sysfs or procfs. They ask an event log reader, a CIM query,
a pipe status reader or a command runner, all of which are protocols defined here. The real
implementations run PowerShell (Get-WinEvent and Get-CimInstance with ConvertTo-Json) through a
CommandRunner with a timeout, use only the standard library, and import process-spawning or
Windows-only modules lazily inside the methods that need them. That keeps this package
importable on Linux, so CI exercises the collectors with the fakes in `tests/fakes_windows.py`.

Nothing here is verified on a Windows host yet; see `UNVERIFIED.md`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

DEFAULT_TIMEOUT_S = 30.0
_NAME = re.compile(r"[A-Za-z0-9_.\-/ ]{1,128}")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_PIPE = re.compile(r"[A-Za-z0-9_.\-]{1,128}")


class SeamError(Exception):
    """A seam call failed. The message is safe to show as an unavailable reason."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


@runtime_checkable
class CommandRunner(Protocol):
    def run(self, args: list[str], timeout_s: float) -> CommandResult:
        """Run a program without a shell. Raises SeamError on timeout or if it cannot start."""


@runtime_checkable
class EventLogReader(Protocol):
    def read(self, log_name: str, event_ids: list[int] | None = None, since: float | None = None,
             max_events: int = 100) -> list[dict[str, Any]]:
        """Return newest-first events as dicts with id, provider, level, time (epoch seconds) and message."""


@runtime_checkable
class CimQuery(Protocol):
    def query(self, class_name: str, properties: list[str] | None = None,
              namespace: str | None = None) -> list[dict[str, Any]]:
        """Return one dict per CIM instance."""


@runtime_checkable
class PipeStatusReader(Protocol):
    def read(self, pipe_name: str) -> dict[str, Any]:
        """Return the JSON object a status pipe serves. Raises SeamError when it cannot be read."""


@dataclass(frozen=True)
class WindowsSeam:
    events: EventLogReader
    cim: CimQuery
    pipe: PipeStatusReader
    runner: CommandRunner


# Script builders and the output parser are plain functions so they can be tested without
# constructing a reader. Every caller supplied value is validated or numeric before it is
# placed in the script text, so a value cannot add PowerShell syntax.

def _check(value: str, pattern: re.Pattern[str], what: str) -> str:
    if not pattern.fullmatch(value):
        raise SeamError(f"invalid {what}: {value!r}")
    return value


def event_log_script(log_name: str, event_ids: list[int] | None, since: float | None,
                     max_events: int) -> str:
    _check(log_name, _NAME, "event log name")
    filt = [f"LogName='{log_name}'"]
    if event_ids:
        filt.append("Id=" + ",".join(str(int(i)) for i in event_ids))
    if since is not None:
        filt.append(f"StartTime=[DateTimeOffset]::FromUnixTimeSeconds({int(since)}).LocalDateTime")
    count = max(1, min(int(max_events), 1000))
    return (
        "$ErrorActionPreference='Stop'; "
        f"try {{ $e = @(Get-WinEvent -FilterHashtable @{{{'; '.join(filt)}}} -MaxEvents {count}) }} "
        "catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $e = @() } else { throw } }; "
        "ConvertTo-Json -Compress -Depth 3 -InputObject @($e | ForEach-Object { [ordered]@{ "
        "id=$_.Id; record=$_.RecordId; provider=$_.ProviderName; level=$_.Level; "
        "time=[DateTimeOffset]::new($_.TimeCreated).ToUnixTimeSeconds(); message=$_.Message } })"
    )


def cim_script(class_name: str, properties: list[str] | None, namespace: str | None) -> str:
    _check(class_name, _IDENT, "CIM class name")
    parts = [f"-ClassName {class_name}"]
    if namespace:
        parts.append(f"-Namespace '{_check(namespace, _NAME, 'CIM namespace')}'")
    select = ""
    if properties:
        names = ",".join(_check(p, _IDENT, "CIM property") for p in properties)
        select = f" | Select-Object {names}"
    return ("$ErrorActionPreference='Stop'; "
            f"ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-CimInstance {' '.join(parts)}{select})")


def parse_json_list(stdout: str) -> list[dict[str, Any]]:
    text = stdout.strip().lstrip("﻿")
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise SeamError(f"PowerShell output was not JSON: {exc}") from exc
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not all(isinstance(d, dict) for d in data):
        raise SeamError("PowerShell output was not a list of objects")
    return data


def run_powershell(runner: CommandRunner, script: str, timeout_s: float) -> str:
    result = runner.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                         "-Command", script], timeout_s)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise SeamError(f"PowerShell exited {result.returncode}: {detail[0] if detail else 'no output'}")
    return result.stdout


class SubprocessRunner:
    """Real CommandRunner. The subprocess module is imported when a command runs."""

    def run(self, args: list[str], timeout_s: float) -> CommandResult:
        import subprocess
        try:
            done = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=timeout_s, check=False, shell=False)
        except subprocess.TimeoutExpired as exc:
            raise SeamError(f"{args[0]} timed out after {timeout_s:g} seconds") from exc
        except OSError as exc:
            raise SeamError(f"cannot run {args[0]}: {exc}") from exc
        return CommandResult(done.returncode, done.stdout, done.stderr)


class PowerShellEventLogReader:
    def __init__(self, runner: CommandRunner, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        self.runner, self.timeout_s = runner, timeout_s

    def read(self, log_name: str, event_ids: list[int] | None = None, since: float | None = None,
             max_events: int = 100) -> list[dict[str, Any]]:
        script = event_log_script(log_name, event_ids, since, max_events)
        return parse_json_list(run_powershell(self.runner, script, self.timeout_s))


class PowerShellCimQuery:
    def __init__(self, runner: CommandRunner, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        self.runner, self.timeout_s = runner, timeout_s

    def query(self, class_name: str, properties: list[str] | None = None,
              namespace: str | None = None) -> list[dict[str, Any]]:
        script = cim_script(class_name, properties, namespace)
        return parse_json_list(run_powershell(self.runner, script, self.timeout_s))


class NamedPipeStatusReader:
    """Read one JSON document from a read-only named pipe. The pipe protocol of the fan
    controller service is unconfirmed, so this only opens the pipe and reads until it closes."""

    def read(self, pipe_name: str) -> dict[str, Any]:
        _check(pipe_name, _PIPE, "pipe name")
        try:
            with open("\\\\.\\pipe\\" + pipe_name, "r", encoding="utf-8") as pipe:
                data = json.loads(pipe.read())
        except (OSError, ValueError) as exc:
            raise SeamError(f"cannot read pipe {pipe_name}: {exc}") from exc
        if not isinstance(data, dict):
            raise SeamError(f"pipe {pipe_name} did not serve a JSON object")
        return data


def real_seam(timeout_s: float = DEFAULT_TIMEOUT_S) -> WindowsSeam:
    """Build the real seam. Only the Windows agent entry point calls this; tests never do."""
    runner = SubprocessRunner()
    return WindowsSeam(events=PowerShellEventLogReader(runner, timeout_s),
                       cim=PowerShellCimQuery(runner, timeout_s),
                       pipe=NamedPipeStatusReader(), runner=runner)
