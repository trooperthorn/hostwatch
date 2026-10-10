"""Windows executors for hostwatch-control: Thermal Control Suite fans, service restarts and reboot.

Nothing here imports a win32 module, and the standard library pieces that only a real run needs
are imported inside the methods that use them, so the package imports and is tested on Linux with
fakes. Every external program goes through the `CommandRunner` seam of `hostwatch.windows` as an
argument list and never through a shell. Executors only run after `verify.CommandVerifier`
accepted the command, but they validate every name and number again themselves.

Fans: the daemon is meant to run as LocalSystem, which the Thermal Control Suite pipe treats as an
Administrator. The pipe is reached through an injectable `PipeClient`, so tests use a fake.

The Suite has no pipe request that switches dry run. `DryRun` is a setting in its own configuration
file and the pipe only reports it, so `fan.set_mode` is refused here with a plain reason instead of
being faked. See UNVERIFIED.md.
"""

from __future__ import annotations

import json
import os
import struct
from typing import Any, Protocol

from ..windows import (DEFAULT_PIPE_TIMEOUT_S, MAX_FRAME_BYTES, PIPE_DIR, CommandRunner, PipeAbsentError,
                       SeamError, SubprocessRunner)
from .actions_linux import HEADER_ID, MODES, UPDATE_COMPONENTS, ActionResult, _clip
from .config import ControlConfig, effective_reboot_delay, valid_service_name

PIPE_NAME = "ThermalControlSuite.Ipc"
SUITE_CONTROLLER = "thermal-control-suite"
POWERSHELL = "powershell.exe"
SHUTDOWN = "shutdown.exe"
# The restart script is a constant. The service name is a separate argument that follows it, so it
# is bound to the $Name parameter and is never part of the script text.
RESTART_SCRIPT = "& { param([string]$Name) Restart-Service -Name $Name -ErrorAction Stop }"
# shutdown.exe accepts at most 10 years (315360000 seconds) after /t.
MAX_REBOOT_SECONDS = 315360000


class PipeClient(Protocol):
    def request(self, pipe_name: str, payload: dict[str, Any], timeout_s: float | None = None) -> dict[str, Any]:
        """Send one request object and return the response object. Raises SeamError on any transport failure."""


def exchange_request(stream: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """One length-prefixed JSON request and one reply on an open binary stream."""
    body = json.dumps(payload).encode("utf-8")
    stream.write(struct.pack("<i", len(body)) + body)
    stream.flush()
    head = b""
    while len(head) < 4:
        chunk = stream.read(4 - len(head))
        if not chunk:
            raise SeamError("the pipe closed before a reply arrived")
        head += chunk
    (length,) = struct.unpack("<i", head)
    if length <= 0 or length > MAX_FRAME_BYTES:
        raise SeamError(f"the pipe sent an unusable frame length {length}")
    data = b""
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            raise SeamError("the pipe closed before a full reply arrived")
        data += chunk
    try:
        response = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SeamError(f"the pipe reply was not JSON: {exc}") from exc
    if not isinstance(response, dict):
        raise SeamError("the pipe reply was not a JSON object")
    return response


class NamedPipeClient:
    """Real PipeClient. The pipe is looked up in the pipe directory first so a stopped service never waits,
    and the exchange runs on a daemon thread so a silent service cannot block beyond the timeout."""

    def __init__(self, timeout_s: float = DEFAULT_PIPE_TIMEOUT_S) -> None:
        self.timeout_s = timeout_s

    def request(self, pipe_name: str, payload: dict[str, Any], timeout_s: float | None = None) -> dict[str, Any]:
        if pipe_name != PIPE_NAME:
            raise SeamError("only the Thermal Control Suite pipe may be used")
        limit = self.timeout_s if timeout_s is None else timeout_s
        try:
            names = os.listdir(PIPE_DIR)
        except OSError as exc:
            raise SeamError(f"cannot list the named pipes: {exc}") from exc
        if pipe_name not in names:
            raise PipeAbsentError(f"pipe {pipe_name} does not exist")
        import threading
        outcome: dict[str, Any] = {}

        def work() -> None:
            try:
                with open(PIPE_DIR + pipe_name, "r+b", buffering=0) as pipe:
                    outcome["response"] = exchange_request(pipe, payload)
            except SeamError as exc:
                outcome["error"] = exc
            except OSError as exc:
                outcome["error"] = SeamError(f"cannot use pipe {pipe_name}: {exc}")

        worker = threading.Thread(target=work, name=f"control-pipe-{pipe_name}", daemon=True)
        worker.start()
        worker.join(limit)
        if worker.is_alive():
            raise SeamError(f"pipe {pipe_name} did not answer within {limit:g} seconds")
        if "error" in outcome:
            raise outcome["error"]
        return outcome["response"]


def _field(obj: dict[str, Any], name: str) -> Any:
    """Read a field by name ignoring case, because the service's JSON casing is unconfirmed."""
    for key, value in obj.items():
        if isinstance(key, str) and key.lower() == name.lower():
            return value
    return None


class WindowsActions:
    def __init__(self, config: ControlConfig, runner: CommandRunner | None = None,
                 pipe: PipeClient | None = None, *, timeout: float = 120.0):
        self.config = config
        self.runner = runner if runner is not None else SubprocessRunner()
        self.pipe = pipe if pipe is not None else NamedPipeClient()
        self.timeout = timeout

    def execute(self, command: dict) -> ActionResult:
        """Run an accepted command. Unknown actions and bad parameters fail before any call."""
        action, params = command.get("action"), command.get("params")
        if not isinstance(params, dict):
            return ActionResult(False, "refused", "params must be an object")
        if action == "fan.set_floor":
            return self.fan_set_floor(params.get("header"), params.get("min_duty"))
        if action == "fan.set_mode":
            return self.fan_set_mode(params.get("mode"))
        if action == "service.restart":
            return self.service_restart(params.get("name"))
        if action == "host.reboot":
            return self.reboot()
        if action == "agent.update":
            return self.agent_update(params.get("component"))
        return ActionResult(False, "refused", f"unsupported action {action!r}")

    def agent_update(self, component: object) -> ActionResult:
        """Not supported here: the Windows agent and control are services installed from a source archive by
        the scripts in deploy/windows, and there is no container to pull. The refusal says so plainly."""
        if component not in UPDATE_COMPONENTS:
            return ActionResult(False, "refused", "component must be agent, control or all")
        return ActionResult(False, "refused", "agent.update is not supported on Windows; run "
                                              "deploy/windows/install-agent.ps1 or install-control.ps1 again "
                                              "on the host to update")

    def _run(self, argv: list[str]) -> tuple[int, str] | ActionResult:
        try:
            done = self.runner.run(argv, self.timeout)
        except SeamError as exc:
            return ActionResult(False, "failed", _clip(str(exc)))
        return done.returncode, (done.stdout + done.stderr)

    # fan actions ------------------------------------------------------------------------------

    def _suite_configured(self) -> bool:
        return self.config.fan is not None and self.config.fan.controller == SUITE_CONTROLLER

    def fan_set_floor(self, header: object, min_duty: object) -> ActionResult:
        if not self._suite_configured():
            return ActionResult(False, "refused", "fan.controller is not thermal-control-suite")
        if not isinstance(header, str) or not HEADER_ID.fullmatch(header):
            return ActionResult(False, "refused", "invalid header name")
        if isinstance(min_duty, bool) or not isinstance(min_duty, int) or not 0 <= min_duty <= 100:
            return ActionResult(False, "refused", "min_duty must be an integer from 0 to 100")
        try:
            listing = self.pipe.request(PIPE_NAME, {"Type": "GetFans"})
        except SeamError as exc:
            return ActionResult(False, "failed", _clip(f"cannot reach the Thermal Control Suite: {exc}"))
        if _field(listing, "Success") is not True:
            return ActionResult(False, "refused",
                                _clip(f"the Suite refused GetFans: {_field(listing, 'Error') or 'no detail'}"))
        fans = _field(listing, "Fans")
        fan = next((f for f in fans if isinstance(f, dict) and _field(f, "Id") == header), None) \
            if isinstance(fans, list) else None
        if fan is None:
            return ActionResult(False, "failed", "the Suite has no fan with that id")
        zone_ids = _field(fan, "ZoneIds")
        if not isinstance(zone_ids, list):
            return ActionResult(False, "failed", "the Suite reported no zone list for that fan")
        # SetFanMapping replaces the whole mapping, so every other value is sent back unchanged.
        mapping = {"ZoneIds": zone_ids, "ControlSensorId": _field(fan, "ControlSensorId"),
                   "RpmSensorId": _field(fan, "RpmSensorId"), "MinDutyPercent": float(min_duty),
                   "MinRpm": _field(fan, "MinRpm") or 0}
        try:
            reply = self.pipe.request(PIPE_NAME, {"Type": "SetFanMapping", "FanId": header, "Mapping": mapping})
        except SeamError as exc:
            return ActionResult(False, "failed", _clip(f"cannot reach the Thermal Control Suite: {exc}"))
        if _field(reply, "Success") is not True:
            return ActionResult(False, "refused",
                                _clip(f"the Suite refused the change: {_field(reply, 'Error') or 'no detail'}"))
        if _field(reply, "Persisted") is False:
            return ActionResult(True, "done",
                                _clip(f"applied live but not saved: {_field(reply, 'Warning') or 'no detail'}"))
        return ActionResult(True, "done", f"fan {header} minimum duty set to {min_duty}")

    def fan_set_mode(self, mode: object) -> ActionResult:
        if not self._suite_configured():
            return ActionResult(False, "refused", "fan.controller is not thermal-control-suite")
        if mode not in MODES:
            return ActionResult(False, "refused", "mode must be dry_run or active")
        return ActionResult(False, "refused", "the Thermal Control Suite pipe has no request that changes dry run; "
                                              "change DryRun in its configuration instead")

    # services ---------------------------------------------------------------------------------

    def service_restart(self, name: object) -> ActionResult:
        if not isinstance(name, str) or not valid_service_name(name) or name.startswith("docker:"):
            return ActionResult(False, "refused", "invalid service name")
        if name not in self.config.restart:
            return ActionResult(False, "refused", "service is not in the local restart list")
        outcome = self._run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                             "-Command", RESTART_SCRIPT, name])
        if isinstance(outcome, ActionResult):
            return outcome
        code, output = outcome
        return ActionResult(code == 0, "done" if code == 0 else "failed", _clip(output))

    # reboot -----------------------------------------------------------------------------------

    def reboot(self) -> ActionResult:
        if not self.config.reboot.allow:
            return ActionResult(False, "refused", "reboot.allow is false")
        delay = min(effective_reboot_delay(self.config.reboot.delay_s), MAX_REBOOT_SECONDS)
        outcome = self._run([SHUTDOWN, "/r", "/t", str(delay)])
        if isinstance(outcome, ActionResult):
            return outcome
        code, output = outcome
        if code != 0:
            return ActionResult(False, "failed", _clip(output))
        return ActionResult(True, "scheduled", f"reboot in {delay} second(s); cancel with hostwatch-control cancel")

    def cancel_reboot(self) -> ActionResult:
        outcome = self._run([SHUTDOWN, "/a"])
        if isinstance(outcome, ActionResult):
            return outcome
        code, output = outcome
        if code != 0:
            return ActionResult(False, "failed", _clip(output))
        return ActionResult(True, "cancelled", "scheduled reboot cancelled")
