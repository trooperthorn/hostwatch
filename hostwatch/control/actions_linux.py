"""Linux executors for hostwatch-control: thermalctl overrides, service restarts and reboot.

Every external command goes through a `Runner` as an argument list and is never given to a
shell. Executors only run after `verify.CommandVerifier` accepted the command, but they still
validate every name and number themselves, so a bug upstream cannot put a hostile string on a
command line. Programs are named by absolute path so that the sudoers rule rendered by
`render_sudoers` matches exactly what is run.

Privilege: when the process is not root, the privileged programs are run as `sudo -n <program>`.
thermalctl refuses an overrides file that is not root-owned, so the daemon never writes
`/etc/thermalctl` itself. The new overrides text goes to `sudo -n tee <candidate>` on standard input,
`thermalctl check-config` validates the candidate, and `sudo -n mv -f <candidate> <overrides>` installs it.
Each of those is one exact command line in the sudoers rule. If any step fails the command is reported
failed, the candidate is removed with `sudo -n rm -f <candidate>`, and the live overrides and the fans
are untouched.
"""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, Sequence

from .config import ControlConfig, effective_reboot_delay, valid_service_name
from .redact import MAX_OUTPUT, redact  # noqa: F401

SYSTEMCTL = "/usr/bin/systemctl"
DOCKER = "/usr/bin/docker"
TEE = "/usr/bin/tee"
MV = "/usr/bin/mv"
RM = "/usr/bin/rm"
THERMALCTL_BIN = "/opt/thermalctl/venv/bin/thermalctl"
THERMALCTL_CONFIG = "/etc/thermalctl/config.toml"
OVERRIDES_PATH = "/etc/thermalctl/overrides.toml"
THERMALCTL_UNIT = "thermalctl"
THERMALCTL_CONTROLLER = "thermalctl"
# The candidate overrides are checked under this fixed name so the sudoers rule can name it exactly.
CANDIDATE_SUFFIX = ".candidate"
# The reboot is a transient systemd timer, so the delay is exact to the second. shutdown(8) only counts minutes.
REBOOT_UNIT = "hostwatch-reboot"
SYSTEMD_RUN = "/usr/bin/systemd-run"
MAX_REBOOT_SECONDS = 999999
HEADER_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$")
MODES = ("dry_run", "active")


@dataclass(frozen=True)
class RunResult:
    returncode: int
    output: str = ""


class Runner(Protocol):
    def __call__(self, argv: Sequence[str], timeout: float) -> RunResult: ...


def subprocess_runner(argv: Sequence[str], timeout: float) -> RunResult:
    """The real runner: an argument list, no shell, output captured and merged."""
    try:
        done = subprocess.run(list(argv), shell=False, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return RunResult(127, f"{type(exc).__name__}: {exc}")
    text = (done.stdout + done.stderr).decode("utf-8", "replace")
    return RunResult(done.returncode, text)


class Writer(Protocol):
    """Runs an argument list with `data` on its standard input."""

    def __call__(self, argv: Sequence[str], data: bytes, timeout: float) -> RunResult: ...


def subprocess_writer(argv: Sequence[str], data: bytes, timeout: float) -> RunResult:
    """The real writer: an argument list, no shell, the data on standard input, output captured and merged."""
    try:
        done = subprocess.run(list(argv), shell=False, input=data, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return RunResult(127, f"{type(exc).__name__}: {exc}")
    return RunResult(done.returncode, (done.stdout + done.stderr).decode("utf-8", "replace"))


@dataclass(frozen=True)
class ActionResult:
    ok: bool
    status: str  # done, scheduled, cancelled, failed, refused
    output: str = ""


def _clip(text: str) -> str:
    """Mask secrets, then clip, so a secret cut by the clip point is never half shown."""
    return redact(text)


class LinuxActions:
    def __init__(self, config: ControlConfig, runner: Runner = subprocess_runner, *,
                 overrides_path: str | Path = OVERRIDES_PATH, thermalctl_bin: str = THERMALCTL_BIN,
                 thermalctl_config: str = THERMALCTL_CONFIG, use_sudo: bool | None = None,
                 timeout: float = 120.0, writer: Writer = subprocess_writer):
        self.config, self.runner, self.writer, self.timeout = config, runner, writer, timeout
        self.overrides_path = Path(overrides_path)
        self.candidate_path = self.overrides_path.with_name(self.overrides_path.name + CANDIDATE_SUFFIX)
        self.thermalctl_bin, self.thermalctl_config = thermalctl_bin, thermalctl_config
        if use_sudo is None:
            use_sudo = hasattr(os, "geteuid") and os.geteuid() != 0
        self.use_sudo = use_sudo

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
        return ActionResult(False, "refused", f"unsupported action {action!r}")

    def _run(self, argv: Sequence[str]) -> RunResult:
        full = (["sudo", "-n"] if self.use_sudo else []) + list(argv)
        return self.runner(full, self.timeout)

    def _write(self, argv: Sequence[str], data: bytes) -> RunResult:
        full = (["sudo", "-n"] if self.use_sudo else []) + list(argv)
        return self.writer(full, data, self.timeout)

    # fan actions ------------------------------------------------------------------------------

    def fan_set_floor(self, header: object, min_duty: object) -> ActionResult:
        if (refused := self._fan_refusal()) is not None:
            return refused
        if not isinstance(header, str) or not HEADER_ID.fullmatch(header):
            return ActionResult(False, "refused", "invalid header name")
        if isinstance(min_duty, bool) or not isinstance(min_duty, int) or not 0 <= min_duty <= 100:
            return ActionResult(False, "refused", "min_duty must be an integer from 0 to 100")
        return self._apply_overrides(lambda mode, floors: (mode, {**floors, header: min_duty}), restart=False)

    def fan_set_mode(self, mode: object) -> ActionResult:
        if (refused := self._fan_refusal()) is not None:
            return refused
        if mode not in MODES:
            return ActionResult(False, "refused", "mode must be dry_run or active")
        return self._apply_overrides(lambda _mode, floors: (mode, floors), restart=True)

    def _read_overrides(self) -> tuple[bytes | None, str | None, dict[str, int]]:
        try:
            raw = self.overrides_path.read_bytes()
        except FileNotFoundError:
            return None, None, {}
        data = tomllib.loads(raw.decode("utf-8"))
        mode = data.get("mode")
        headers = data.get("headers", {})
        floors = {name: t["min_duty"] for name, t in headers.items()
                  if HEADER_ID.fullmatch(name) and isinstance(t, dict)
                  and isinstance(t.get("min_duty"), int) and not isinstance(t["min_duty"], bool)}
        if mode is not None and mode not in MODES:
            raise ValueError("existing overrides have an unknown mode")
        return raw, mode, floors

    @staticmethod
    def _render(mode: str | None, floors: dict[str, int]) -> bytes:
        lines = ["# Written by hostwatch-control. Changes are validated by thermalctl check-config.\n"]
        if mode is not None:
            lines.append(f'mode = "{mode}"\n')
        for name in sorted(floors):
            lines.append(f"\n[headers.{name}]\nmin_duty = {floors[name]}\n")
        return "".join(lines).encode("utf-8")

    def _discard_candidate(self) -> None:
        """Best effort removal of the candidate. It is never the live file, so a failure here changes nothing."""
        self._run([RM, "-f", str(self.candidate_path)])

    def _fan_refusal(self) -> ActionResult | None:
        fan = self.config.fan
        if fan is None or fan.controller != THERMALCTL_CONTROLLER:
            return ActionResult(False, "refused", "fan.controller is not thermalctl")
        return None

    def _apply_overrides(self, change: Callable, restart: bool) -> ActionResult:
        try:
            _previous, mode, floors = self._read_overrides()
        except (OSError, ValueError, KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            return ActionResult(False, "failed", f"cannot read the existing overrides: {exc}")
        new_mode, new_floors = change(mode, floors)
        staged = self._write([TEE, str(self.candidate_path)], self._render(new_mode, new_floors))
        if staged.returncode != 0:
            self._discard_candidate()
            return ActionResult(False, "failed", _clip(
                f"cannot write the overrides. The existing overrides and the fans were not changed. {staged.output}"))
        check = self._run([self.thermalctl_bin, "check-config", self.thermalctl_config,
                           "--overrides", str(self.candidate_path)])
        if check.returncode != 0:
            self._discard_candidate()
            return ActionResult(False, "failed", _clip(
                f"check-config rejected the overrides. The existing overrides were not changed. {check.output}"))
        installed = self._run([MV, "-f", str(self.candidate_path), str(self.overrides_path)])
        if installed.returncode != 0:
            self._discard_candidate()
            return ActionResult(False, "failed", _clip(
                f"cannot install the overrides. The existing overrides and the fans were not changed. {installed.output}"))
        if restart:
            applied = self._run([SYSTEMCTL, "restart", THERMALCTL_UNIT])
        else:
            applied = self._run([SYSTEMCTL, "kill", "-s", "HUP", THERMALCTL_UNIT])
        if applied.returncode != 0:
            verb = "restarted" if restart else "reloaded"
            return ActionResult(False, "failed", _clip(f"overrides written but thermalctl was not {verb}. {applied.output}"))
        return ActionResult(True, "done", _clip(check.output))

    # services ---------------------------------------------------------------------------------

    def service_restart(self, name: object) -> ActionResult:
        if not isinstance(name, str) or not valid_service_name(name):
            return ActionResult(False, "refused", "invalid service name")
        if name not in self.config.restart:
            return ActionResult(False, "refused", "service is not in the local restart list")
        if name.startswith("docker:"):
            argv = [DOCKER, "restart", name[len("docker:"):]]
        else:
            argv = [SYSTEMCTL, "restart", name]
        done = self._run(argv)
        return ActionResult(done.returncode == 0, "done" if done.returncode == 0 else "failed", _clip(done.output))

    # reboot -----------------------------------------------------------------------------------

    def reboot(self) -> ActionResult:
        if not self.config.reboot.allow:
            return ActionResult(False, "refused", "reboot.allow is false")
        delay = min(effective_reboot_delay(self.config.reboot.delay_s), MAX_REBOOT_SECONDS)
        done = self._run(_reboot_argv(delay))
        if done.returncode != 0:
            return ActionResult(False, "failed", _clip(done.output))
        return ActionResult(True, "scheduled", f"reboot in {delay} second(s); cancel with hostwatch-control cancel")

    def cancel_reboot(self) -> ActionResult:
        done = self._run(_cancel_argv())
        if done.returncode != 0:
            return ActionResult(False, "failed", _clip(done.output))
        return ActionResult(True, "cancelled", "scheduled reboot cancelled")


def _reboot_argv(delay: int) -> list[str]:
    return [SYSTEMD_RUN, f"--unit={REBOOT_UNIT}", f"--on-active={delay}s", SYSTEMCTL, "reboot"]


def _cancel_argv() -> list[str]:
    return [SYSTEMCTL, "stop", f"{REBOOT_UNIT}.timer"]


# sudoers --------------------------------------------------------------------------------------

_ACCOUNT = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def sudoers_commands(config: ControlConfig) -> list[str]:
    """Exactly the privileged command shapes the Linux executors can run, nothing wider."""
    cmds = []
    if config.fan is not None and config.fan.controller == "thermalctl":
        cmds += [f"{THERMALCTL_BIN} check-config {THERMALCTL_CONFIG} --overrides {OVERRIDES_PATH}{CANDIDATE_SUFFIX}",
                 f"{TEE} {OVERRIDES_PATH}{CANDIDATE_SUFFIX}",
                 f"{MV} -f {OVERRIDES_PATH}{CANDIDATE_SUFFIX} {OVERRIDES_PATH}",
                 f"{RM} -f {OVERRIDES_PATH}{CANDIDATE_SUFFIX}",
                 f"{SYSTEMCTL} kill -s HUP {THERMALCTL_UNIT}",
                 f"{SYSTEMCTL} restart {THERMALCTL_UNIT}"]
    for name in config.restart:
        if name.startswith("docker:"):
            cmds.append(f"{DOCKER} restart {name[len('docker:'):]}")
        else:
            cmds.append(f"{SYSTEMCTL} restart {name}")
    if config.reboot.allow:
        # Delays are 30 seconds or more, so two to six digits.
        cmds += [f"{SYSTEMD_RUN} --unit={REBOOT_UNIT} --on-active={'[0-9]' * n}s {SYSTEMCTL} reboot"
                 for n in range(2, 7)]
        cmds.append(" ".join(_cancel_argv()))
    unique: list[str] = []
    for cmd in cmds:
        if cmd not in unique:
            unique.append(cmd)
    return unique


def render_sudoers(config: ControlConfig, account: str = "hostwatch-control") -> str:
    if not _ACCOUNT.fullmatch(account):
        raise ValueError("invalid account name")
    lines = ["# hostwatch-control: the only commands the control account may run as root.",
             "# Check it with visudo -c -f, then copy it to /etc/sudoers.d/ with mode 0440.",
             "# Regenerate it when the restart list in control.toml changes."]
    cmds = sudoers_commands(config)
    if cmds:
        lines.append("")
        lines += [f"{account} ALL=(root) NOPASSWD: {cmd}" for cmd in cmds]
    return "\n".join(lines) + "\n"


def main_cancel() -> int:
    """Local `hostwatch-control cancel`: cancel a scheduled reboot without Observe."""
    from . import config as cfgmod
    cfg = cfgmod.load("/etc/hostwatch/control.toml")
    result = LinuxActions(cfg).cancel_reboot()
    print(result.output)
    return 0 if result.ok else 1
