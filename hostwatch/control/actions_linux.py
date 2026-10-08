"""Linux executors for hostwatch-control: thermalctl overrides, service restarts and reboot.

Every external command goes through a `Runner` as an argument list and is never given to a
shell. Executors only run after `verify.CommandVerifier` accepted the command, but they still
validate every name and number themselves, so a bug upstream cannot put a hostile string on a
command line. Programs are named by absolute path so that the sudoers rule rendered by
`render_sudoers` matches exactly what is run.

Privilege: when the process is not root, the privileged programs are run as `sudo -n <program>`.
thermalctl refuses an overrides file that is not root-owned, so the daemon never writes
`/etc/thermalctl` itself. The new overrides text goes to `sudo -n thermalctl install-override` on standard
input and nothing else: thermalctl validates it with the code the service uses, replaces the live file
atomically with root ownership and signals the service. That is one exact command line in the sudoers rule,
so the account gets no generic tee, mv or rm. If thermalctl exits non-zero the command is reported failed
with its message, and the live overrides and the fans are untouched. Every floor already in the file,
integer or float, is kept, and a floor change carries an `expires_at` so it never outlives its purpose.
"""

from __future__ import annotations

import math
import os
import re
import subprocess
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, Sequence

from .config import ControlConfig, effective_reboot_delay, valid_service_name
from .redact import MAX_OUTPUT, redact  # noqa: F401

SYSTEMCTL = "/usr/bin/systemctl"
DOCKER = "/usr/bin/docker"
THERMALCTL_BIN = "/opt/thermalctl/venv/bin/thermalctl"
OVERRIDES_PATH = "/etc/thermalctl/overrides.toml"
THERMALCTL_UNIT = "thermalctl"
THERMALCTL_CONTROLLER = "thermalctl"
# The one privileged command that delivers overrides. It takes no arguments: the candidate is on standard input
# and thermalctl's own defaults name the config and the live file, so the sudoers rule can match it exactly.
INSTALL_OVERRIDE_ARGS = ("install-override",)
# A floor override expires with the signed command, and never later than this many seconds from now.
MAX_OVERRIDE_S = 900
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
                 use_sudo: bool | None = None, timeout: float = 120.0, writer: Writer = subprocess_writer,
                 clock: Callable[[], float] = time.time):
        self.config, self.runner, self.writer, self.timeout = config, runner, writer, timeout
        self.clock = clock
        # Only read here: thermalctl installs to its own default path, which the sudoers rule names.
        self.overrides_path = Path(overrides_path)
        self.thermalctl_bin = thermalctl_bin
        if use_sudo is None:
            use_sudo = hasattr(os, "geteuid") and os.geteuid() != 0
        self.use_sudo = use_sudo

    def execute(self, command: dict) -> ActionResult:
        """Run an accepted command. Unknown actions and bad parameters fail before any call."""
        action, params = command.get("action"), command.get("params")
        if not isinstance(params, dict):
            return ActionResult(False, "refused", "params must be an object")
        if action == "fan.set_floor":
            return self.fan_set_floor(params.get("header"), params.get("min_duty"), command.get("expires_at"))
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

    def fan_set_floor(self, header: object, min_duty: object, command_expires_at: object = None) -> ActionResult:
        if (refused := self._fan_refusal()) is not None:
            return refused
        if not isinstance(header, str) or not HEADER_ID.fullmatch(header):
            return ActionResult(False, "refused", "invalid header name")
        if isinstance(min_duty, bool) or not isinstance(min_duty, int) or not 0 <= min_duty <= 100:
            return ActionResult(False, "refused", "min_duty must be an integer from 0 to 100")
        return self._apply_overrides(lambda mode, floors: (mode, {**floors, header: min_duty}), restart=False,
                                     expires_at=self._expiry(command_expires_at))

    def fan_set_mode(self, mode: object) -> ActionResult:
        if (refused := self._fan_refusal()) is not None:
            return refused
        if mode not in MODES:
            return ActionResult(False, "refused", "mode must be dry_run or active")
        return self._apply_overrides(lambda _mode, floors: (mode, floors), restart=True)

    def _expiry(self, command_expires_at: object) -> int:
        """Epoch second at which a floor override stops applying: the signed command's expiry, capped."""
        cap = int(self.clock()) + MAX_OVERRIDE_S
        if isinstance(command_expires_at, bool) or not isinstance(command_expires_at, int):
            return cap
        return min(command_expires_at, cap)

    def _read_overrides(self) -> tuple[bytes | None, str | None, dict[str, int | float]]:
        try:
            raw = self.overrides_path.read_bytes()
        except FileNotFoundError:
            return None, None, {}
        data = tomllib.loads(raw.decode("utf-8"))
        mode = data.get("mode")
        headers = data.get("headers", {})
        # thermalctl accepts a float floor such as 32.5, so every number is kept as it was written.
        floors = {name: t["min_duty"] for name, t in headers.items()
                  if HEADER_ID.fullmatch(name) and isinstance(t, dict)
                  and isinstance(t.get("min_duty"), (int, float)) and not isinstance(t["min_duty"], bool)
                  and math.isfinite(t["min_duty"])}
        if mode is not None and mode not in MODES:
            raise ValueError("existing overrides have an unknown mode")
        return raw, mode, floors

    @staticmethod
    def _render(mode: str | None, floors: dict[str, int | float], expires_at: int | None = None) -> bytes:
        lines = ["# Written by hostwatch-control. Changes are validated by thermalctl install-override.\n"]
        if mode is not None:
            lines.append(f'mode = "{mode}"\n')
        if expires_at is not None:
            lines.append(f"expires_at = {expires_at}\n")
        for name in sorted(floors):
            lines.append(f"\n[headers.{name}]\nmin_duty = {floors[name]!r}\n")
        return "".join(lines).encode("utf-8")

    def _fan_refusal(self) -> ActionResult | None:
        fan = self.config.fan
        if fan is None or fan.controller != THERMALCTL_CONTROLLER:
            return ActionResult(False, "refused", "fan.controller is not thermalctl")
        return None

    def _apply_overrides(self, change: Callable, restart: bool, expires_at: int | None = None) -> ActionResult:
        try:
            _previous, mode, floors = self._read_overrides()
        except (OSError, ValueError, KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            return ActionResult(False, "failed", f"cannot read the existing overrides: {exc}")
        new_mode, new_floors = change(mode, floors)
        if new_mode is not None:
            # thermalctl refuses an expiry beside a mode, because a mode change needs a restart to revert.
            expires_at = None
        elif expires_at is not None and expires_at <= int(self.clock()):
            return ActionResult(False, "failed", "the command has already expired, so no override was installed")
        installed = self._write([self.thermalctl_bin, *INSTALL_OVERRIDE_ARGS],
                                self._render(new_mode, new_floors, expires_at))
        if installed.returncode != 0:
            return ActionResult(False, "failed", _clip(
                "thermalctl install-override failed. The existing overrides and the fans were not changed. "
                f"{installed.output}"))
        if restart:
            # install-override signals the service itself, but a reload refuses a mode change, so restart.
            applied = self._run([SYSTEMCTL, "restart", THERMALCTL_UNIT])
            if applied.returncode != 0:
                return ActionResult(False, "failed", _clip(
                    f"overrides written but thermalctl was not restarted. {applied.output}"))
        return ActionResult(True, "done", _clip(installed.output))

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
        cmds += [" ".join([THERMALCTL_BIN, *INSTALL_OVERRIDE_ARGS]),
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
             "# Regenerate it when the restart list in control.toml changes.",
             "#",
             "# The thermalctl rule matches thermal-control-linux's example exactly: no arguments, so sudo refuses",
             "# --overrides, --config and --from, and the candidate comes on standard input. The thermalctl path,",
             "# every directory above it and the interpreter it points to must be root-owned and not writable by",
             "# any other user, or the account could replace them and gain root."]
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
