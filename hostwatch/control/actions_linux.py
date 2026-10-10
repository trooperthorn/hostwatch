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

`agent.update` replaces the hostwatch-agent container with the current edge image and upgrades this daemon
from git with pip. The container is rebuilt from `docker inspect` of the running one (name, restart policy,
network mode, user, read-only root, tmpfs, capabilities, security options, extra groups, the journal gid
variable and the mounts), with the settings file /etc/hostwatch/agent.env given to docker by path, so the
ingest key never passes through this process. The old container is renamed hostwatch-agent-prev while the
new one starts and is put back when the new one fails. The daemon upgrade runs pip as root and then has
systemd restart this unit a few seconds later, after the result has been reported. Both halves run inside
the one command, so other commands wait until the pull or the install is over.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import time
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Protocol, Sequence

from . import installed
from .config import ControlConfig, effective_reboot_delay, valid_service_name
from .redact import MAX_OUTPUT, mask_secrets, redact  # noqa: F401

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
MAX_OVERRIDE_S = 900  # fixed, not configurable
# The reboot is a transient systemd timer, so the delay is exact to the second. shutdown(8) only counts minutes.
REBOOT_UNIT = "hostwatch-reboot"
SYSTEMD_RUN = "/usr/bin/systemd-run"
MAX_REBOOT_SECONDS = 999999
HEADER_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$")
MODES = ("dry_run", "active")
# agent.update. The names, the image and the install source are fixed here because the sudoers rules name
# them exactly; a container created from another image, or a daemon installed from another source, is
# reported failed rather than pulled from somewhere the rule does not cover.
AGENT_CONTAINER = "hostwatch-agent"
AGENT_PREV_CONTAINER = "hostwatch-agent-prev"
AGENT_IMAGE = "ghcr.io/trooperthorn/hostwatch:edge"
AGENT_ENV_FILE = "/etc/hostwatch/agent.env"
# Variables the Observe installer passes with -e beside the env file. Only these are copied from the old
# container; everything else in its environment came from the env file, which docker reads again itself.
AGENT_COPIED_ENV = ("HOSTWATCH_JOURNAL_GID", "HOSTWATCH_RAPL_GID")
VERSION_LABEL = "org.opencontainers.image.version"
CONTROL_VENV = "/opt/hostwatch-control/venv"
CONTROL_PIP = CONTROL_VENV + "/bin/pip"
CONTROL_PYTHON = CONTROL_VENV + "/bin/python"
CONTROL_SOURCE = "git+https://github.com/trooperthorn/hostwatch.git"
CONTROL_SPEC = f"hostwatch[control] @ {CONTROL_SOURCE}"
PIP_INSTALL_ARGS = ("install", "--quiet", "--upgrade", CONTROL_SPEC)
CONTROL_UNIT = "hostwatch-control"
CONTROL_RESTART_DELAY_S = 5
UPDATE_COMPONENTS = ("agent", "control", "all")
UPDATE_PULL_TIMEOUT_S = 600.0
UPDATE_START_TIMEOUT_S = 60.0
UPDATE_PIP_TIMEOUT_S = 600.0
# How long the new container is given before its state is read; one that exits at once is rolled back.
UPDATE_SETTLE_S = 2.0
# The note inside the result JSON is cut here so the whole result stays well under the 2000 characters the
# daemon keeps and the 4096 Observe stores.
UPDATE_NOTE_MAX = 1200


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
    # Work the daemon runs after the result has been queued and sent, so a step that ends this process (the
    # restart after a control update) cannot keep the result from being reported. Returns a RunResult or None.
    after_report: "Callable[[], RunResult | None] | None" = field(default=None, compare=False, repr=False)


def _clip(text: str) -> str:
    """Mask secrets, then clip, so a secret cut by the clip point is never half shown."""
    return redact(text)


class LinuxActions:
    def __init__(self, config: ControlConfig, runner: Runner = subprocess_runner, *,
                 overrides_path: str | Path = OVERRIDES_PATH, thermalctl_bin: str = THERMALCTL_BIN,
                 use_sudo: bool | None = None, timeout: float = 120.0, writer: Writer = subprocess_writer,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep):
        self.config, self.runner, self.writer, self.timeout = config, runner, writer, timeout
        self.clock, self.sleep = clock, sleep
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
        if action == "agent.update":
            return self.agent_update(params.get("component"))
        return ActionResult(False, "refused", f"unsupported action {action!r}")

    def _run(self, argv: Sequence[str], timeout: float | None = None) -> RunResult:
        full = (["sudo", "-n"] if self.use_sudo else []) + list(argv)
        return self.runner(full, self.timeout if timeout is None else timeout)

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
        if command_expires_at is not None and (isinstance(command_expires_at, bool)
                                               or not isinstance(command_expires_at, int)):
            return ActionResult(False, "refused", "the command expiry must be an integer")
        expires_at = self._expiry(command_expires_at)
        if expires_at <= int(self.clock()):
            return ActionResult(False, "failed", "the command has already expired, so no override was installed")
        state = self._load()
        if isinstance(state, ActionResult):
            return state
        mode, floors, file_expiry = state
        # thermalctl applies expires_at to the whole file, so a floor with no expiry cannot share a file with one,
        # and it refuses an expiry beside a mode. Both would make an override outlive its purpose, so refuse.
        if mode is not None:
            return ActionResult(False, "refused", "the overrides file sets a mode, which cannot carry an expiry, "
                                "so the floor was not installed")
        if floors and file_expiry is None:
            return ActionResult(False, "refused", "the overrides file holds floors without an expiry, which an "
                                "expiry would silently remove, so the floor was not installed")
        if file_expiry is not None:
            # Floors already in the file never live longer than they were first given.
            expires_at = min(expires_at, int(file_expiry))
        return self._install(None, {**floors, header: min_duty}, expires_at, restart=False)

    def fan_set_mode(self, mode: object) -> ActionResult:
        if (refused := self._fan_refusal()) is not None:
            return refused
        if mode not in MODES:
            return ActionResult(False, "refused", "mode must be dry_run or active")
        state = self._load()
        if isinstance(state, ActionResult):
            return state
        _mode, floors, file_expiry = state
        if floors and file_expiry is not None:
            # A mode cannot carry an expiry, and dropping it would make the time-bounded floors permanent.
            return ActionResult(False, "refused", "the overrides file holds time-bounded floors, which a mode "
                                "change would make permanent, so the mode was not changed")
        return self._install(mode, floors, None, restart=True)

    def _expiry(self, command_expires_at: object) -> int:
        """Epoch second at which a floor override stops applying: the signed command's expiry, capped."""
        cap = int(self.clock()) + MAX_OVERRIDE_S
        if isinstance(command_expires_at, bool) or not isinstance(command_expires_at, int):
            return cap
        return min(command_expires_at, cap)

    @staticmethod
    def _file_expiry(value: object) -> "int | float | None":
        """The file's expires_at as epoch seconds. thermalctl accepts epoch seconds or a TOML datetime with an
        offset, so both are read; anything else is refused, never treated as no expiry."""
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError("existing overrides have an expires_at datetime without an offset")
            return value.timestamp()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError("existing overrides have an expires_at that is not epoch seconds or a datetime")
        return value

    def _read_overrides(self) -> tuple[bytes | None, str | None, dict[str, int | float], int | float | None]:
        try:
            raw = self.overrides_path.read_bytes()
        except FileNotFoundError:
            return None, None, {}, None
        data = tomllib.loads(raw.decode("utf-8"))
        mode = data.get("mode")
        headers = data.get("headers", {})
        expiry = self._file_expiry(data.get("expires_at"))
        if not isinstance(headers, dict):
            raise ValueError("existing overrides have a headers entry that is not a table")
        # thermalctl accepts a float floor such as 32.5 and any string header id, so every floor is kept as written.
        # An entry that cannot be kept is refused rather than dropped, so an owner's edit is never lost silently.
        floors: dict[str, int | float] = {}
        for name, table in headers.items():
            duty = table.get("min_duty") if isinstance(table, dict) else None
            if isinstance(duty, bool) or not isinstance(duty, (int, float)) or not math.isfinite(duty):
                raise ValueError(f"existing overrides have a header {name!r} that is not a table with a numeric min_duty")
            floors[name] = duty
        if mode is not None and mode not in MODES:
            raise ValueError("existing overrides have an unknown mode")
        return raw, mode, floors, expiry

    def _load(self) -> "tuple[str | None, dict[str, int | float], int | float | None] | ActionResult":
        """The mode, floors and expiry still in force. thermalctl ignores an expired file, so its contents are
        dropped here rather than brought back to life with a fresh expiry."""
        try:
            _raw, mode, floors, expiry = self._read_overrides()
        except (OSError, ValueError, KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            return ActionResult(False, "failed", f"cannot read the existing overrides: {exc}")
        if expiry is not None and expiry <= self.clock():
            return None, {}, None
        return mode, floors, expiry

    _BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")

    @classmethod
    def _key(cls, name: str) -> str:
        if cls._BARE_KEY.fullmatch(name):
            return name
        # ensure_ascii=False keeps characters outside the BMP whole; json would write a surrogate pair TOML rejects.
        return json.dumps(name, ensure_ascii=False).replace(chr(127), chr(92) + "u007f")

    @classmethod
    def _render(cls, mode: str | None, floors: dict[str, int | float], expires_at: int | None = None) -> bytes:
        lines = ["# Written by hostwatch-control. Changes are validated by thermalctl install-override.\n"]
        if mode is not None:
            lines.append(f'mode = "{mode}"\n')
        if expires_at is not None:
            lines.append(f"expires_at = {expires_at}\n")
        for name in sorted(floors):
            lines.append(f"\n[headers.{cls._key(name)}]\nmin_duty = {floors[name]!r}\n")
        return "".join(lines).encode("utf-8")

    def _fan_refusal(self) -> ActionResult | None:
        fan = self.config.fan
        if fan is None or fan.controller != THERMALCTL_CONTROLLER:
            return ActionResult(False, "refused", "fan.controller is not thermalctl")
        return None

    def _install(self, mode: str | None, floors: dict[str, int | float], expires_at: int | None,
                 restart: bool) -> ActionResult:
        installed = self._write([self.thermalctl_bin, *INSTALL_OVERRIDE_ARGS], self._render(mode, floors, expires_at))
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


    # agent.update ------------------------------------------------------------------------------

    def agent_update(self, component: object) -> ActionResult:
        if component not in UPDATE_COMPONENTS:
            return ActionResult(False, "refused", "component must be agent, control or all")
        policy = self.config.update
        missing = [name for name in ("agent", "control")
                   if component in (name, "all") and not getattr(policy, name)]
        if missing:
            joined = " and ".join(f"update.{m}" for m in missing)
            return ActionResult(False, "refused", f"{joined} {'is' if len(missing) == 1 else 'are'} false")
        report = UpdateReport(component)
        after: Callable[[], RunResult | None] | None = None
        if component in ("agent", "all"):
            if not self._update_agent(report):
                return report.result(False)
        if component in ("control", "all"):
            after = self._update_control(report)
            if after is None:
                return report.result(False)
        return report.result(True, after)

    # the container --------------------------------------------------------------------------

    def _docker_inspect(self, name: str) -> "dict | str":
        """The inspect record of a container, or the reason it could not be read."""
        done = self._run([DOCKER, "inspect", "--type", "container", name])
        if done.returncode != 0:
            return f"docker inspect {name} failed: {done.output.strip() or 'no output'}"
        try:
            data = json.loads(done.output)
        except ValueError:
            return f"docker inspect {name} did not return JSON"
        if not isinstance(data, list) or not data or not isinstance(data[0], dict):
            return f"docker inspect {name} returned no container"
        return data[0]

    def _image_inspect(self, ref: str) -> "tuple[str, str | None] | str":
        """(image id, version label) of a local image, or the reason it could not be read."""
        done = self._run([DOCKER, "image", "inspect", ref])
        if done.returncode != 0:
            return f"docker image inspect {ref} failed: {done.output.strip() or 'no output'}"
        try:
            data = json.loads(done.output)
        except ValueError:
            return f"docker image inspect {ref} did not return JSON"
        if not isinstance(data, list) or not data or not isinstance(data[0], dict) \
                or not isinstance(data[0].get("Id"), str):
            return f"docker image inspect {ref} returned no image"
        return data[0]["Id"], _label(data[0].get("Config"), VERSION_LABEL)

    def _update_agent(self, report: "UpdateReport") -> bool:
        """Pull the image the running container came from and recreate the container when the image changed.
        True when the agent is current afterwards (already or newly), False with the reason in the report."""
        old = self._docker_inspect(AGENT_CONTAINER)
        if isinstance(old, str):
            return report.fail(f"no {AGENT_CONTAINER} container to update ({old})")
        old_id = old.get("Image")
        if not isinstance(old_id, str) or not old_id:
            return report.fail("docker inspect gave no image id for the running container")
        report.old_image_id = short_image_id(old_id)
        report.agent_old_version = _label(old.get("Config"), VERSION_LABEL)
        config = old.get("Config") if isinstance(old.get("Config"), dict) else {}
        ref = _tag_reference(config.get("Image"))
        if ref is None:
            report.say(f"the running container was not created from a repository tag, so {AGENT_IMAGE} is pulled")
            ref = AGENT_IMAGE
        if ref != AGENT_IMAGE:
            return report.fail(f"the running container was created from {ref}, but only {AGENT_IMAGE} may be "
                               "pulled on this host; the running agent was not touched")
        try:
            argv = agent_run_argv(old, ref)
        except ValueError as exc:
            return report.fail(f"cannot rebuild the container from docker inspect: {exc}; "
                               "the running agent was not touched")
        pulled = self._run([DOCKER, "pull", ref], UPDATE_PULL_TIMEOUT_S)
        if pulled.returncode != 0:
            return report.fail(f"docker pull {ref} failed; the running agent was not touched: "
                               f"{pulled.output.strip() or 'no output'}")
        new = self._image_inspect(ref)
        if isinstance(new, str):
            return report.fail(f"{new}; the running agent was not touched")
        new_id, new_version = new
        report.new_image_id = short_image_id(new_id)
        report.agent_new_version = new_version
        if new_id == old_id:
            report.say("already current")
            return True
        return self._recreate_agent(report, argv)

    def _recreate_agent(self, report: "UpdateReport", argv: list[str]) -> bool:
        """The installer's sequence: the old container is kept under the prev name until the new one runs."""
        self._run([DOCKER, "rm", "-f", AGENT_PREV_CONTAINER])  # a leftover from an earlier failure, if any
        stopped = self._run([DOCKER, "stop", AGENT_CONTAINER])
        if stopped.returncode != 0:
            return report.fail(f"docker stop {AGENT_CONTAINER} failed, so it was not replaced: "
                               f"{stopped.output.strip() or 'no output'}")
        renamed = self._run([DOCKER, "rename", AGENT_CONTAINER, AGENT_PREV_CONTAINER])
        if renamed.returncode != 0:
            started = self._run([DOCKER, "start", AGENT_CONTAINER])
            back = ("started again" if started.returncode == 0
                    else "could not be started again: " + (started.output.strip() or "no output"))
            return report.fail(f"docker rename failed, so the old container was kept and {back}: "
                               f"{renamed.output.strip() or 'no output'}")
        ran = self._run(argv, UPDATE_START_TIMEOUT_S)
        if ran.returncode != 0:
            return report.fail(f"the new container did not start ({ran.output.strip() or 'no output'}); "
                               + self._restore_prev())
        self.sleep(UPDATE_SETTLE_S)
        state = self._docker_inspect(AGENT_CONTAINER)
        running = isinstance(state, dict) and bool((state.get("State") or {}).get("Running"))
        if not running:
            why = state if isinstance(state, str) else "it is not running"
            return report.fail(f"the new container exited right after starting ({why}); " + self._restore_prev())
        removed = self._run([DOCKER, "rm", "-f", AGENT_PREV_CONTAINER])
        report.say("container recreated from the new image")
        if removed.returncode != 0:
            report.say(f"the old container {AGENT_PREV_CONTAINER} could not be removed and is left stopped: "
                       f"{removed.output.strip() or 'no output'}")
        return True

    def _restore_prev(self) -> str:
        """Put the old container back under its name and start it. The text says what happened."""
        self._run([DOCKER, "rm", "-f", AGENT_CONTAINER])
        renamed = self._run([DOCKER, "rename", AGENT_PREV_CONTAINER, AGENT_CONTAINER])
        if renamed.returncode != 0:
            return (f"the old container could not be renamed back from {AGENT_PREV_CONTAINER} and is stopped: "
                    f"{renamed.output.strip() or 'no output'}")
        started = self._run([DOCKER, "start", AGENT_CONTAINER], UPDATE_START_TIMEOUT_S)
        if started.returncode != 0:
            return f"the old container was renamed back but did not start: {started.output.strip() or 'no output'}"
        return "the old container was put back and is running"

    # this daemon ----------------------------------------------------------------------------

    def _update_control(self, report: "UpdateReport") -> "Callable[[], RunResult | None] | None":
        """pip-upgrade the daemon's own environment. Returns the step that schedules the restart, to be run
        after the result has been reported, or None when the update failed."""
        if not os.access(SYSTEMD_RUN, os.X_OK):
            report.fail(f"systemd-run is not available at {SYSTEMD_RUN}, so the daemon could not schedule its "
                        "own restart; control was not updated")
            return None
        report.control_old_version = installed.describe()
        done = self._run([CONTROL_PIP, *PIP_INSTALL_ARGS], UPDATE_PIP_TIMEOUT_S)
        if done.returncode != 0:
            report.fail(f"pip install failed, so the running daemon is unchanged: {done.output.strip() or 'no output'}")
            return None
        report.control_new_version = self._installed_in_venv()
        report.say(f"control installed; the service restarts {CONTROL_RESTART_DELAY_S} s after this result is reported")

        def restart() -> RunResult:
            return self._run(_control_restart_argv())

        return restart

    def _installed_in_venv(self) -> str | None:
        """The version the venv interpreter now reports, which is the code the restarted daemon will run."""
        done = self.runner([CONTROL_PYTHON, "-m", "hostwatch.control.installed"], self.timeout)
        text = done.output.strip()
        return text if done.returncode == 0 and text else None


class UpdateReport:
    """The fields of the agent.update result, rendered as the JSON text Observe shows."""

    def __init__(self, component: str) -> None:
        self.component = component
        self.old_image_id: str | None = None
        self.new_image_id: str | None = None
        self.agent_old_version: str | None = None
        self.agent_new_version: str | None = None
        self.control_old_version: str | None = None
        self.control_new_version: str | None = None
        self.notes: list[str] = []

    def say(self, text: str) -> None:
        self.notes.append(text)

    def fail(self, text: str) -> bool:
        self.notes.append(text)
        return False

    def _version(self, agent: str | None, control: str | None) -> str | None:
        if self.component == "agent":
            return agent
        if self.component == "control":
            return control
        return f"agent {agent or 'unknown'}; control {control or 'unknown'}"

    def result(self, ok: bool, after_report: "Callable[[], RunResult | None] | None" = None) -> ActionResult:
        note = mask_secrets("; ".join(self.notes))
        if len(note) > UPDATE_NOTE_MAX:
            note = note[:UPDATE_NOTE_MAX] + "...[truncated]"
        body = {"component": self.component, "old_image_id": self.old_image_id, "new_image_id": self.new_image_id,
                "old_version": self._version(self.agent_old_version, self.control_old_version),
                "new_version": self._version(self.agent_new_version, self.control_new_version), "note": note}
        return ActionResult(ok, "done" if ok else "failed", json.dumps(body), after_report)


def short_image_id(image_id: str) -> str:
    """`sha256:` plus the first twelve hex digits, as `docker ps` shows it. The full 64 digit id would be
    masked as a secret-shaped hex run by both this daemon's redaction and Observe's."""
    algo, _, digest = image_id.partition(":")
    return f"{algo}:{digest[:12]}" if digest else image_id[:12]


def _label(config: object, name: str) -> str | None:
    labels = config.get("Labels") if isinstance(config, dict) else None
    value = labels.get(name) if isinstance(labels, dict) else None
    return value if isinstance(value, str) and value else None


_IMAGE_REF = re.compile(r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")


def _tag_reference(value: object) -> str | None:
    """The `repository:tag` a container was created from, or None when it was an id or a digest reference."""
    if not isinstance(value, str) or value.startswith("sha256:") or "@" in value:
        return None
    return value if _IMAGE_REF.fullmatch(value) else None


_PLAIN = re.compile(r"^[^\s\x00-\x1f\x7f-]\S*$")


def _plain(value: object, what: str) -> str:
    """A value from docker inspect that is safe as one argument: no whitespace, no control characters and
    not starting with a dash, so it can never be read as a further option."""
    if not isinstance(value, str) or not _PLAIN.fullmatch(value):
        raise ValueError(f"{what} {value!r} is not a plain value")
    return value


def agent_run_argv(inspect: dict, image: str) -> list[str]:
    """The `docker run` that recreates the container the Observe installer made, read back from its inspect
    record. The env file is given by path because its contents are not recoverable from inspect and must
    not pass through this process. Raises ValueError on a value that cannot be put on a command line."""
    host = inspect.get("HostConfig") if isinstance(inspect.get("HostConfig"), dict) else {}
    config = inspect.get("Config") if isinstance(inspect.get("Config"), dict) else {}
    argv = [DOCKER, "run", "--detach", "--name", AGENT_CONTAINER]
    policy = host.get("RestartPolicy") if isinstance(host.get("RestartPolicy"), dict) else {}
    restart = policy.get("Name") or "no"
    count = policy.get("MaximumRetryCount")
    if restart == "on-failure" and isinstance(count, int) and not isinstance(count, bool) and count > 0:
        restart = f"on-failure:{count}"
    argv += ["--restart", _plain(restart, "restart policy")]
    argv += ["--network", _plain(host.get("NetworkMode") or "default", "network mode")]
    if config.get("User"):
        argv += ["--user", _plain(config["User"], "user")]
    if host.get("ReadonlyRootfs"):
        argv.append("--read-only")
    tmpfs = host.get("Tmpfs") if isinstance(host.get("Tmpfs"), dict) else {}
    for dest in sorted(tmpfs):
        opts = tmpfs[dest]
        argv += ["--tmpfs", _plain(dest if not opts else f"{dest}:{opts}", "tmpfs")]
    for cap in host.get("CapDrop") or []:
        argv += ["--cap-drop", _plain(cap, "capability")]
    for cap in host.get("CapAdd") or []:
        argv += ["--cap-add", _plain(cap, "capability")]
    for opt in host.get("SecurityOpt") or []:
        argv += ["--security-opt", _plain(opt, "security option")]
    for group in host.get("GroupAdd") or []:
        argv += ["--group-add", _plain(str(group), "group")]
    for entry in config.get("Env") or []:
        name, sep, _value = entry.partition("=") if isinstance(entry, str) else ("", "", "")
        if sep and name in AGENT_COPIED_ENV:
            argv += ["--env", _plain(entry, "environment entry")]
    argv += ["--env-file", AGENT_ENV_FILE]
    for mount in inspect.get("Mounts") or []:
        if not isinstance(mount, dict):
            continue
        kind, dest = mount.get("Type"), mount.get("Destination")
        source = mount.get("Source") if kind == "bind" else mount.get("Name") if kind == "volume" else None
        if not source or not dest:
            continue
        spec = f"{source}:{dest}" + ("" if mount.get("RW", True) else ":ro")
        argv += ["--volume", _plain(spec, "mount")]
    argv.append(_plain(image, "image"))
    return argv


def _control_restart_argv() -> list[str]:
    return [SYSTEMD_RUN, f"--on-active={CONTROL_RESTART_DELAY_S}", SYSTEMCTL, "restart", CONTROL_UNIT]


def _reboot_argv(delay: int) -> list[str]:
    return [SYSTEMD_RUN, f"--unit={REBOOT_UNIT}", f"--on-active={delay}s", SYSTEMCTL, "reboot"]


def _cancel_argv() -> list[str]:
    return [SYSTEMCTL, "stop", f"{REBOOT_UNIT}.timer"]


# sudoers --------------------------------------------------------------------------------------

_ACCOUNT = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
# Characters that end a command in the sudoers grammar (`,` and `:`), the escape itself, and the fnmatch
# wildcards, each written with a backslash so the rule matches the literal text. `=` is left as it is:
# sudo's lexer keeps it inside an argument, and the reboot rules have always written it bare.
_SUDOERS_SPECIAL = re.compile(r"[\\,:*?\[\]]")


def sudoers_literal(text: str) -> str:
    """`text` as one exact argument in a sudoers rule."""
    return _SUDOERS_SPECIAL.sub(lambda m: "\\" + m.group(0), text)


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
    if config.update.agent:
        image = sudoers_literal(AGENT_IMAGE)
        cmds += [f"{DOCKER} inspect --type container {AGENT_CONTAINER}",
                 f"{DOCKER} pull {image}",
                 f"{DOCKER} image inspect {image}",
                 f"{DOCKER} rm -f {AGENT_PREV_CONTAINER}",
                 f"{DOCKER} stop {AGENT_CONTAINER}",
                 f"{DOCKER} rename {AGENT_CONTAINER} {AGENT_PREV_CONTAINER}",
                 # The only wildcard: the run arguments come from docker inspect of the old container, so the
                 # rule can fix the subcommand and the name but not the rest. See the file header.
                 f"{DOCKER} run --detach --name {AGENT_CONTAINER} *",
                 f"{DOCKER} rm -f {AGENT_CONTAINER}",
                 f"{DOCKER} rename {AGENT_PREV_CONTAINER} {AGENT_CONTAINER}",
                 f"{DOCKER} start {AGENT_CONTAINER}"]
    if config.update.control:
        cmds += [f"{CONTROL_PIP} {' '.join(sudoers_literal(a) for a in PIP_INSTALL_ARGS)}",
                 " ".join(_control_restart_argv())]
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
             "# Regenerate it when the restart list or the update flags in control.toml change.",
             "#",
             "# The thermalctl rule matches thermal-control-linux's example exactly: no arguments, so sudo refuses",
             "# --overrides, --config and --from, and the candidate comes on standard input. The thermalctl path,",
             "# every directory above it and the interpreter it points to must be root-owned and not writable by",
             "# any other user, or the account could replace them and gain root."]
    if config.update.agent:
        lines += ["#",
                  "# The update rules let the account pull one fixed image and recreate the one named container.",
                  "# The docker run rule is the only one with a wildcard: it fixes the subcommand and the name but",
                  "# not the mounts and options, which the daemon copies from the old container. Whoever can run",
                  "# that rule can start a root container with any mount, which is root on the host, so the rule",
                  "# is a grant to the account and not a limit on what a container may do."]
    if config.update.control:
        lines += ["#",
                  "# The pip rule upgrades the daemon's own environment from the one fixed git source, and the",
                  "# systemd-run rule restarts the daemon a few seconds later. The venv must be root-owned and not",
                  "# writable by any other user, since pip runs as root inside it."]
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
