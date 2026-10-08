"""The hostwatch-control pull loop.

Every cycle the daemon first replays any results that could not be sent earlier, then asks Observe
for the commands waiting for this host (`GET /api/v1/control/commands?host=`, bearer `wpc_` key) and
handles them one at a time in `seq` order. Each command goes through `CommandVerifier` (signature,
host, expiry, id, seq, local allowlist). An accepted command is executed by the platform executor and
a refused one is not executed. Either way a result is written to the durable outbox first and then
posted to `POST /api/v1/control/results`, so a network failure or a restart never loses the report.

The daemon only ever dials out. It opens no listening port. The key is read from the environment or
the protected settings file, is sent only as a bearer header and is never logged. Output sent back is
clipped and has recognisable secrets masked, but masking is a courtesy and not a guarantee.

The pull answer is {"host", "commands": [...signed commands...], "cancel": [command ids]}. `cancel` lists this
host's scheduled commands that an admin cancelled; for each one that this daemon has a pending reboot for, it
cancels the reboot locally and reports `cancelled`. An id it never pulled is ignored.

A result is posted as exactly the body the Observe results route validates (it refuses unknown fields):
  {"id", "state", "output", "started_at", "finished_at"}
`state` is done, failed, refused, scheduled or cancelled. A reboot is reported `scheduled` when the timer is
set and `done` or `failed` later for the same id. For a refusal or a failure `output` starts with the stable
reason code from `verify.py` (for example `unit_not_allowed: ...`). The richer record (host, action, seq,
reason) stays in the local outbox. Results are only posted for commands this host pulled. A command that was
already executed and is pulled again is answered with its stored result, never refused as a replay.

Settings (environment, optionally seeded from a KEY=value file named control.env in the data directory):
  HOSTWATCH_CONTROL_URL         Observe base URL, for example https://observe.example.lan:8443
  HOSTWATCH_CONTROL_KEY         the host's wpc_ control key
  HOSTWATCH_CONTROL_CONFIG      path of control.toml (default /etc/hostwatch/control.toml, or control.toml in
                                the data directory on Windows)
  HOSTWATCH_CONTROL_DATA_DIR    replay state, result outbox and logs (default /var/lib/hostwatch-control,
                                or C:/ProgramData/hostwatch on Windows)
  HOSTWATCH_CONTROL_INTERVAL_S  poll interval, 5 to 300 (default 5)
"""

from __future__ import annotations

import logging
import os
import re
import signal
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from . import bootid
from . import config as cfgmod
from . import identity
from .actions_linux import ActionResult
from .outbox import OUTBOX_FILE, ResultOutbox
from .redact import redact
from .signing import SigningUnavailable
from .state import STATE_FILE
from .verify import REPLAYED_ID, CommandVerifier

log = logging.getLogger("hostwatch.control")

COMMANDS_PATH = "/api/v1/control/commands"
RESULTS_PATH = "/api/v1/control/results"
KEY_PREFIX = "wpc_"
MIN_INTERVAL_S = 5.0
MAX_INTERVAL_S = 300.0
MAX_BACKOFF_S = 60.0
HTTP_TIMEOUT_S = 10.0
MAX_PER_PULL = 20
# 409 is final: Observe already has a result for that command id, so the copy is dropped.
DROP_STATUSES = frozenset({409})
MAX_OUTPUT_CHARS = 4096  # Observe keeps this much of the output and cuts the rest
MAX_CANCEL_IDS = 100
NO_SUCH_COMMAND = "no such command for this host"
RESOLVE_GRACE_S = 30.0
# A restarted daemon on the same boot waits this long past the due time for the host to go down, then reports failed.
BOOT_WAIT_S = 600.0
RESULT_LOST = "result_lost"
# A 4xx answer that will not change on a retry: the body is refused as it stands. The result is parked
# with the reason (never deleted, because it may report a real reboot) so the results behind it go on.
# Not here: 401 and 403 (a key problem fixed on the Observe side), 404 (the route may not exist yet; a 404
# that says "no such command for this host" is permanent and is parked), 408, 425 and 429 (retry later).
# Those, and every 5xx, keep the result queued.
RETRYABLE_4XX = frozenset({401, 403, 404, 408, 425, 429})
LINUX_DATA_DIR = Path("/var/lib/hostwatch-control")
LINUX_CONFIG = Path("/etc/hostwatch/control.toml")
WINDOWS_DATA_DIR = Path("C:/ProgramData/hostwatch")
ENV_FILE_NAME = "control.env"
SIGNING_UNAVAILABLE = "signing_unavailable"

class SettingsError(Exception):
    """The daemon cannot start with the settings it was given."""


@dataclass(frozen=True)
class Settings:
    url: str
    key: str
    config_path: Path
    data_dir: Path
    interval_s: float = MIN_INTERVAL_S

    def __repr__(self) -> str:  # the key must never reach a log line through a repr
        return f"Settings(url={self.url!r}, config_path={self.config_path!r}, data_dir={self.data_dir!r})"


def default_data_dir(platform: str | None = None) -> Path:
    return WINDOWS_DATA_DIR if (platform or sys.platform) == "win32" else LINUX_DATA_DIR


def load_settings(environ: Mapping[str, str] | None = None, *, data_dir: str | Path | None = None,
                  config_path: str | Path | None = None, platform: str | None = None) -> Settings:
    env = os.environ if environ is None else environ
    folder = Path(data_dir or env.get("HOSTWATCH_CONTROL_DATA_DIR") or default_data_dir(platform))
    chosen = config_path or env.get("HOSTWATCH_CONTROL_CONFIG")
    if chosen:
        config = Path(chosen)
    elif (platform or sys.platform) == "win32":
        config = folder / "control.toml"
    else:
        config = LINUX_CONFIG
    url = (env.get("HOSTWATCH_CONTROL_URL") or "").strip().rstrip("/")
    if not re.match(r"^https?://[^/\s]+", url):
        raise SettingsError("HOSTWATCH_CONTROL_URL must be the Observe base URL, starting with http:// or https://")
    key = (env.get("HOSTWATCH_CONTROL_KEY") or "").strip()
    if not key.startswith(KEY_PREFIX) or len(key) <= len(KEY_PREFIX):
        raise SettingsError(f"HOSTWATCH_CONTROL_KEY must be a control key starting with {KEY_PREFIX}")
    raw = env.get("HOSTWATCH_CONTROL_INTERVAL_S")
    try:
        interval = float(raw) if raw else MIN_INTERVAL_S
    except ValueError as exc:
        raise SettingsError("HOSTWATCH_CONTROL_INTERVAL_S must be a number") from exc
    if not MIN_INTERVAL_S <= interval <= MAX_INTERVAL_S:
        raise SettingsError(f"HOSTWATCH_CONTROL_INTERVAL_S must be from {MIN_INTERVAL_S:g} to {MAX_INTERVAL_S:g}")
    return Settings(url, key, config, folder, interval)


class Executor(Protocol):
    def execute(self, command: dict) -> ActionResult: ...

    def cancel_reboot(self) -> ActionResult: ...


def build_actions(config: cfgmod.ControlConfig, platform: str | None = None) -> Any:
    """The platform executor. The Windows module is imported only on Windows."""
    if (platform or sys.platform) == "win32":
        from .actions_windows import WindowsActions
        return WindowsActions(config)
    from .actions_linux import LinuxActions
    return LinuxActions(config)


class DeliveryError(Exception):
    """Observe could not be reached or answered with a failure."""


def wire_body(payload: dict) -> dict:
    """The exact body of the Observe results route (`ResultBody`): no other field may be sent."""
    started, finished = payload.get("started_at"), payload.get("finished_at")
    started = float(started) if isinstance(started, (int, float)) and not isinstance(started, bool) else None
    finished = float(finished) if isinstance(finished, (int, float)) and not isinstance(finished, bool) else None
    if started is not None and finished is not None and finished < started:
        finished = started
    return {"id": payload["id"], "state": payload.get("status"),
            "output": str(payload.get("output") or "")[:MAX_OUTPUT_CHARS],
            "started_at": started, "finished_at": finished}


def _seq_of(item: object) -> int:
    command = item.get("command") if isinstance(item, dict) else None
    seq = command.get("seq") if isinstance(command, dict) else None
    return seq if isinstance(seq, int) and not isinstance(seq, bool) else 0


class ControlDaemon:
    def __init__(self, settings: Settings, config: cfgmod.ControlConfig, verifier: CommandVerifier,
                 actions: Executor, outbox: ResultOutbox, client: httpx.Client,
                 clock: Callable[[], float] = time.time,
                 boot_id: Callable[[], str | None] = bootid.read) -> None:
        self.boot_id = boot_id
        self.settings, self.config = settings, config
        self.verifier, self.actions, self.outbox, self.client, self.clock = verifier, actions, outbox, client, clock
        self.stop_event = threading.Event()
        self._failures = 0
        self._pulled = False  # whether the last cycle got an answer to its pull
        self._followed: set[str] = set()  # reboots resolved or cancelled in this cycle, after the pull
        self.started_at = clock()  # a reboot due before this moment stays pending for BOOT_WAIT_S; only the boot id proves it done
        self._headers = {"Authorization": f"Bearer {settings.key}"}

    # network ----------------------------------------------------------------------------------

    def pull(self) -> tuple[list, list[str]]:
        """The signed commands waiting for this host and the ids of its commands an admin cancelled."""
        try:
            r = self.client.get(self.settings.url + COMMANDS_PATH, params={"host": self.config.host},
                                headers=self._headers, timeout=HTTP_TIMEOUT_S)
        except httpx.HTTPError as exc:
            raise DeliveryError(f"pull failed: {type(exc).__name__}") from exc
        if r.status_code in (401, 403):
            raise DeliveryError(f"Observe refused the control key (HTTP {r.status_code}); check "
                                "HOSTWATCH_CONTROL_KEY and that it is bound to this host name")
        if not r.is_success:
            raise DeliveryError(f"pull answered HTTP {r.status_code}")
        try:
            answer = r.json()
            items = answer["commands"]
        except (ValueError, KeyError, TypeError) as exc:
            raise DeliveryError("pull answer is not a command list") from exc
        if not isinstance(items, list):
            raise DeliveryError("pull answer is not a command list")
        cancel = answer.get("cancel") if isinstance(answer, dict) else None
        ids = [c for c in cancel if isinstance(c, str) and c] if isinstance(cancel, list) else []
        return items, ids[:MAX_CANCEL_IDS]

    def flush(self) -> None:
        """Send queued results oldest first. A result leaves the queue after a 2xx answer, after a 409
        (Observe already has it), or when it is parked after a permanent 4xx refusal, so one undeliverable
        result never blocks the rest. Any other failure raises and the result stays queued."""
        while (head := self.outbox.peek()) is not None:
            if self.stop_event.is_set():
                return
            seq, payload = head
            try:
                r = self.client.post(self.settings.url + RESULTS_PATH, json=wire_body(payload),
                                     headers=self._headers, timeout=HTTP_TIMEOUT_S)
            except httpx.HTTPError as exc:
                raise DeliveryError(f"result post failed: {type(exc).__name__}") from exc
            if r.is_success:
                log.info("result for command %s delivered (%s)", payload.get("id"), payload.get("status"))
                self.outbox.ack(seq)
            elif 400 <= r.status_code < 500 and r.status_code not in DROP_STATUSES \
                    and (r.status_code not in RETRYABLE_4XX or self._no_such_command(r)):
                reason = f"Observe answered HTTP {r.status_code}"
                log.error("%s for the result of command %s; it is parked and the next result goes on",
                          reason, payload.get("id"))
                self.outbox.park(seq, reason)
            elif r.status_code in DROP_STATUSES:
                log.warning("Observe answered HTTP %d for the result of command %s; it already has one, "
                            "so this copy is dropped", r.status_code, payload.get("id"))
                self.outbox.ack(seq)
            else:
                raise DeliveryError(f"result post answered HTTP {r.status_code}")

    @staticmethod
    def _no_such_command(r: httpx.Response) -> bool:
        """A 404 from the results route itself (Observe does not know this id for this host) is final."""
        if r.status_code != 404:
            return False
        try:
            return r.json().get("detail") == NO_SUCH_COMMAND
        except (ValueError, AttributeError):
            return False

    # one command ------------------------------------------------------------------------------

    def _result(self, command: dict, received: float, started: float, ok: bool, status: str,
                reason: str, output: str) -> dict:
        action = command.get("action")
        seq = command.get("seq")
        output = redact(output)
        if reason:
            output = f"{reason}: {output}" if output else reason
        return {"v": 1, "id": command["id"], "host": self.config.host,
                "action": action if isinstance(action, str) else "",
                "seq": seq if isinstance(seq, int) and not isinstance(seq, bool) else None,
                "status": status, "ok": ok, "reason": reason, "output": output[:MAX_OUTPUT_CHARS],
                "received_at": int(received), "started_at": int(started), "finished_at": int(self.clock()),
                "outbox_dropped": self.outbox.dropped_total()}

    def handle(self, item: object) -> dict | None:
        """Verify and execute one pulled command and return its result, or None when it has no usable id."""
        received = self.clock()
        command = item.get("command") if isinstance(item, dict) else None
        signature = item.get("signature") if isinstance(item, dict) else None
        if not isinstance(command, dict) or not isinstance(command.get("id"), str) or not command["id"]:
            log.error("a pulled command has no usable id and cannot be reported; ignored")
            return None
        wrong = identity.check(self.config)
        if wrong:
            log.error("command %s refused: %s", command["id"], wrong)
            return self._result(command, received, received, False, "refused", identity.WRONG_MACHINE, wrong)
        try:
            decision = self.verifier.check(command, signature)
        except SigningUnavailable as exc:
            return self._result(command, received, received, False, "refused", SIGNING_UNAVAILABLE, str(exc))
        if not decision and decision.reason == REPLAYED_ID:
            return self._replayed(command, received)
        if not decision:
            log.warning("command %s refused: %s %s", command["id"], decision.reason, decision.detail)
            return self._result(command, received, received, False, "refused", decision.reason, decision.detail)
        started = self.clock()
        log.info("executing command %s (%s, seq %s, requested by %s)", command["id"], command["action"],
                 command["seq"], command["requested_by"])
        try:
            done = self.actions.execute(command)
        except Exception as exc:  # an executor bug must be reported, not end the loop
            log.exception("executor failed on command %s", command["id"])
            return self._result(command, received, started, False, "failed", "action_failed",
                                f"{type(exc).__name__}: {exc}")
        reason = "" if done.ok else ("action_refused" if done.status == "refused" else "action_failed")
        if done.ok and done.status == "scheduled" and command["action"] == "host.reboot":
            self.outbox.schedule(command["id"], self.clock() + self.config.reboot.delay_s, self.boot_id())
        return self._result(command, received, started, done.ok, done.status, reason, done.output)

    def _replayed(self, command: dict, received: float) -> dict | None:
        """A signed command this host already accepted is pulled again, so Observe has not recorded its
        outcome. Answer with the stored result. It is never refused as a replay: the command did run."""
        cid = command["id"]
        if cid in self._followed or self.outbox.has(cid):
            return None  # its result is still queued and goes out first
        stored = self.outbox.stored(cid)
        if stored is None:
            log.warning("command %s was accepted earlier but its result is gone; reporting it failed", cid)
            return self._result(command, received, received, False, "failed", RESULT_LOST,
                                "the command was accepted earlier but its result was lost, so what it did is unknown")
        if stored.get("status") == "scheduled" and cid in self.outbox.scheduled():
            return None  # the reboot is still pending and Observe already has the scheduled report
        return stored

    def _followup(self, cid: str, status: str, reason: str, output: str) -> None:
        """Queue the later result of a scheduled reboot, built from the stored scheduled one."""
        now = int(self.clock())
        base = self.outbox.stored(cid) or {"v": 1, "id": cid, "host": self.config.host, "action": "host.reboot",
                                            "seq": None, "received_at": now}
        text = f"{reason}: {output}" if reason else output
        self.outbox.add(cid, {**base, "status": status, "ok": status != "failed", "reason": reason,
                              "output": text, "started_at": base.get("finished_at", now), "finished_at": now,
                              "outbox_dropped": self.outbox.dropped_total()})
        self.outbox.unschedule(cid)
        self._followed.add(cid)

    def _adopt_boot_id(self, cid: str) -> None:
        """A reboot scheduled before boot ids were recorded has none. While it is not yet due the host is
        still on the boot it was scheduled on, so the current id is taken as the one to compare against."""
        if self.outbox.scheduled_boot_id(cid) is None:
            current = self.boot_id()
            if current:
                self.outbox.set_scheduled_boot_id(cid, current)

    def resolve_reboots(self) -> None:
        """Report done or failed for a reboot whose time has passed. It is done only when the host boot id
        differs from the one recorded when it was scheduled. A daemon that merely restarted on the same boot
        leaves it pending, and a pending reboot that the host never carries out is failed after BOOT_WAIT_S."""
        for cid, due in self.outbox.scheduled().items():
            if self.clock() < due:
                self._adopt_boot_id(cid)
            if self.clock() < due + RESOLVE_GRACE_S:
                continue
            moved = bootid.changed(self.outbox.scheduled_boot_id(cid), self.boot_id())
            if moved:
                self._followup(cid, "done", "", "the host restarted after the scheduled reboot")
            elif self.started_at > due and self.clock() < due + BOOT_WAIT_S:
                continue  # the daemon restarted but the host did not: still pending
            elif moved is None:
                self._followup(cid, "failed", "reboot_unconfirmed",
                               "the scheduled reboot time passed and the boot id could not be compared, so "
                               "the reboot is not reported as done")
            else:
                self._followup(cid, "failed", "reboot_not_seen",
                               "the scheduled reboot time passed and the host is still on the same boot")

    def cancel_scheduled(self, ids: list[str]) -> None:
        """Cancel the pending reboot of every listed command this host scheduled, and report it cancelled."""
        for cid in ids:
            if cid not in self.outbox.scheduled():
                continue  # not a reboot this host is waiting on: nothing to cancel and nothing to report
            try:
                done = self.actions.cancel_reboot()
            except Exception as exc:
                log.exception("cancelling the reboot of command %s failed", cid)
                done = ActionResult(False, "failed", f"{type(exc).__name__}: {exc}")
            if done.ok:
                self._followup(cid, "cancelled", "", done.output or "scheduled reboot cancelled")
            else:
                log.warning("could not cancel the reboot of command %s: %s", cid, done.output)

    # the loop ---------------------------------------------------------------------------------

    def cycle(self) -> None:
        """One pass: replay unsent results, pull, and handle each command to completion in seq order.
        Raises DeliveryError when Observe could not be reached, after doing everything it still could."""
        problem: DeliveryError | None = None
        self._pulled = False
        self._followed.clear()
        try:
            self.flush()
        except DeliveryError as exc:
            problem = exc
        try:
            pulled, cancel = self.pull()
        except DeliveryError as exc:
            if problem is not None:
                log.warning("%s", exc)  # the earlier flush error is the one raised; keep both in the log
                raise problem from exc
            raise
        self._pulled = True
        self.resolve_reboots()
        self.cancel_scheduled(cancel)
        try:
            self.flush()
        except DeliveryError as exc:
            problem = exc
        items = sorted(pulled, key=_seq_of)
        for item in items[:MAX_PER_PULL]:
            if self.stop_event.is_set():
                break
            result = self.handle(item)
            if result is None:
                continue
            self.outbox.add(result["id"], result)
            try:
                self.flush()
            except DeliveryError as exc:
                problem = exc
        if problem is not None:
            raise problem

    def _backoff(self) -> float:
        return min(self.settings.interval_s * (2 ** min(self._failures, 6)), MAX_BACKOFF_S)

    def run(self) -> None:
        log.info("hostwatch-control started for host %s, polling %s every %gs", self.config.host,
                 self.settings.url, self.settings.interval_s)
        while not self.stop_event.is_set():
            started = time.monotonic()
            wait = self.settings.interval_s
            try:
                self.cycle()
                self._failures = 0
            except DeliveryError as exc:
                if self._pulled:
                    # Observe answers pulls, so only a result is stuck. Pending results never slow polling,
                    # because a queued command (a cancel, for one) must still be fetched on time.
                    self._failures = 0
                else:
                    self._failures += 1
                    wait = self._backoff()
                log.warning("%s; %d result(s) queued, next attempt in %gs", exc, self.outbox.depth(), wait)
            except Exception:  # last resort: nothing may end the loop
                log.exception("unexpected error in the control loop; continuing")
            self.stop_event.wait(max(0.0, wait - (time.monotonic() - started)))
        log.info("hostwatch-control stopped; %d result(s) remain queued", self.outbox.depth())

    def stop(self) -> None:
        """Ask the loop to end. It only sets a flag, so a signal handler or a service control handler may call it."""
        self.stop_event.set()

    def close(self) -> None:
        self.outbox.close()
        self.client.close()


def build_daemon(settings: Settings, *, client: httpx.Client | None = None, actions: Any = None,
                 clock: Callable[[], float] = time.time,
                 boot_id: Callable[[], str | None] = bootid.read) -> ControlDaemon:
    """Load control.toml and open the state and outbox. Anything unsafe or missing stops the daemon here."""
    try:
        import cryptography  # noqa: F401
    except ImportError as exc:
        raise SettingsError("the control extra is not installed: pip install 'hostwatch[control]'") from exc
    try:
        config = cfgmod.load(settings.config_path)
    except cfgmod.ConfigError as exc:
        raise SettingsError(str(exc)) from exc
    identity.refresh_machine_names()
    wrong = identity.check(config)
    if wrong:
        raise SettingsError(wrong)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    verifier = CommandVerifier(config, settings.data_dir / STATE_FILE, clock=clock)
    if verifier.state is None:
        log.error("the replay state is unusable (%s); every command will be refused until it is fixed",
                  verifier.state_error)
    return ControlDaemon(settings, config, verifier, actions if actions is not None else build_actions(config),
                         ResultOutbox(settings.data_dir / OUTBOX_FILE), client or httpx.Client(), clock, boot_id)


def configure_logging(data_dir: Path | None = None) -> None:
    """Console logging, or a rotating file in the data directory when one is given (the Windows service)."""
    import logging.handlers
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if data_dir is not None:
        data_dir.mkdir(parents=True, exist_ok=True)
        handlers = [logging.handlers.RotatingFileHandler(data_dir / "control.log", maxBytes=5_000_000,
                                                         backupCount=3, encoding="utf-8")]
    logging.basicConfig(level=logging.INFO, handlers=handlers, force=True,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def settings_from_files(data_dir: str | Path | None = None, config_path: str | Path | None = None,
                        env_file: str | Path | None = None) -> Settings:
    """Settings from the environment after the optional control.env file is loaded. The file never
    overrides a variable that is already set."""
    folder = Path(data_dir or os.environ.get("HOSTWATCH_CONTROL_DATA_DIR") or default_data_dir())
    path = Path(env_file) if env_file else folder / ENV_FILE_NAME
    if path.is_file():
        from ..windows.service import load_env_file
        try:
            load_env_file(path)
        except ValueError as exc:
            raise SettingsError(str(exc)) from exc
    return load_settings(data_dir=folder, config_path=config_path)


def run_foreground(config_path: str | None = None, data_dir: str | None = None, env_file: str | None = None,
                   daemon_factory: Callable[[Settings], ControlDaemon] = build_daemon) -> int:
    """`python -m hostwatch control run`. SIGINT or SIGTERM ends the loop cleanly."""
    try:
        settings = settings_from_files(data_dir, config_path, env_file)
        daemon = daemon_factory(settings)
    except (SettingsError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        number = getattr(signal, name, None)
        if number is not None:
            try:
                signal.signal(number, lambda *_: daemon.stop())
            except ValueError:
                pass  # not the main thread
    try:
        daemon.run()
    finally:
        daemon.close()
    return 0


def run_cancel(config_path: str | None = None,
               actions_factory: Callable[[cfgmod.ControlConfig], Any] = build_actions) -> int:
    """`python -m hostwatch control cancel`: cancel a scheduled reboot on this host without Observe."""
    path = config_path or os.environ.get("HOSTWATCH_CONTROL_CONFIG") or (
        str(WINDOWS_DATA_DIR / "control.toml") if sys.platform == "win32" else str(LINUX_CONFIG))
    try:
        config = cfgmod.load(path)
    except cfgmod.ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    result = actions_factory(config).cancel_reboot()
    print(result.output)
    return 0 if result.ok else 1
