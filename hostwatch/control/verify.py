"""The ordered checks that decide whether a signed command may run.

Order, as in docs/CONTROL.md: signature, host, expiry with 30 s of clock skew, the issue-time
and lifetime limits (expiry no more than 900 s after issue, issue time not in the future and not
older than 600 s), id unseen, seq higher than the persisted one and no more than 1000 above it,
then the local allowlist. The first failure is the
refusal and carries a stable reason code. Only a command that passes every check is recorded
in the replay state, and it is recorded before it is returned, so a crash during execution
cannot let the same command run twice (at most once, never at least once). A command refused
by the allowlist is not recorded and uses up no sequence number.

Parameters are matched exactly: a missing, extra or wrongly typed parameter is a refusal (host.reboot
alone tolerates a confirm_host text, which is ignored), because the executors must never see a field the allowlist did not look at. An unreadable or
corrupt state file refuses every command (fail closed).

`agent.update` takes exactly `component`, one of agent, control or all, and needs the matching flag in the
`[update]` stanza: `agent` for the container, `control` for this daemon, both for all. The refusal names the
flag that is false, so the owner knows which line of control.toml to change.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import ControlConfig
from .signing import verify_signature
from .state import ReplayState, StateError

SKEW_S = 30
# Limits that a valid signature cannot widen. A signed command is only useful for a short window.
MAX_VALIDITY_S = 900
MAX_AGE_S = 600
MAX_SEQ_JUMP = 1000
VERSION = 1

# Reason codes. Every refusal uses exactly one of these.
BAD_SIGNATURE = "bad_signature"
MALFORMED = "malformed"
WRONG_HOST = "wrong_host"
EXPIRED = "expired"
REPLAYED_ID = "replayed_id"
STALE_SEQ = "stale_seq"
EXPIRY_TOO_LONG = "expiry_too_long"
ISSUED_IN_FUTURE = "issued_in_future"
ISSUED_TOO_OLD = "issued_too_old"
SEQ_JUMP_TOO_LARGE = "seq_jump_too_large"
UNKNOWN_ACTION = "unknown_action"
BAD_PARAMS = "bad_params"
ACTION_NOT_ENABLED = "action_not_enabled"
CONTROLLER_NOT_ALLOWED = "controller_not_allowed"
HEADER_NOT_ALLOWED = "header_not_allowed"
FLOOR_BELOW_MIN = "floor_below_min"
FLOOR_ABOVE_MAX = "floor_above_max"
MODE_CHANGE_NOT_ALLOWED = "mode_change_not_allowed"
UNIT_NOT_ALLOWED = "unit_not_allowed"
REBOOT_NOT_ALLOWED = "reboot_not_allowed"
UPDATE_NOT_ALLOWED = "update_not_allowed"
STATE_UNAVAILABLE = "state_unavailable"

ACTIONS = ("fan.set_floor", "fan.set_mode", "service.restart", "host.reboot", "agent.update")
UPDATE_COMPONENTS = ("agent", "control", "all")
# Observe checks the typed host name before it signs a reboot. Older plugin builds copied it into the
# signed params as confirm_host; it is accepted and ignored. Any other extra parameter is a refusal.
REBOOT_IGNORED_PARAMS = frozenset({"confirm_host"})
_FIELDS = {"v": int, "id": str, "host": str, "action": str, "params": dict,
           "requested_by": str, "issued_at": int, "expires_at": int, "seq": int}


@dataclass(frozen=True)
class Decision:
    ok: bool
    reason: str = ""
    detail: str = ""
    command: dict | None = None

    def __bool__(self) -> bool:
        return self.ok


def _refuse(reason: str, detail: str = "") -> Decision:
    return Decision(False, reason, detail)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _shape_error(command: dict) -> str:
    for name, kind in _FIELDS.items():
        value = command.get(name)
        if kind is int and not _is_int(value):
            return f"{name} must be an integer"
        if kind is not int and not isinstance(value, kind):
            return f"{name} is missing or has the wrong type"
    if command["v"] != VERSION:
        return f"unsupported version {command['v']}"
    return ""


def update_refusal(config: ControlConfig, component: str) -> str:
    """Why `[update]` does not permit this component, naming every flag that is false, or "" when it does."""
    wanted = {"agent": ("agent",), "control": ("control",), "all": ("agent", "control")}.get(component, ())
    missing = [name for name in wanted if not getattr(config.update, name)]
    if not missing:
        return ""
    return " and ".join(f"update.{name}" for name in missing) + (" is false" if len(missing) == 1 else " are false")


def check_allowlist(config: ControlConfig, command: dict) -> Decision:
    action, params = command["action"], command["params"]
    if action not in ACTIONS:
        return _refuse(UNKNOWN_ACTION, f"action {action!r} is not supported")

    if action in ("fan.set_floor", "fan.set_mode"):
        fan = config.fan
        if fan is None:
            return _refuse(ACTION_NOT_ENABLED, "no [fan] section in control.toml")
        wanted = {"controller", "header", "min_duty"} if action == "fan.set_floor" else {"controller", "mode"}
        if set(params) != wanted:
            return _refuse(BAD_PARAMS, f"parameters must be exactly {sorted(wanted)}")
        if params["controller"] != fan.controller:
            return _refuse(CONTROLLER_NOT_ALLOWED, f"controller {params['controller']!r} is not allowed")
        if action == "fan.set_mode":
            if params["mode"] not in ("dry_run", "active"):
                return _refuse(BAD_PARAMS, "mode must be dry_run or active")
            if not fan.allow_mode_change:
                return _refuse(MODE_CHANGE_NOT_ALLOWED, "allow_mode_change is false")
            return Decision(True, command=command)
        header, duty = params["header"], params["min_duty"]
        if not isinstance(header, str) or not _is_int(duty):
            return _refuse(BAD_PARAMS, "header must be a string and min_duty an integer")
        if header not in fan.headers:
            return _refuse(HEADER_NOT_ALLOWED, f"header {header!r} is not listed")
        if duty < fan.min_duty_floor:
            return _refuse(FLOOR_BELOW_MIN, f"min_duty {duty} is below {fan.min_duty_floor}")
        if duty > fan.min_duty_ceiling:
            return _refuse(FLOOR_ABOVE_MAX, f"min_duty {duty} is above {fan.min_duty_ceiling}")
        return Decision(True, command=command)

    if action == "service.restart":
        if set(params) != {"name"} or not isinstance(params["name"], str):
            return _refuse(BAD_PARAMS, "parameters must be exactly ['name'] with a string name")
        if params["name"] not in config.restart:
            return _refuse(UNIT_NOT_ALLOWED, f"unit {params['name']!r} is not listed")
        return Decision(True, command=command)

    if action == "agent.update":
        if set(params) != {"component"} or params["component"] not in UPDATE_COMPONENTS:
            return _refuse(BAD_PARAMS, "parameters must be exactly ['component'] with agent, control or all")
        missing = update_refusal(config, params["component"])
        if missing:
            return _refuse(UPDATE_NOT_ALLOWED, missing)
        return Decision(True, command=command)

    extra = set(params) - REBOOT_IGNORED_PARAMS
    if extra or not all(isinstance(params[k], str) for k in params):
        return _refuse(BAD_PARAMS, "host.reboot takes no parameters other than a confirm_host text")
    if not config.reboot.allow:
        return _refuse(REBOOT_NOT_ALLOWED, "reboot.allow is false")
    return Decision(True, command=command)


class CommandVerifier:
    def __init__(self, config: ControlConfig, state_path: str | Path,
                 clock: Callable[[], float] = time.time, state_key: bytes | None = None):
        self.config, self.clock = config, clock
        self.state: ReplayState | None = None
        self.state_error = ""
        try:
            self.state = ReplayState(state_path, state_key)
        except StateError as exc:
            self.state_error = str(exc)

    def check(self, command: object, signature: object) -> Decision:
        if not isinstance(command, dict):
            return _refuse(MALFORMED, "command is not an object")
        if not verify_signature(command, signature, self.config.public_key):
            return _refuse(BAD_SIGNATURE)
        problem = _shape_error(command)
        if problem:
            return _refuse(MALFORMED, problem)
        if command["host"] != self.config.host:
            return _refuse(WRONG_HOST, f"command is for {command['host']!r}")
        if self.clock() > command["expires_at"] + SKEW_S:
            return _refuse(EXPIRED, f"expired at {command['expires_at']}")
        now = self.clock()
        if command["expires_at"] - command["issued_at"] > MAX_VALIDITY_S:
            return _refuse(EXPIRY_TOO_LONG, f"expiry is more than {MAX_VALIDITY_S} s after issue")
        if command["issued_at"] > now + SKEW_S:
            return _refuse(ISSUED_IN_FUTURE, f"issued_at {command['issued_at']} is in the future")
        if now - command["issued_at"] > MAX_AGE_S + SKEW_S:
            return _refuse(ISSUED_TOO_OLD, f"issued_at {command['issued_at']} is more than {MAX_AGE_S} s old")
        state = self.state
        if state is None:
            return _refuse(STATE_UNAVAILABLE, self.state_error)
        if state.seen(command["id"]):
            return _refuse(REPLAYED_ID, f"id {command['id']} was already used")
        if not state.seq_ok(command["seq"]):
            return _refuse(STALE_SEQ, f"seq {command['seq']} is not above {state.last_seq}")
        if state.last_seq is not None and command["seq"] - state.last_seq > MAX_SEQ_JUMP:
            return _refuse(SEQ_JUMP_TOO_LARGE, f"seq {command['seq']} is more than {MAX_SEQ_JUMP} above {state.last_seq}")
        decision = check_allowlist(self.config, command)
        if not decision:
            return decision
        try:
            state.record(command["id"], command["seq"])
        except StateError as exc:
            return _refuse(STATE_UNAVAILABLE, str(exc))
        return decision
