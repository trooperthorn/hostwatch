"""Loader for control.toml, the root-owned local allowlist.

The file is the authority on what this host will do. On POSIX the loader refuses a file that
group or others can write, because anyone who could edit it could widen the allowlist or swap
the pinned key. That check is enforced. On Windows the loader cannot see ACLs without pywin32,
so it does not check; the install script is expected to lock the file to SYSTEM and
Administrators, and that is advisory until verified on a host (see UNVERIFIED.md).
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

KEY_PREFIX = "ed25519:"
CONTROLLERS = ("thermalctl", "thermal-control-suite")
# Unit and container names end up on a command line later, so only plain characters are accepted.
SERVICE_NAME = re.compile(r"^(docker:)?[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")


class ConfigError(Exception):
    """The control file is missing, unsafe or invalid. The daemon must not start."""


@dataclass(frozen=True)
class FanPolicy:
    controller: str
    headers: tuple[str, ...]
    min_duty_floor: int
    min_duty_ceiling: int
    allow_mode_change: bool


@dataclass(frozen=True)
class RebootPolicy:
    allow: bool = False
    delay_s: int = 60


@dataclass(frozen=True)
class ControlConfig:
    public_key: bytes
    host: str
    fan: FanPolicy | None = None
    restart: tuple[str, ...] = ()
    reboot: RebootPolicy = field(default_factory=RebootPolicy)


def parse_public_key(text: object) -> bytes:
    """Decode `ed25519:<base64 of the 32 raw key bytes>`."""
    if not isinstance(text, str) or not text.startswith(KEY_PREFIX):
        raise ConfigError(f"watchpost_public_key must start with {KEY_PREFIX}")
    try:
        raw = base64.b64decode(text[len(KEY_PREFIX):], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError("watchpost_public_key is not valid base64") from exc
    if len(raw) != 32:
        raise ConfigError("watchpost_public_key must decode to 32 bytes")
    return raw


def _int(table: dict, key: str, default: int) -> int:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key} must be an integer")
    return value


def _bool(table: dict, key: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be true or false")
    return value


def _strings(table: dict, key: str) -> tuple[str, ...]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ConfigError(f"{key} must be a list of non-empty strings")
    return tuple(value)


def _table(data: dict, key: str) -> dict | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ConfigError(f"[{key}] must be a table")
    return value


def parse(data: dict) -> ControlConfig:
    host = data.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ConfigError("host must be a non-empty string")
    key = parse_public_key(data.get("watchpost_public_key"))

    fan = None
    fan_t = _table(data, "fan")
    if fan_t is not None:
        controller = fan_t.get("controller")
        if controller not in CONTROLLERS:
            raise ConfigError(f"fan.controller must be one of {', '.join(CONTROLLERS)}")
        headers = _strings(fan_t, "headers")
        if not headers:
            raise ConfigError("fan.headers must list at least one header")
        floor = _int(fan_t, "min_duty_floor", 0)
        ceiling = _int(fan_t, "min_duty_ceiling", 100)
        if not 0 <= floor <= ceiling <= 100:
            raise ConfigError("fan limits must satisfy 0 <= min_duty_floor <= min_duty_ceiling <= 100")
        fan = FanPolicy(controller, headers, floor, ceiling, _bool(fan_t, "allow_mode_change", False))

    restart: tuple[str, ...] = ()
    services_t = _table(data, "services")
    if services_t is not None:
        restart = _strings(services_t, "restart")
        for name in restart:
            if not SERVICE_NAME.match(name):
                raise ConfigError(f"services.restart entry {name!r} has characters that are not allowed")

    reboot = RebootPolicy()
    reboot_t = _table(data, "reboot")
    if reboot_t is not None:
        delay = _int(reboot_t, "delay_s", 60)
        if delay < 0:
            raise ConfigError("reboot.delay_s must not be negative")
        reboot = RebootPolicy(_bool(reboot_t, "allow", False), delay)

    return ControlConfig(public_key=key, host=host.strip(), fan=fan, restart=restart, reboot=reboot)


def check_permissions(path: Path) -> None:
    """Refuse a file that group or others can write (POSIX only)."""
    if os.name != "posix":
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(f"{path} is writable by group or others (mode {stat.S_IMODE(mode):04o}); "
                          "refusing to use it. Fix it with: chmod go-w")


def load(path: str | Path) -> ControlConfig:
    p = Path(path)
    try:
        check_permissions(p)
        raw = p.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read {p}: {exc}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{p} is not valid TOML: {exc}") from exc
    return parse(data)
