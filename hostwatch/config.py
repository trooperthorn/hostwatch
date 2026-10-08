"""Runtime configuration, read from environment variables.

Every setting has a default that works for the agent container on a Linux host
with /sys bind-mounted read-only at /host/sys. /proc is the
container's own: the files read (stat, meminfo, loadavg) are system-wide, so the
host /proc, which would expose every host process, is not mounted. The event
sources (journal, pstore, rasdaemon database) are read-only mounts under /host.
"""

from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

log = logging.getLogger(__name__)


class Secret(str):
    """A string whose repr hides its value, so a logged or printed Config never leaks it.

    It behaves as a normal str everywhere else (comparison, encoding, slicing), which keeps
    credential checks unchanged. str() and format() still return the value on purpose: code that
    sends the credential needs it. Only repr, which dataclass reprs and log %r use, is redacted.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "Secret('***')" if self else "Secret('')"


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}


def parse_bool(name: str, default: str = "0") -> bool:
    """Read a boolean environment variable. Accepts 1, true, yes, on as true and 0, false, no, off
    or empty as false (case-insensitive, surrounding spaces ignored). Anything else raises, naming
    the variable, so a typo can never silently turn a security setting off."""
    raw = os.environ.get(name, default).strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ValueError(f"{name} must be one of 1, true, yes, on, 0, false, no, off (got {raw!r})")


def parse_sensor_patterns(name: str, raw: str) -> tuple[str, ...]:
    """Parse a comma-separated list of chip:sensor glob patterns, such as nct6779:AUXTIN*.

    Each entry needs a non-empty chip part and a non-empty sensor part separated by one colon
    (the chip name never contains a colon, so the first colon splits them). Patterns are
    matched case-sensitively with fnmatch rules. Whitespace around entries is ignored and
    empty entries are skipped. An entry without a colon, with an empty part, or with a
    control character raises ValueError naming the variable, so a typo cannot silently
    drop or keep the wrong readings.
    """
    out: list[str] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        chip, sep, sensor = entry.partition(":")
        if not sep or not chip.strip() or not sensor.strip():
            raise ValueError(f"{name} entries must look like chip:sensor (got {entry!r})")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in entry):
            raise ValueError(f"{name} entry {entry!r} contains a control character")
        out.append(f"{chip.strip()}:{sensor.strip()}")
    return tuple(out)


def sensor_matches(patterns, chip: str, sensor: str) -> bool:
    """True when chip:sensor matches any of the glob patterns."""
    from fnmatch import fnmatchcase
    key = f"{chip}:{sensor}"
    return any(fnmatchcase(key, p) for p in patterns)


OTLP_FORMATS = ("protobuf", "json")


@dataclass(frozen=True)
class Config:
    host_name: str = field(default_factory=lambda: _env("HOSTWATCH_HOST_NAME", socket.gethostname()))
    sysfs: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_SYSFS", "/host/sys")))
    pstore: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_PSTORE", "/host/pstore")))
    journal: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_JOURNAL", "/host/journal")))
    journal_volatile: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_JOURNAL_VOLATILE", "/host/journal-volatile")))
    rasdaemon_db: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_RASDAEMON_DB", "/host/rasdaemon/ras-mc_event.db")))
    procfs: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_PROCFS", "/proc")))
    data_dir: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_DATA_DIR", "/data")))
    redetect_s: float = field(default_factory=lambda: float(_env("HOSTWATCH_REDETECT", "600")))
    # The Observe base URL. HOSTWATCH_OBSERVE_URL is the preferred name. HOSTWATCH_HUB_URL is kept as an
    # alias because Observe's install scripts set it. When both are set the preferred name wins.
    observe_url: str = field(default_factory=lambda: (
        _env("HOSTWATCH_OBSERVE_URL", "").strip() or _env("HOSTWATCH_HUB_URL", "").strip()).rstrip("/"))
    ingest_key: str = field(default_factory=lambda: Secret(_env("HOSTWATCH_INGEST_KEY", "")), repr=False)
    # json with gzip is the default: it costs about half the CPU to encode of protobuf and is no larger
    # on the wire (scripts/bench_io.py reproduces the figures). protobuf stays available.
    otlp_format: str = field(default_factory=lambda: _env("HOSTWATCH_OTLP_FORMAT", "json").strip().lower())
    otlp_gzip: bool = field(default_factory=lambda: parse_bool("HOSTWATCH_OTLP_GZIP", "1"))
    scrutiny_url: str = field(default_factory=lambda: _env("HOSTWATCH_SCRUTINY_URL", ""))
    nut_host: str = field(default_factory=lambda: _env("HOSTWATCH_NUT_HOST", "").strip())
    nut_port: int = field(default_factory=lambda: int(_env("HOSTWATCH_NUT_PORT", "3493")))
    nut_ups: str = field(default_factory=lambda: _env("HOSTWATCH_NUT_UPS", "").strip())
    nut_user: str = field(default_factory=lambda: _env("HOSTWATCH_NUT_USER", "").strip())
    nut_password_file: str = field(default_factory=lambda: _env("HOSTWATCH_NUT_PASSWORD_FILE", "").strip())
    rpi_throttled_path: str = field(default_factory=lambda: _env("HOSTWATCH_RPI_THROTTLED_PATH", "").strip())
    thermalctl_status: str = field(default_factory=lambda: _env("HOSTWATCH_THERMALCTL_STATUS", "").strip())
    truenas_url: str = field(default_factory=lambda: _env("HOSTWATCH_TRUENAS_URL", "").strip())
    truenas_api_key_file: str = field(default_factory=lambda: _env("HOSTWATCH_TRUENAS_API_KEY_FILE", "").strip())
    truenas_ca: str = field(default_factory=lambda: _env("HOSTWATCH_TRUENAS_CA", "").strip())
    truenas_insecure: bool = field(default_factory=lambda: parse_bool("HOSTWATCH_TRUENAS_INSECURE"))
    truenas_timeout_s: float = field(default_factory=lambda: float(_env("HOSTWATCH_TRUENAS_TIMEOUT_S", "10")))
    hwmon_ignore: str = field(default_factory=lambda: _env("HOSTWATCH_HWMON_IGNORE", "").strip())
    hwmon_cpu_sensors: str = field(default_factory=lambda: _env("HOSTWATCH_HWMON_CPU_SENSORS", "").strip())
    hwmon_required_fans: str = field(default_factory=lambda: _env("HOSTWATCH_HWMON_REQUIRED_FANS", "").strip())

    def __post_init__(self) -> None:
        # Values passed explicitly or through dataclasses.replace are plain str; wrap them too.
        if not isinstance(self.ingest_key, Secret):
            object.__setattr__(self, "ingest_key", Secret(self.ingest_key))

    def validate(self) -> None:
        self._validate_nut()
        parse_sensor_patterns("HOSTWATCH_HWMON_IGNORE", self.hwmon_ignore)
        parse_sensor_patterns("HOSTWATCH_HWMON_CPU_SENSORS", self.hwmon_cpu_sensors)
        parse_sensor_patterns("HOSTWATCH_HWMON_REQUIRED_FANS", self.hwmon_required_fans)
        if self.otlp_format not in OTLP_FORMATS:
            raise ValueError(f"HOSTWATCH_OTLP_FORMAT must be protobuf or json (got {self.otlp_format!r})")
        if not self.observe_url:
            raise ValueError("HOSTWATCH_OBSERVE_URL is not set. Set it to the Observe base URL, for example "
                             "https://observe.example:8443. HOSTWATCH_HUB_URL is accepted as an alias.")
        parts = urlsplit(self.observe_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"HOSTWATCH_OBSERVE_URL must be an http or https URL (got {self.observe_url!r})")
        if not self.ingest_key:
            raise ValueError("HOSTWATCH_INGEST_KEY is not set. Create an ingest key for this host in Observe "
                             "and set it here. The key is bound to the host name Observe knows this host by.")
        if not self.host_name.strip():
            raise ValueError("HOSTWATCH_HOST_NAME must not be empty")

    def _validate_nut(self) -> None:
        """The UPS name and user go into protocol lines, so they may hold no whitespace or control
        characters. A newline there would otherwise inject a second command."""
        for var, value in (("HOSTWATCH_NUT_UPS", self.nut_ups), ("HOSTWATCH_NUT_USER", self.nut_user)):
            if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
                raise ValueError(f"{var} must not contain spaces, tabs, CR, LF or other control characters")
