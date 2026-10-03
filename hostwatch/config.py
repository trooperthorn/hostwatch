"""Runtime configuration, read from environment variables.

Every setting has a default that works for the single-container "all" role on
a Linux host with /sys bind-mounted read-only at /host/sys. /proc is the
container's own: the files read (stat, meminfo, loadavg) are system-wide, so the
host /proc, which would expose every host process, is not mounted. The event
sources (journal, pstore, rasdaemon database) are read-only mounts under /host.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


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


@dataclass(frozen=True)
class Config:
    role: str = field(default_factory=lambda: _env("HOSTWATCH_ROLE", "all"))
    host_name: str = field(default_factory=lambda: _env("HOSTWATCH_HOST_NAME", socket.gethostname()))
    sysfs: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_SYSFS", "/host/sys")))
    pstore: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_PSTORE", "/host/pstore")))
    journal: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_JOURNAL", "/host/journal")))
    journal_volatile: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_JOURNAL_VOLATILE", "/host/journal-volatile")))
    rasdaemon_db: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_RASDAEMON_DB", "/host/rasdaemon/ras-mc_event.db")))
    procfs: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_PROCFS", "/proc")))
    data_dir: Path = field(default_factory=lambda: Path(_env("HOSTWATCH_DATA_DIR", "/data")))
    interval_s: float = field(default_factory=lambda: float(_env("HOSTWATCH_INTERVAL", "15")))
    silent_after_s: float | None = field(
        default_factory=lambda: float(_env("HOSTWATCH_SILENT_AFTER_S", "0")) or None)
    crash_hold_s: float = field(default_factory=lambda: float(_env("HOSTWATCH_CRASH_HOLD_S", "86400")))
    redetect_s: float = field(default_factory=lambda: float(_env("HOSTWATCH_REDETECT", "600")))
    hub_url: str = field(default_factory=lambda: _env("HOSTWATCH_HUB_URL", "http://127.0.0.1:8090"))
    hub_bind: str = field(default_factory=lambda: _env("HOSTWATCH_HUB_BIND", "127.0.0.1"))
    hub_port: int = field(default_factory=lambda: int(_env("HOSTWATCH_HUB_PORT", "8090")))
    ingest_token: str = field(default_factory=lambda: _env("HOSTWATCH_INGEST_TOKEN", ""))
    ingest_key: str = field(default_factory=lambda: _env("HOSTWATCH_INGEST_KEY", ""))
    legacy_token_disabled: bool = field(
        default_factory=lambda: parse_bool("HOSTWATCH_LEGACY_TOKEN_DISABLED"))
    argon2_time_cost: int = field(default_factory=lambda: int(_env("HOSTWATCH_ARGON2_TIME_COST", "3")))
    argon2_memory_kib: int = field(default_factory=lambda: int(_env("HOSTWATCH_ARGON2_MEMORY_KIB", "65536")))
    argon2_parallelism: int = field(default_factory=lambda: int(_env("HOSTWATCH_ARGON2_PARALLELISM", "4")))
    login_max_failures: int = field(default_factory=lambda: int(_env("HOSTWATCH_LOGIN_MAX_FAILURES", "5")))
    login_lock_s: float = field(default_factory=lambda: float(_env("HOSTWATCH_LOGIN_LOCK_S", "900")))
    session_ttl_s: float = field(default_factory=lambda: float(_env("HOSTWATCH_SESSION_TTL_S", "28800")))
    tls_enabled: bool = field(default_factory=lambda: parse_bool("HOSTWATCH_TLS"))
    tls_cert: str = field(default_factory=lambda: _env("HOSTWATCH_TLS_CERT", ""))
    tls_key: str = field(default_factory=lambda: _env("HOSTWATCH_TLS_KEY", ""))
    tls_client_ca: str = field(default_factory=lambda: _env("HOSTWATCH_TLS_CLIENT_CA", ""))
    allow_insecure_bind: bool = field(default_factory=lambda: parse_bool("HOSTWATCH_ALLOW_INSECURE_BIND"))
    allowed_clients: str = field(default_factory=lambda: _env("HOSTWATCH_ALLOWED_CLIENTS", ""))
    mtls_mode: str = field(default_factory=lambda: _env("HOSTWATCH_MTLS_MODE", "off").lower())
    mtls_trusted_proxies: str = field(default_factory=lambda: _env("HOSTWATCH_MTLS_TRUSTED_PROXIES", ""))
    scrutiny_url: str = field(default_factory=lambda: _env("HOSTWATCH_SCRUTINY_URL", ""))
    nut_host: str = field(default_factory=lambda: _env("HOSTWATCH_NUT_HOST", "").strip())
    nut_port: int = field(default_factory=lambda: int(_env("HOSTWATCH_NUT_PORT", "3493")))
    nut_ups: str = field(default_factory=lambda: _env("HOSTWATCH_NUT_UPS", "").strip())
    nut_user: str = field(default_factory=lambda: _env("HOSTWATCH_NUT_USER", "").strip())
    nut_password_file: str = field(default_factory=lambda: _env("HOSTWATCH_NUT_PASSWORD_FILE", "").strip())
    ha_url: str = field(default_factory=lambda: _env("HOSTWATCH_HA_URL", "").strip())
    ha_token_file: str = field(default_factory=lambda: _env("HOSTWATCH_HA_TOKEN_FILE", "").strip())
    power_witness: str = field(default_factory=lambda: _env("HOSTWATCH_POWER_WITNESS", "").strip())
    raw_retention_days: int = field(default_factory=lambda: int(_env("HOSTWATCH_RAW_RETENTION_DAYS", "7")))
    rollup_retention_days: int = field(default_factory=lambda: int(_env("HOSTWATCH_ROLLUP_RETENTION_DAYS", "400")))
    mqtt_host: str = field(default_factory=lambda: _env("HOSTWATCH_MQTT_HOST", "").strip())
    mqtt_port: int = field(default_factory=lambda: int(_env("HOSTWATCH_MQTT_PORT", "1883")))
    mqtt_username: str = field(default_factory=lambda: _env("HOSTWATCH_MQTT_USERNAME", ""))
    mqtt_password: str = field(default_factory=lambda: _env("HOSTWATCH_MQTT_PASSWORD", ""), repr=False)
    mqtt_password_file: str = field(default_factory=lambda: _env("HOSTWATCH_MQTT_PASSWORD_FILE", ""))
    mqtt_tls: bool = field(default_factory=lambda: parse_bool("HOSTWATCH_MQTT_TLS"))
    mqtt_tls_ca: str = field(default_factory=lambda: _env("HOSTWATCH_MQTT_TLS_CA", ""))
    mqtt_tls_cert: str = field(default_factory=lambda: _env("HOSTWATCH_MQTT_TLS_CERT", ""))
    mqtt_tls_key: str = field(default_factory=lambda: _env("HOSTWATCH_MQTT_TLS_KEY", ""))
    mqtt_tls_insecure: bool = field(default_factory=lambda: parse_bool("HOSTWATCH_MQTT_TLS_INSECURE"))
    mqtt_discovery_prefix: str = field(default_factory=lambda: _env("HOSTWATCH_MQTT_DISCOVERY_PREFIX", "homeassistant"))
    mqtt_base_topic: str = field(default_factory=lambda: _env("HOSTWATCH_MQTT_BASE_TOPIC", "hostwatch"))
    mqtt_events_interval: float = field(default_factory=lambda: float(_env("HOSTWATCH_MQTT_EVENTS_INTERVAL", "10")))
    prometheus_enabled: bool = field(default_factory=lambda: parse_bool("HOSTWATCH_PROMETHEUS"))

    def validate(self) -> None:
        if self.role not in {"all", "hub", "agent"}:
            raise ValueError(f"HOSTWATCH_ROLE must be all, hub, or agent (got {self.role!r})")
        if self.mtls_mode not in {"off", "uvicorn", "proxy"}:
            raise ValueError(f"HOSTWATCH_MTLS_MODE must be off, uvicorn, or proxy (got {self.mtls_mode!r})")
        if self.mtls_mode == "uvicorn":
            raise ValueError(
                "HOSTWATCH_MTLS_MODE=uvicorn is not supported: the pinned uvicorn does not expose the verified "
                "peer certificate to the application, so no client could ever authenticate. Use "
                "HOSTWATCH_MTLS_MODE=proxy behind a reverse proxy that verifies client certificates. "
                "See UNVERIFIED.md for how to re-check a newer uvicorn."
            )
        if self.mtls_mode == "proxy":
            from .mtls import parse_proxies
            try:
                proxies = parse_proxies(self.mtls_trusted_proxies)
            except ValueError as exc:
                raise ValueError(f"HOSTWATCH_MTLS_TRUSTED_PROXIES is not a list of addresses: {exc}") from exc
            if not proxies:
                raise ValueError("HOSTWATCH_MTLS_MODE=proxy requires HOSTWATCH_MTLS_TRUSTED_PROXIES")
        if self.ingest_token and len(self.ingest_token) < 32:
            raise ValueError(
                "HOSTWATCH_INGEST_TOKEN must be at least 32 characters when it is set. "
                "Generate one with: openssl rand -hex 32"
            )
        if self.ingest_token.startswith("hw_"):
            raise ValueError(
                "HOSTWATCH_INGEST_TOKEN starts with hw_, which is the scoped API key prefix. The hub would treat "
                "it as an API key and never match it as the legacy token. Put the key in HOSTWATCH_INGEST_KEY "
                "or generate a legacy token with: openssl rand -hex 32"
            )
        if self.role == "agent" and not (self.ingest_key or self.ingest_token):
            raise ValueError(
                "The agent role needs a credential: set HOSTWATCH_INGEST_KEY to a scoped key "
                "(preferred) or HOSTWATCH_INGEST_TOKEN to the legacy shared token."
            )

        if self.silent_after_s is not None and not self.silent_after_s > 0:
            raise ValueError(f"HOSTWATCH_SILENT_AFTER_S must be greater than 0 seconds (got {self.silent_after_s})")
        if not self.crash_hold_s > 0:
            raise ValueError(f"HOSTWATCH_CRASH_HOLD_S must be greater than 0 seconds (got {self.crash_hold_s})")
        self._validate_bind()
        self._validate_mqtt()

    @property
    def mqtt_enabled(self) -> bool:
        """The MQTT publisher is off unless a broker host is configured."""
        return bool(self.mqtt_host)

    @property
    def mqtt_tls_active(self) -> bool:
        return self.mqtt_tls or bool(self.mqtt_tls_ca or self.mqtt_tls_cert)

    def mqtt_password_value(self) -> str:
        """The broker password from HOSTWATCH_MQTT_PASSWORD or, preferably, the password file
        (trailing newlines are stripped). Read at call time so a rotated file is picked up."""
        if self.mqtt_password_file:
            return Path(self.mqtt_password_file).read_text(encoding="utf-8").rstrip("\r\n")
        return self.mqtt_password

    @property
    def silence_window_s(self) -> float:
        """Seconds without a report before a host is silent: HOSTWATCH_SILENT_AFTER_S, or three agent intervals."""
        return self.silent_after_s if self.silent_after_s else 3 * self.interval_s

    def _validate_mqtt(self) -> None:
        mqtt_set = [n for n, v in (
            ("HOSTWATCH_MQTT_USERNAME", self.mqtt_username), ("HOSTWATCH_MQTT_PASSWORD", self.mqtt_password),
            ("HOSTWATCH_MQTT_PASSWORD_FILE", self.mqtt_password_file), ("HOSTWATCH_MQTT_TLS_CA", self.mqtt_tls_ca),
            ("HOSTWATCH_MQTT_TLS_CERT", self.mqtt_tls_cert), ("HOSTWATCH_MQTT_TLS_KEY", self.mqtt_tls_key)) if v]
        if not self.mqtt_host:
            if mqtt_set:
                raise ValueError(f"{mqtt_set[0]} is set but HOSTWATCH_MQTT_HOST is not, so MQTT stays off. "
                                 "Set HOSTWATCH_MQTT_HOST or remove the MQTT settings.")
            return
        if not 1 <= self.mqtt_port <= 65535:
            raise ValueError(f"HOSTWATCH_MQTT_PORT must be between 1 and 65535 (got {self.mqtt_port})")
        if not self.mqtt_events_interval > 0:
            raise ValueError("HOSTWATCH_MQTT_EVENTS_INTERVAL must be greater than 0 seconds "
                             f"(got {self.mqtt_events_interval})")
        if self.mqtt_password and self.mqtt_password_file:
            raise ValueError("Set only one of HOSTWATCH_MQTT_PASSWORD and HOSTWATCH_MQTT_PASSWORD_FILE")
        has_password = bool(self.mqtt_password or self.mqtt_password_file)
        if bool(self.mqtt_username) != has_password:
            raise ValueError("HOSTWATCH_MQTT_USERNAME and a password (HOSTWATCH_MQTT_PASSWORD or "
                             "HOSTWATCH_MQTT_PASSWORD_FILE) must be set together")
        if bool(self.mqtt_tls_cert) != bool(self.mqtt_tls_key):
            raise ValueError("HOSTWATCH_MQTT_TLS_CERT and HOSTWATCH_MQTT_TLS_KEY must be set together")
        for name, path in (("HOSTWATCH_MQTT_PASSWORD_FILE", self.mqtt_password_file),
                           ("HOSTWATCH_MQTT_TLS_CA", self.mqtt_tls_ca), ("HOSTWATCH_MQTT_TLS_CERT", self.mqtt_tls_cert),
                           ("HOSTWATCH_MQTT_TLS_KEY", self.mqtt_tls_key)):
            if path and not Path(path).is_file():
                raise ValueError(f"{name} does not point to a readable file: {path}")
        if self.mqtt_tls_insecure and not self.mqtt_tls_active:
            raise ValueError("HOSTWATCH_MQTT_TLS_INSECURE requires TLS (set HOSTWATCH_MQTT_TLS=1 or a CA)")
        if self.mqtt_tls_insecure:
            log.warning("HOSTWATCH_MQTT_TLS_INSECURE=1: the broker certificate host name is not verified.")
        for name, topic in (("HOSTWATCH_MQTT_DISCOVERY_PREFIX", self.mqtt_discovery_prefix),
                            ("HOSTWATCH_MQTT_BASE_TOPIC", self.mqtt_base_topic)):
            if not topic or topic.startswith("/") or topic.endswith("/") or any(c in topic for c in "+#\x00"):
                raise ValueError(f"{name} must be a non-empty topic prefix without wildcards or a leading or "
                                 f"trailing slash (got {topic!r})")

    @property
    def agent_credential(self) -> str:
        """The bearer the agent sends: the scoped ingest key if set, else the legacy shared token."""
        return self.ingest_key or self.ingest_token

    @property
    def tls_configured(self) -> bool:
        """True when the hub itself will terminate TLS with an operator supplied certificate."""
        return bool(self.tls_cert and self.tls_key)

    @property
    def tls_active(self) -> bool:
        """True when clients reach the hub over TLS: the hub terminates it (certificate and key
        configured) or the operator declares a TLS proxy in front with HOSTWATCH_TLS. Cookies are
        marked Secure whenever this is true. With a proxy this relies on the operator setting
        HOSTWATCH_TLS; the hub cannot verify it (advisory)."""
        return self.tls_configured or self.tls_enabled

    def _validate_bind(self) -> None:
        """Exposure control: refuse a non-loopback bind unless TLS is on or the override is set.

        This limits who can reach the listener. It is not authentication; the
        login, session and key checks in hub.py are what authenticate callers.
        """
        if bool(self.tls_cert) != bool(self.tls_key):
            raise ValueError("HOSTWATCH_TLS_CERT and HOSTWATCH_TLS_KEY must be set together")
        if self.tls_client_ca and not self.tls_configured:
            raise ValueError("HOSTWATCH_TLS_CLIENT_CA requires HOSTWATCH_TLS_CERT and HOSTWATCH_TLS_KEY")
        for name, path in (("HOSTWATCH_TLS_CERT", self.tls_cert), ("HOSTWATCH_TLS_KEY", self.tls_key),
                           ("HOSTWATCH_TLS_CLIENT_CA", self.tls_client_ca)):
            if path and not Path(path).is_file():
                raise ValueError(f"{name} does not point to a readable file: {path}")
        allowed = parse_allowed_clients(self.allowed_clients)
        if allowed and not any(_is_useful_client(a) for a in allowed):
            raise ValueError(
                "HOSTWATCH_ALLOWED_CLIENTS has no entry that can ever match a remote client: every entry is "
                "a loopback, unspecified, multicast or broadcast address. Loopback is always allowed without "
                "being listed, so add at least one unicast address of a real remote client.")
        if self.role != "agent":
            _check_bind_address(self.hub_bind)
        if self.role == "agent" or _is_loopback(self.hub_bind) or self.tls_configured:
            return
        if self.allow_insecure_bind:
            log.warning(
                "HOSTWATCH_ALLOW_INSECURE_BIND=1: the hub listens on %s without TLS. Passwords, session "
                "cookies and API keys cross the network in clear text. Use this only behind a TLS proxy "
                "you control.", self.hub_bind)
            return
        if allowed and _is_specific_address(self.hub_bind):
            log.warning(
                "The hub listens on %s without TLS, limited to the clients in HOSTWATCH_ALLOWED_CLIENTS. "
                "Passwords, session cookies and API keys cross that network unencrypted. The allowlist is "
                "exposure control, not authentication.", self.hub_bind)
            return
        raise ValueError(
            f"HOSTWATCH_HUB_BIND={self.hub_bind} is not a loopback address and TLS is not configured. "
            "Set HOSTWATCH_TLS_CERT and HOSTWATCH_TLS_KEY, bind to 127.0.0.1, bind to one specific host "
            "address (not 0.0.0.0 or ::) together with a non-empty HOSTWATCH_ALLOWED_CLIENTS, "
            "or set HOSTWATCH_ALLOW_INSECURE_BIND=1 to accept plain HTTP off-host."
        )


def normalize_ip(value: str):
    """Parse one address with ipaddress and map an IPv4-mapped IPv6 address to its IPv4 form."""
    addr = ipaddress.ip_address(value)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def parse_allowed_clients(raw: str) -> frozenset:
    """Parse HOSTWATCH_ALLOWED_CLIENTS: a comma separated list of individual addresses. CIDR
    ranges, hostnames and empty entries raise ValueError naming the entry."""
    if not raw.strip():
        return frozenset()
    out = set()
    for item in raw.split(","):
        entry = item.strip()
        if not entry:
            raise ValueError("HOSTWATCH_ALLOWED_CLIENTS contains an empty entry")
        if "%" in entry:
            raise ValueError(
                f"HOSTWATCH_ALLOWED_CLIENTS entry {entry!r} has a scope zone (%). Scoped IPv6 addresses are "
                "not accepted because the peer address the hub sees never carries a zone, so the entry "
                "could never match. Use the address without the zone.")
        try:
            out.add(normalize_ip(entry))
        except ValueError:
            raise ValueError(
                f"HOSTWATCH_ALLOWED_CLIENTS entry {entry!r} is not an individual IPv4 or IPv6 address "
                "(CIDR ranges and hostnames are not accepted)") from None
    return frozenset(out)


def _is_specific_address(host: str) -> bool:
    try:
        addr = normalize_ip(host)
    except ValueError:
        return False
    return not addr.is_unspecified and not addr.is_multicast


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


_BROADCAST = ipaddress.IPv4Address("255.255.255.255")


def _is_useful_client(addr) -> bool:
    """True for an address a remote client can actually connect from: unicast, not loopback,
    unspecified, multicast or broadcast."""
    return not (addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr == _BROADCAST)


def _check_bind_address(host: str) -> None:
    """Reject bind values that are never valid listener addresses: a scoped IPv6 address, a
    multicast address or the IPv4 broadcast address. Hostnames are left to the socket layer."""
    if "%" in host:
        raise ValueError(
            f"HOSTWATCH_HUB_BIND={host} has a scope zone (%). Scoped IPv6 addresses are not accepted; "
            "bind to a global or unique local address instead.")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return
    if addr.is_multicast or addr == _BROADCAST:
        raise ValueError(
            f"HOSTWATCH_HUB_BIND={host} is a multicast or broadcast address, which cannot accept "
            "connections. Bind to one unicast host address.")
