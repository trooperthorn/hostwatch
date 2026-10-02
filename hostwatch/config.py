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
    mtls_mode: str = field(default_factory=lambda: _env("HOSTWATCH_MTLS_MODE", "off").lower())
    mtls_trusted_proxies: str = field(default_factory=lambda: _env("HOSTWATCH_MTLS_TRUSTED_PROXIES", ""))
    scrutiny_url: str = field(default_factory=lambda: _env("HOSTWATCH_SCRUTINY_URL", ""))
    raw_retention_days: int = field(default_factory=lambda: int(_env("HOSTWATCH_RAW_RETENTION_DAYS", "7")))
    rollup_retention_days: int = field(default_factory=lambda: int(_env("HOSTWATCH_ROLLUP_RETENTION_DAYS", "400")))

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

        self._validate_bind()

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
        if self.role == "agent" or _is_loopback(self.hub_bind) or self.tls_configured:
            return
        if not self.allow_insecure_bind:
            raise ValueError(
                f"HOSTWATCH_HUB_BIND={self.hub_bind} is not a loopback address and TLS is not configured. "
                "Set HOSTWATCH_TLS_CERT and HOSTWATCH_TLS_KEY, bind to 127.0.0.1, "
                "or set HOSTWATCH_ALLOW_INSECURE_BIND=1 to accept plain HTTP off-host."
            )
        log.warning(
            "HOSTWATCH_ALLOW_INSECURE_BIND=1: the hub listens on %s without TLS. Passwords, session "
            "cookies and API keys cross the network in clear text. Use this only behind a TLS proxy "
            "you control.", self.hub_bind)


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
