"""Runtime configuration, read from environment variables.

Every setting has a default that works for the single-container "all" role on
a Linux host with /sys bind-mounted read-only at /host/sys. /proc is the
container's own: the files read (stat, meminfo, loadavg) are system-wide, so the
host /proc, which would expose every host process, is not mounted. The event
sources (journal, pstore, rasdaemon database) are read-only mounts under /host.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


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
    argon2_time_cost: int = field(default_factory=lambda: int(_env("HOSTWATCH_ARGON2_TIME_COST", "3")))
    argon2_memory_kib: int = field(default_factory=lambda: int(_env("HOSTWATCH_ARGON2_MEMORY_KIB", "65536")))
    argon2_parallelism: int = field(default_factory=lambda: int(_env("HOSTWATCH_ARGON2_PARALLELISM", "4")))
    login_max_failures: int = field(default_factory=lambda: int(_env("HOSTWATCH_LOGIN_MAX_FAILURES", "5")))
    login_lock_s: float = field(default_factory=lambda: float(_env("HOSTWATCH_LOGIN_LOCK_S", "900")))
    session_ttl_s: float = field(default_factory=lambda: float(_env("HOSTWATCH_SESSION_TTL_S", "28800")))
    tls_enabled: bool = field(default_factory=lambda: _env("HOSTWATCH_TLS", "0").lower() in {"1", "true", "yes"})
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
        if self.mtls_mode == "proxy":
            from .mtls import parse_proxies
            try:
                proxies = parse_proxies(self.mtls_trusted_proxies)
            except ValueError as exc:
                raise ValueError(f"HOSTWATCH_MTLS_TRUSTED_PROXIES is not a list of addresses: {exc}") from exc
            if not proxies:
                raise ValueError("HOSTWATCH_MTLS_MODE=proxy requires HOSTWATCH_MTLS_TRUSTED_PROXIES")
        if len(self.ingest_token) < 32:
            raise ValueError(
                "HOSTWATCH_INGEST_TOKEN must be set to at least 32 characters. "
                "Generate one with: openssl rand -hex 32"
            )
