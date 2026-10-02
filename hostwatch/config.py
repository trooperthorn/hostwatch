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
    scrutiny_url: str = field(default_factory=lambda: _env("HOSTWATCH_SCRUTINY_URL", ""))
    quarantine_after: int = field(default_factory=lambda: int(_env("HOSTWATCH_QUARANTINE_AFTER", "5")))
    raw_retention_days: int = field(default_factory=lambda: int(_env("HOSTWATCH_RAW_RETENTION_DAYS", "7")))
    rollup_retention_days: int = field(default_factory=lambda: int(_env("HOSTWATCH_ROLLUP_RETENTION_DAYS", "400")))

    def validate(self) -> None:
        if self.role not in {"all", "hub", "agent"}:
            raise ValueError(f"HOSTWATCH_ROLE must be all, hub, or agent (got {self.role!r})")
        if len(self.ingest_token) < 32:
            raise ValueError(
                "HOSTWATCH_INGEST_TOKEN must be set to at least 32 characters. "
                "Generate one with: openssl rand -hex 32"
            )
