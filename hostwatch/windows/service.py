"""The native Windows agent: a foreground run mode and a Windows service host.

The agent is the same `Agent` loop that Linux hosts run, built with the Windows seam and the Windows
Event Log reader. It keeps its durable outbox in the data directory (C:/ProgramData/hostwatch by
default) and pushes the unchanged wire schema with the same INGEST_KEY or INGEST_TOKEN bearer. The
destination is a URL setting, so it can later point at another receiver that ingests the same schema.

Two ways to run it:

  python -m hostwatch windows run     foreground, for a console check or a scheduled launcher
  the hostwatch-agent service         LocalSystem, started by the installer in deploy/windows/install.ps1

pywin32 is imported only inside `service_class` and `main`, never at import time, so this module loads
on Linux and the tests never need pywin32. The host logic that matters (build the agent, run it, flush
the outbox on a clean stop) lives in `AgentHost`, which has no Windows dependency and is tested with
fakes. Nothing here has run as a real service yet; see `UNVERIFIED.md`.

Settings come from environment variables, optionally seeded from a `KEY=value` file (`agent.env` in the
data directory). The installer protects that file so only SYSTEM and Administrators can read it. Values
from the file never override variables that are already set, and no value is ever logged.
"""

from __future__ import annotations

import dataclasses
import logging
import logging.handlers
import os
import re
import signal
import sys
from collections.abc import Callable, Mapping, MutableMapping
from pathlib import Path
from typing import Any

import httpx

from ..agent import Agent, hub_tls_verify
from ..config import Config
from ..events.winevent import WinEventReader
from . import WindowsSeam, real_seam

SERVICE_NAME = "hostwatch-agent"
SERVICE_DISPLAY_NAME = "hostwatch agent"
SERVICE_DESCRIPTION = "Collects host health and sends it to the configured hostwatch receiver."
DEFAULT_DATA_DIR = Path("C:/ProgramData/hostwatch")
ENV_FILE_NAME = "agent.env"
LOG_FILE_NAME = "agent.log"
# Event sources that read Linux journals and kernel stores. They do not exist on Windows, and the
# Event Log reader replaces them, so they are dropped rather than reported unavailable every cycle.
LINUX_ONLY_EVENT_SOURCES = ("pstore", "rasdaemon", "journal", "truenas_alerts")
_SETTING = re.compile(r"HOSTWATCH_[A-Z0-9_]+")

log = logging.getLogger("hostwatch.windows.service")


class WindowsAgent(Agent):
    """The agent loop for Windows. Boot and crash classification comes from the Event Log reader, so
    the Linux boot id and heartbeat check is skipped."""

    def start_boot_check(self) -> None:
        return None


def build_agent(cfg: Config, seam: WindowsSeam | None = None) -> Agent:
    """The Windows agent with its Event Log source, wired to the real seam unless one is given."""
    seam = seam if seam is not None else real_seam()
    agent = WindowsAgent(cfg, seam, platform="windows")
    for name in LINUX_ONLY_EVENT_SOURCES:
        agent.event_sources.pop(name, None)
    agent.event_sources["winevent"] = WinEventReader(seam, cfg.data_dir).read
    return agent


def load_env_file(path: Path, environ: MutableMapping[str, str] | None = None) -> list[str]:
    """Load `NAME=value` lines into the environment without overriding a variable that is already set.
    Blank lines and lines starting with # are skipped. Only HOSTWATCH_ names are accepted, and a bad
    line is rejected by line number without echoing its text, because it may hold a secret. Returns
    the names that were set."""
    env = os.environ if environ is None else environ
    applied: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        name = name.strip()
        if not sep or not _SETTING.fullmatch(name):
            raise ValueError(f"{path.name} line {number} is not a HOSTWATCH_NAME=value setting")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name not in env:
            env[name] = value
            applied.append(name)
    return applied


def build_config(data_dir: str | Path | None = None, env_file: str | Path | None = None) -> Config:
    """The agent Config, read from os.environ after the settings file is loaded. The data directory is
    the argument, else HOSTWATCH_DATA_DIR, else the default. The role is always agent."""
    folder = Path(data_dir or os.environ.get("HOSTWATCH_DATA_DIR") or DEFAULT_DATA_DIR)
    path = Path(env_file) if env_file else folder / ENV_FILE_NAME
    if path.is_file():
        load_env_file(path)
    cfg = dataclasses.replace(Config(), role="agent", data_dir=folder)
    cfg.validate()
    return cfg


class AgentHost:
    """Runs the agent and flushes the outbox once more when it stops. No Windows module is used here."""

    def __init__(self, cfg: Config, seam: WindowsSeam | None = None,
                 client_factory: Callable[[], httpx.Client] | None = None,
                 agent_factory: Callable[[Config, WindowsSeam | None], Agent] = build_agent) -> None:
        self.cfg = cfg
        self.agent = agent_factory(cfg, seam)
        self._client_factory = client_factory or (lambda: httpx.Client(verify=hub_tls_verify(cfg)))

    def stop(self) -> None:
        """Ask the loop to end. It only sets a flag, so a service control handler may call it."""
        self.agent.stop()

    def flush_outbox(self) -> bool:
        """One last delivery attempt. Batches the receiver does not accept stay queued on disk for the
        next start, so a failure here loses nothing. Returns True when the outbox is empty."""
        try:
            with self._client_factory() as client:
                self.agent.flush(client)
        except Exception as exc:
            log.warning("final delivery failed (%s); %d batch(es) stay queued for the next start",
                        type(exc).__name__, self.agent.outbox.depth())
            return False
        return True

    def run(self) -> None:
        """Block until stop() is called, then flush the outbox. The flush also runs if the loop fails."""
        try:
            self.agent.run()
        finally:
            self.flush_outbox()


def configure_logging(data_dir: Path, to_file: bool) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if to_file:
        data_dir.mkdir(parents=True, exist_ok=True)
        handlers = [logging.handlers.RotatingFileHandler(
            data_dir / LOG_FILE_NAME, maxBytes=5_000_000, backupCount=3, encoding="utf-8")]
    logging.basicConfig(level=logging.INFO, handlers=handlers, force=True,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def run_foreground(data_dir: str | None = None, env_file: str | None = None,
                   host_factory: Callable[[Config], Any] = AgentHost) -> int:
    """`python -m hostwatch windows run`. Ctrl+C or a break signal stops the loop and flushes."""
    try:
        cfg = build_config(data_dir, env_file)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    host = host_factory(cfg)
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        number = getattr(signal, name, None)
        if number is not None:
            try:
                signal.signal(number, lambda *_: host.stop())
            except ValueError:
                pass  # not the main thread
    host.run()
    return 0


def service_class():
    """Build the pywin32 service class. pywin32 is imported here so nothing else needs it."""
    import servicemanager
    import win32service
    import win32serviceutil

    class HostwatchAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self.host: AgentHost | None = None
            self.stop_requested = False

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_requested = True
            if self.host is not None:
                self.host.stop()

        def SvcDoRun(self):
            data_dir = Path(os.environ.get("HOSTWATCH_DATA_DIR") or DEFAULT_DATA_DIR)
            try:
                configure_logging(data_dir, to_file=True)
                self.host = AgentHost(build_config(data_dir))
                if self.stop_requested:
                    self.host.stop()
                servicemanager.LogInfoMsg(f"{SERVICE_NAME} started")
                self.host.run()
            except Exception as exc:
                log.exception("the agent service failed")
                servicemanager.LogErrorMsg(f"{SERVICE_NAME} failed: {type(exc).__name__}")
                raise  # a non-zero exit lets the recovery actions restart the service
            servicemanager.LogInfoMsg(f"{SERVICE_NAME} stopped")

    return HostwatchAgentService


def main(argv: list[str] | None = None) -> int:
    """Service entry point: `python -m hostwatch.windows.service install|remove|start|stop|update`.
    With no arguments the service control manager is hosting the process."""
    import servicemanager
    import win32serviceutil

    argv = sys.argv if argv is None else argv
    cls = service_class()
    if len(argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(cls)
        servicemanager.StartServiceCtrlDispatcher()
        return 0
    win32serviceutil.HandleCommandLine(cls, argv=argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
