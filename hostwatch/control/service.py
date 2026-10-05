"""The hostwatch-control Windows service host.

A separate service from the collector's hostwatch-agent, with its own registration and its own
settings. It runs as LocalSystem because the Thermal Control Suite pipe treats LocalSystem as an
Administrator and `Restart-Service` and `shutdown.exe` need that privilege. The data folder (replay
state, result outbox, control.env, control.toml and control.log) is recorded by the installer as the
service parameter `DataDir` and read here before anything else.

pywin32 is imported only inside `service_class` and `main`, never at import time, so this module loads
on Linux and the tests never need pywin32. The loop itself is `daemon.ControlDaemon`, which has no
Windows dependency. Nothing here has run as a real service yet; see `UNVERIFIED.md`.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable
from pathlib import Path

from . import daemon

SERVICE_NAME = "hostwatch-control"
SERVICE_DISPLAY_NAME = "hostwatch control"
SERVICE_DESCRIPTION = "Pulls signed commands from watchpost, checks them against the local allowlist and runs them."
SERVICE_MODULE = "hostwatch.control.service"
SERVICE_CLASS_NAME = "HostwatchControlService"
SERVICE_CLASS_STRING = f"{SERVICE_MODULE}.{SERVICE_CLASS_NAME}"
REGISTRY_PARAMETERS_KEY = r"SYSTEM\CurrentControlSet\Services\hostwatch-control\Parameters"
REGISTRY_DATA_DIR_VALUE = "DataDir"

log = logging.getLogger("hostwatch.control.service")


def registry_data_dir(reader: Callable[[str, str], str | None] | None = None) -> Path | None:
    """The data folder the installer recorded in the service parameters, or None when it is absent."""
    if reader is None:
        def reader(key: str, name: str) -> str | None:
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as handle:
                    value, _kind = winreg.QueryValueEx(handle, name)
            except OSError:
                return None
            return value if isinstance(value, str) else None
    value = reader(REGISTRY_PARAMETERS_KEY, REGISTRY_DATA_DIR_VALUE)
    return Path(value) if value else None


def service_data_dir(reader: Callable[[str, str], str | None] | None = None) -> Path:
    """The installer's registry parameter, else HOSTWATCH_CONTROL_DATA_DIR, else the Windows default."""
    return registry_data_dir(reader) or Path(os.environ.get("HOSTWATCH_CONTROL_DATA_DIR") or daemon.WINDOWS_DATA_DIR)


def service_exe_name(prefix: str | Path | None = None) -> str | None:
    """The pythonservice.exe that belongs to this environment's pywin32, so a venv install does not
    register the base interpreter's copy. None leaves the choice to pywin32 when the file is absent."""
    base = Path(sys.prefix if prefix is None else prefix)
    candidate = base / "Lib" / "site-packages" / "win32" / "pythonservice.exe"
    return str(candidate) if candidate.is_file() else None


_service_class_cache: list[type] = []


def __getattr__(name: str):
    """Module level access to the service class for pywin32, which loads the registered class by its
    dotted string. The class is built on first use so importing this module never needs pywin32."""
    if name == SERVICE_CLASS_NAME:
        if not _service_class_cache:
            _service_class_cache.append(service_class())
        return _service_class_cache[0]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def service_class():
    """Build the pywin32 service class. pywin32 is imported here so nothing else needs it."""
    import servicemanager
    import win32service
    import win32serviceutil

    class HostwatchControlService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION
        _exe_name_ = service_exe_name()

        def __init__(self, args):
            super().__init__(args)
            self.daemon: daemon.ControlDaemon | None = None
            self.stop_requested = False

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_requested = True
            if self.daemon is not None:
                self.daemon.stop()

        def SvcDoRun(self):
            data_dir = service_data_dir()
            try:
                daemon.configure_logging(data_dir)
                settings = daemon.settings_from_files(data_dir)
                self.daemon = daemon.build_daemon(settings)
                if self.stop_requested:
                    self.daemon.stop()
                servicemanager.LogInfoMsg(f"{SERVICE_NAME} started")
                try:
                    self.daemon.run()
                finally:
                    self.daemon.close()
            except Exception as exc:
                log.exception("the control service failed")
                servicemanager.LogErrorMsg(f"{SERVICE_NAME} failed: {type(exc).__name__}")
                raise  # a non-zero exit lets the recovery actions restart the service
            servicemanager.LogInfoMsg(f"{SERVICE_NAME} stopped")

    return HostwatchControlService


def main(argv: list[str] | None = None) -> int:
    """Service entry point: `python -m hostwatch.control.service install|remove|start|stop|update`.
    With no arguments the service control manager is hosting the process."""
    import servicemanager
    import win32serviceutil

    argv = sys.argv if argv is None else argv
    cls = getattr(sys.modules[__name__], SERVICE_CLASS_NAME)
    if len(argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(cls)
        servicemanager.StartServiceCtrlDispatcher()
        return 0
    win32serviceutil.HandleCommandLine(cls, serviceClassString=SERVICE_CLASS_STRING, argv=argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
