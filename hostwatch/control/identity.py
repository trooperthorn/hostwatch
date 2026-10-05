"""Which machine is this? hostwatch-control refuses to act under another machine's name.

control.toml names the host this daemon speaks for. If the file was copied to the wrong machine, the
daemon would run that host's commands, a reboot included, on this one. So the host name in the file must
match the machine's own name: the full name, the short name (before the first dot) or, on Windows,
COMPUTERNAME, compared without regard to case. A host whose operating system name differs from the
name used in watchpost sets `machine_id` in control.toml instead. It must equal /etc/machine-id on Linux
or the MachineGuid registry value on Windows. When machine_id is set, it alone decides.

The check runs when the daemon starts and again before every command, so a renamed or cloned disk stops too.
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

from .config import ControlConfig

WRONG_MACHINE = "wrong_machine"
LINUX_MACHINE_ID = Path("/etc/machine-id")


def machine_names() -> set[str]:
    """Every name this machine answers to, lower case, each with its short form."""
    raw = {socket.gethostname(), socket.getfqdn()}
    if sys.platform == "win32":
        raw.add(os.environ.get("COMPUTERNAME", ""))
    names: set[str] = set()
    for name in raw:
        name = name.strip().lower()
        if name:
            names.add(name)
            names.add(name.split(".")[0])
    return names


def local_machine_id() -> str:
    """The machine id, or an empty string when it cannot be read."""
    try:
        if sys.platform == "win32":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                return str(winreg.QueryValueEx(key, "MachineGuid")[0]).strip().lower()
        return LINUX_MACHINE_ID.read_text(encoding="ascii").strip().lower()
    except (OSError, ImportError, ValueError):
        return ""


def check(config: ControlConfig) -> str:
    """An empty string when this machine is the one control.toml is for, otherwise the reason it is not."""
    if config.machine_id:
        actual = local_machine_id()
        if actual and actual == config.machine_id.strip().lower():
            return ""
        return (f"control.toml machine_id does not match this machine (host {config.host!r}); "
                "refusing to act for another machine")
    host = config.host.strip().lower()
    names = machine_names()
    if host in names or host.split(".")[0] in {n.split(".")[0] for n in names}:
        return ""
    return (f"control.toml is for host {config.host!r} but this machine is "
            f"{socket.gethostname()!r}; refusing to act under another machine's name. "
            "Install the control service from the page of the host it belongs to, or set machine_id")
