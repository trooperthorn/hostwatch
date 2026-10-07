"""Which boot of the host is this? A scheduled reboot is done only when the boot has changed.

A daemon that starts again after the due time proves nothing: the service can be restarted by hand, by a
crash or by an update, with the host still on the same boot. So the boot is recorded when the reboot is
scheduled and compared when it falls due.

Linux uses the kernel boot_id. Windows has none, so the id is the boot time worked out from the tick
counter (`win:<epoch seconds>`) and two ids are the same boot when they are within BOOT_TIME_TOLERANCE_S,
which absorbs clock adjustments. A Windows host that reboots through Fast Startup keeps its tick counter
on some builds, so on those a real reboot may not be seen and is reported as not seen rather than done.
When the boot id cannot be read the answer is None, and nothing is reported done on that basis.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
BOOT_TIME_TOLERANCE_S = 120.0
WINDOWS_PREFIX = "win:"


def read() -> str | None:
    """The current boot id, or None when it cannot be read."""
    try:
        if sys.platform == "win32":
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.GetTickCount64.restype = ctypes.c_uint64
            return f"{WINDOWS_PREFIX}{int(time.time() - kernel32.GetTickCount64() / 1000.0)}"
        text = BOOT_ID_PATH.read_text(encoding="ascii").strip().lower()
        return text or None
    except (OSError, ValueError, AttributeError):
        return None


def changed(before: str | None, now: str | None) -> bool | None:
    """True when the two ids are different boots, False when the same, None when either is unknown."""
    if not before or not now:
        return None
    if before.startswith(WINDOWS_PREFIX) and now.startswith(WINDOWS_PREFIX):
        try:
            return abs(int(now[len(WINDOWS_PREFIX):]) - int(before[len(WINDOWS_PREFIX):])) > BOOT_TIME_TOLERANCE_S
        except ValueError:
            return None
    return before != now
