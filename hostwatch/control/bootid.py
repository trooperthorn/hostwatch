"""Which boot of the host is this? A scheduled reboot is done only when the boot has changed.

A daemon that starts again after the due time proves nothing: the service can be restarted by hand, by a
crash or by an update, with the host still on the same boot. So the boot is recorded when the reboot is
scheduled and compared when it falls due.

Linux uses the kernel boot_id. Windows has none, so the id is `win:<boot epoch seconds>:<tick ms>`: the boot
time worked out from the tick counter, and the tick counter itself. The tick counter only grows within one
boot, so a smaller tick count than the recorded one is a new boot whatever the wall clock did. When the tick
count has not gone down, the same boot is a boot time within BOOT_TIME_TOLERANCE_S. A boot time further away
is ambiguous, because it is either a wall clock correction (an NTP resync) or a reboot after which the host
has been up longer than it was at scheduling, so it answers None and nothing is reported done. A Windows host
that reboots through Fast Startup keeps its tick counter on some builds, so on those a real reboot may not be
seen and is reported as not seen rather than done. When the boot id cannot be read the answer is None, and
nothing is reported done on that basis.
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
            ticks = int(kernel32.GetTickCount64())
            return f"{WINDOWS_PREFIX}{int(time.time() - ticks / 1000.0)}:{ticks}"
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
            b_epoch, _, b_ticks = before[len(WINDOWS_PREFIX):].partition(":")
            n_epoch, _, n_ticks = now[len(WINDOWS_PREFIX):].partition(":")
            if b_ticks and n_ticks and int(n_ticks) < int(b_ticks):
                return True  # the tick counter went back: the host started again
            if abs(int(n_epoch) - int(b_epoch)) <= BOOT_TIME_TOLERANCE_S:
                return False
            return None  # a clock correction or a reboot that cannot be told apart: do not say done
        except ValueError:
            return None
    return before != now
