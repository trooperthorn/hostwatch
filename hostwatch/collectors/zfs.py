"""ZFS pool state from /proc/spl/kstat/zfs/<pool>/state.

The state file of each pool is world readable on a ZFS host (measured on TrueNAS-SVR), so no
privilege and no API call is needed. Reported per pool:
  pool_state   1 when the state was read, with labels pool=<name> and state=<ONLINE|DEGRADED|...>;
               None when the state file could not be read

The hub maps the state text to a status: ONLINE ok, DEGRADED, FAULTED, UNAVAIL and SUSPENDED
critical, any other text unknown.
"""

from __future__ import annotations

from pathlib import Path

from .base import Collector, read_text


class ZfsCollector(Collector):
    linux_only = True
    id = "zfs"

    @property
    def _root(self) -> Path:
        return self.procfs / "spl" / "kstat" / "zfs"

    def _pools(self) -> list[Path]:
        """Directories under the zfs kstat root that hold a state entry, readable or not."""
        return sorted(p for p in self._root.iterdir() if p.is_dir() and (p / "state").exists())

    def detect(self):
        try:
            pools = self._pools()
        except OSError as exc:
            return False, f"could not list {self._root}: {type(exc).__name__}"
        if not pools:
            return False, "no zfs pools"
        return True, ", ".join(p.name for p in pools)

    def is_absent(self):
        """Absent when the zfs kstat directory is readable and holds no pools, or does not exist
        while /proc is readable (the zfs module is not loaded). Anything else stays unavailable."""
        try:
            return not self._pools()
        except FileNotFoundError:
            return self.procfs.is_dir()
        except OSError:
            return False

    def collect(self):
        out = []
        for pool in self._pools():
            state = read_text(pool / "state")
            out.append(self.sample("pool_state", 1 if state else None, "", pool=pool.name,
                                   state=state or "unknown"))
        return out
