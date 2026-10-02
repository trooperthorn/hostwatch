"""Linux software RAID (md) health from /sys/block/md*/md.

Reported per array:
  degraded            number of missing members (0 is healthy)
  raid_disks          configured member count
  array_state         1 with label state=<clean|active|...>
  sync_action         1 with label action=<idle|check|resync|recover|...>
  sync_progress_pct   only while an action is running
  mismatch_cnt        sectors that differed in the last check (0 is healthy)
"""

from __future__ import annotations

from .base import Collector, read_int, read_text


class MdRaidCollector(Collector):
    id = "mdraid"

    def _arrays(self):
        base = self.sysfs / "block"
        if not base.is_dir():
            return []
        return sorted(p for p in base.glob("md*") if (p / "md").is_dir())

    def detect(self):
        arrays = self._arrays()
        if not arrays:
            return False, "no md arrays"
        return True, ", ".join(a.name for a in arrays)

    def collect(self):
        out = []
        for arr in self._arrays():
            md = arr / "md"
            name = arr.name
            level = read_text(md / "level") or ""
            for metric in ("degraded", "raid_disks", "mismatch_cnt"):
                val = read_int(md / metric)
                out.append(self.sample(metric, val, "count", array=name, level=level))
            state = read_text(md / "array_state")
            out.append(self.sample("array_state", 1 if state else None, "", array=name, state=state or "unknown"))
            action = read_text(md / "sync_action")
            out.append(self.sample("sync_action", 1 if action else None, "", array=name, action=action or "unknown"))
            completed = read_text(md / "sync_completed")
            if completed and "/" in completed:
                done, total = (int(x) for x in completed.split("/"))
                if total:
                    out.append(self.sample("sync_progress_pct", round(100 * done / total, 2), "%", array=name))
        return out
