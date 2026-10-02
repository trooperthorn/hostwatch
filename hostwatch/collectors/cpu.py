"""CPU utilization, frequency, idle-state residency, and throttle counters."""

from __future__ import annotations

import time

from .base import Collector, read_int, read_text


class CpuCollector(Collector):
    id = "cpu"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prev_stat: tuple[int, int] | None = None
        self._prev_idle: dict[tuple[str, str], int] = {}
        self._prev_t: float | None = None

    def detect(self) -> tuple[bool, str]:
        if read_text(self.procfs / "stat") is None:
            return False, "cannot read /proc/stat"
        return True, ""

    def _cpus(self):
        base = self.sysfs / "devices" / "system" / "cpu"
        if not base.is_dir():
            return []
        return sorted((p for p in base.iterdir() if p.name[3:].isdigit() and p.name.startswith("cpu")),
                      key=lambda p: int(p.name[3:]))

    def collect(self):
        out = []
        wall = time.time()
        now = time.monotonic()
        dt = None if self._prev_t is None else now - self._prev_t
        self._prev_t = now

        # Utilization from the aggregate "cpu" line of /proc/stat.
        stat = read_text(self.procfs / "stat") or ""
        for line in stat.splitlines():
            if line.startswith("cpu "):
                fields = [int(x) for x in line.split()[1:]]
                idle = fields[3] + (fields[4] if len(fields) > 4 else 0)  # idle + iowait
                total = sum(fields[:8])
                if self._prev_stat is not None:
                    d_total = total - self._prev_stat[0]
                    d_idle = idle - self._prev_stat[1]
                    if d_total > 0:
                        out.append(self.sample("utilization_pct", round(100 * (1 - d_idle / d_total), 2), "%", ts=wall))
                self._prev_stat = (total, idle)
                break

        load = read_text(self.procfs / "loadavg")
        if load:
            parts = load.split()
            for i, span in enumerate(("1m", "5m", "15m")):
                out.append(self.sample("load", float(parts[i]), "", ts=wall, span=span))

        for cpu in self._cpus():
            khz = read_int(cpu / "cpufreq" / "scaling_cur_freq")
            if khz is not None:
                out.append(self.sample("freq_mhz", round(khz / 1000, 1), "MHz", ts=wall, cpu=cpu.name))
            for kind in ("core", "package"):
                count = read_int(cpu / "thermal_throttle" / f"{kind}_throttle_count")
                if count is not None and (kind == "core" or cpu.name == "cpu0"):
                    out.append(self.sample(f"{kind}_throttle_count", count, "count", ts=wall, cpu=cpu.name))
            idle_dir = cpu / "cpuidle"
            if idle_dir.is_dir():
                for state in sorted(idle_dir.glob("state*")):
                    name = read_text(state / "name") or state.name
                    usec = read_int(state / "time")
                    if usec is None:
                        continue
                    key = (cpu.name, state.name)
                    prev = self._prev_idle.get(key)
                    self._prev_idle[key] = usec
                    if prev is not None and dt and dt > 0:
                        pct = min(100.0, max(0.0, (usec - prev) / (dt * 1e6) * 100))
                        out.append(self.sample("idle_residency_pct", round(pct, 2), "%", ts=wall,
                                               cpu=cpu.name, state=name))
        return out
