"""Prometheus text exposition format (version 0.0.4) for the shared `HostSummary`.

Written by hand so the optional endpoint adds no dependency. A value that is
unavailable produces no sample at all, never a zero, which is the project rule
for unavailable data. What the scraper can still learn is carried by the
`hostwatch_source_up` gauge, 1 when a source reports and 0 when it is
unavailable or stale, so an alert can distinguish "healthy" from "not measured".
"""

from __future__ import annotations

from .summary import Component, HostSummary

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def escape_label_value(value: str) -> str:
    """Escape backslash, double quote and newline, as the exposition format requires."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def escape_help(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\n", "\\n")


class _Families:
    def __init__(self) -> None:
        self._order: list[str] = []
        self._meta: dict[str, tuple[str, str]] = {}
        self._samples: dict[str, list[str]] = {}

    def add(self, name: str, help_text: str, labels: dict[str, str], value: float, kind: str = "gauge") -> None:
        if name not in self._meta:
            self._order.append(name)
            self._meta[name] = (help_text, kind)
            self._samples[name] = []
        pairs = ",".join(f'{k}="{escape_label_value(str(v))}"' for k, v in labels.items())
        self._samples[name].append(f"{name}{{{pairs}}} {_fmt(value)}")

    def render(self) -> str:
        lines: list[str] = []
        for name in self._order:
            help_text, kind = self._meta[name]
            lines.append(f"# HELP {name} {escape_help(help_text)}")
            lines.append(f"# TYPE {name} {kind}")
            lines.extend(self._samples[name])
        return "\n".join(lines) + "\n" if lines else ""


def _fmt(value: float) -> str:
    return repr(float(value))


def _add(fam: _Families, name: str, help_text: str, host: str, c: Component, extra: dict[str, str] | None = None):
    # Both the value and the state must be known; otherwise the sample is omitted.
    if c.value is None or c.status is None:
        return
    labels = {"host": host, **(extra or {})}
    fam.add(name, help_text, labels, c.value)


def render(summaries: list[HostSummary]) -> str:
    fam = _Families()
    for s in summaries:
        h = s.host
        _add(fam, "hostwatch_cpu_utilization_percent", "CPU utilization in percent.", h, s.cpu)
        _add(fam, "hostwatch_memory_used_percent", "Memory used in percent.", h, s.memory)
        _add(fam, "hostwatch_package_power_watts", "CPU package power in watts.", h, s.package_power)
        if s.wall_power is not None:
            _add(fam, "hostwatch_wall_power_watts", "Power drawn at the wall in watts.", h, s.wall_power)
        for c in s.temperatures:
            if c.labels:
                _add(fam, "hostwatch_temperature_celsius", "Temperature in degrees Celsius.", h, c,
                     {k: v for k, v in sorted(c.labels.items())})
        for c in s.md_arrays:
            _add(fam, "hostwatch_md_degraded_devices", "Degraded devices in an md RAID array.", h, c,
                 {"array": c.labels.get("array", "")})
        for c in s.pools:
            _add(fam, "hostwatch_pool_status", "Pool health, the worse of the zfs kstat and TrueNAS API views: 0 ok, 1 warning, 2 critical. The source label names the contributing sources.", h, c,
                 {"pool": c.labels.get("pool", ""), "source": c.labels.get("source", "")})
        for c in s.disks:
            _add(fam, "hostwatch_disk_device_status", "Scrutiny device status, 0 when healthy.", h, c,
                 {k: v for k, v in sorted(c.labels.items())})
        for name, c in s.sources.items():
            fam.add("hostwatch_source_up", "1 when the source reports, 0 when it is unavailable or stale.",
                    {"host": h, "source": name}, 1 if c.value is not None else 0)
        for name, c in s.sources.items():
            fam.add("hostwatch_source_present",
                    "0 when the agent established that the source is absent by design, otherwise 1.",
                    {"host": h, "source": name}, 0 if c.state == "not_present" else 1)
        fam.add("hostwatch_host_status",
                "Overall status: 0 ok, 1 warning (also while a group is unmeasured), 2 critical (also no data).",
                {"host": h}, s.overall_status)
        fam.add("hostwatch_host_unmeasured_groups", "Expected component groups that are not being measured.",
                {"host": h}, len(s.unmeasured))
    return fam.render()
