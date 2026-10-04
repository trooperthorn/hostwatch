"""Collector registry. Order here is the order samples are gathered."""

from __future__ import annotations

import sys

from ..config import Config, parse_sensor_patterns
from ..truenas.client import TruenasClient
from ..windows import WindowsSeam
from .base import Collector
from .cpu import CpuCollector
from .hwmon import HwmonCollector
from .mdraid import MdRaidCollector
from .memory import MemoryCollector
from .nut import NutCollector
from .rapl import RaplCollector
from .rpi import RpiCollector
from .scrutiny import ScrutinyCollector
from .thermalctl import ThermalctlCollector
from .truenas import TruenasCollector
from .win_cpu import WinCpuCollector
from .win_memory import WinMemoryCollector
from .win_storage import WinSmartctlCollector, WinStorageCollector
from .zfs import ZfsCollector


def build_collectors(cfg: Config, seam: WindowsSeam | None = None,
                     platform: str | None = None) -> list[Collector]:
    """Build the collectors in gather order. The seam is carried on each collector so Windows
    collectors read through it; the Linux collectors ignore it. On Windows the CPU and memory
    collectors are the seam-backed ones, which keep the source ids `cpu` and `memory`, so no host
    has two sources with one id, and the disk collectors `win_storage` and `win_smartctl` are added.
    `platform` defaults from `sys.platform`; tests pass it to build
    the Windows set on Linux."""
    s, p = cfg.sysfs, cfg.procfs
    windows = (platform or ("windows" if sys.platform == "win32" else "")) == "windows"
    built = [
        WinCpuCollector(s, p) if windows else CpuCollector(s, p),
        WinMemoryCollector(s, p) if windows else MemoryCollector(s, p),
        RaplCollector(s, p),
        HwmonCollector(s, p, parse_sensor_patterns("HOSTWATCH_HWMON_IGNORE", cfg.hwmon_ignore)),
        MdRaidCollector(s, p),
        ZfsCollector(s, p),
        ScrutinyCollector(s, p, cfg.scrutiny_url),
        NutCollector(s, p, cfg.nut_host, cfg.nut_ups, cfg.nut_user, cfg.nut_password_file, cfg.nut_port),
        TruenasCollector(s, p, TruenasClient.from_config(cfg)),
        RpiCollector(s, p, cfg.rpi_throttled_path),
        ThermalctlCollector(s, p, cfg.thermalctl_status),
    ]
    if windows:
        built += [WinStorageCollector(s, p), WinSmartctlCollector(s, p)]
    for c in built:
        c.seam = seam
    return built
