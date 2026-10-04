"""Collector registry. Order here is the order samples are gathered."""

from __future__ import annotations

from ..config import Config, parse_sensor_patterns
from ..truenas.client import TruenasClient
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
from .zfs import ZfsCollector


def build_collectors(cfg: Config) -> list[Collector]:
    s, p = cfg.sysfs, cfg.procfs
    return [
        CpuCollector(s, p),
        MemoryCollector(s, p),
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
