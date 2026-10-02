"""Collector registry. Order here is the order samples are gathered."""

from __future__ import annotations

from ..config import Config
from .base import Collector
from .cpu import CpuCollector
from .hwmon import HwmonCollector
from .mdraid import MdRaidCollector
from .memory import MemoryCollector
from .rapl import RaplCollector
from .scrutiny import ScrutinyCollector


def build_collectors(cfg: Config) -> list[Collector]:
    s, p = cfg.sysfs, cfg.procfs
    return [
        CpuCollector(s, p),
        MemoryCollector(s, p),
        RaplCollector(s, p),
        HwmonCollector(s, p),
        MdRaidCollector(s, p),
        ScrutinyCollector(s, p, cfg.scrutiny_url),
    ]
