"""Readings, source reports and events as the collectors produce them.

These are the agent's own data types. They never cross the network as they are: otel_map.py turns
them into OpenTelemetry points and log records, and otlp.py encodes those for Observe.

A sample with value None means the source exists but could not produce a value this cycle (for
example a transient read error). It is never turned into zero, and the mapping drops it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Sample(BaseModel):
    source: str = Field(description="collector id, e.g. rapl, mdraid")
    metric: str = Field(description="metric name within the source, e.g. package_watts")
    value: float | None
    unit: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    ts: float = Field(allow_inf_nan=False, description="unix epoch seconds when the value was read")


class SourceStatus(BaseModel):
    source: str
    available: bool
    reason: str = ""
    present: bool = Field(
        default=True,
        description="False only when the collector positively established that this host has no such source "
                    "(for example no md arrays). An unreadable source stays present and unavailable. "
                    "Agents that never send the field are read as present.")
    pending: bool = Field(
        default=False,
        description="True while a first read is still running. The status is a placeholder, so the agent "
                    "logs no source change for it.")


class Event(BaseModel):
    kind: str = Field(description="event kind, e.g. boot.clean_shutdown or md.degraded")
    severity: str = Field(description="info, warning, or critical")
    source: str = Field(description="event source id, e.g. journal, pstore, rasdaemon")
    ts: float = Field(allow_inf_nan=False, description="unix epoch seconds when the event happened")
    title: str
    detail: dict[str, Any] = Field(default_factory=dict)
    dedup_key: str = Field(min_length=1, description="stable key; Observe keeps one row per host and key")
    boot_id: str | None = Field(default=None, description="kernel boot_id the event belongs to, when known")
