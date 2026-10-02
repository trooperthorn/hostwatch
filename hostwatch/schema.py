"""Agent-to-hub wire schema (version 1).

Events (boot classifications, journal matches, threshold crossings) travel in
the optional Batch.events list. The field defaults to empty and is purely
additive, so SCHEMA_VERSION stays at 1: v1 agents that never send it remain
valid, and an older hub that does not know the field ignores it. Event sources
are reported in Batch.sources like any other source, with available=False and a
reason when absent.

This is the contract between any agent (Linux now, Windows in Phase 8) and the
hub. Keep it small and explicit: a batch carries samples plus a report of which
sources were available, so the hub can tell "value is zero" apart from "this
host cannot measure that".

A sample with value None means the source exists but could not produce a value
this cycle (for example a transient read error). It is stored as unavailable,
never as zero.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from . import SCHEMA_VERSION


class Sample(BaseModel):
    source: str = Field(description="collector id, e.g. rapl, mdraid")
    metric: str = Field(description="metric name within the source, e.g. package_watts")
    value: float | None
    unit: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    ts: float = Field(description="unix epoch seconds when the value was read")


class SourceStatus(BaseModel):
    source: str
    available: bool
    reason: str = ""


class Event(BaseModel):
    kind: str = Field(description="event kind, e.g. boot.clean_shutdown or md.degraded")
    severity: str = Field(description="info, warning, or critical")
    source: str = Field(description="event source id, e.g. journal, pstore, rasdaemon")
    ts: float = Field(description="unix epoch seconds when the event happened")
    title: str
    detail: dict[str, Any] = Field(default_factory=dict)
    dedup_key: str = Field(min_length=1, description="stable key; the hub keeps one row per host and key")
    boot_id: str | None = Field(default=None, description="kernel boot_id the event belongs to, when known")


class Batch(BaseModel):
    schema_version: int = SCHEMA_VERSION
    agent_version: str
    host: str
    platform: str
    sent_at: float
    sources: list[SourceStatus]
    samples: list[Sample]
    events: list[Event] = Field(default_factory=list)
    batch_id: str | None = Field(
        default=None, min_length=1, max_length=64,
        description="optional uuid string, set once per batch and reused on resend so the hub can acknowledge a repeat")

    def model_post_init(self, __context: Any) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
