"""Agent-to-hub wire schema (version 1).

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


class Batch(BaseModel):
    schema_version: int = SCHEMA_VERSION
    agent_version: str
    host: str
    platform: str
    sent_at: float
    sources: list[SourceStatus]
    samples: list[Sample]

    def model_post_init(self, __context: Any) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
