"""Edge-triggered threshold events from collected samples.

Each rule keeps a small state per subject (an array, a source, a drive) and
emits one event when the state changes: one on entry and one on recovery.
A steady state emits nothing. A sample whose value is None is unknown: it
never triggers a rule and never counts as a recovery, and the stored state is
left as it was.

State lives in memory. On start it is seeded from events already stored by the
hub (the dicts returned by Store.events or GET /internal/v1/events), so a
restart does not repeat an open condition. Every event carries the rule key
and the new state in its detail, which is what seeding reads back.

Rules:
  md.degraded             mdraid degraded > 0 raises, back to 0 clears
  md.sync_changed         the md sync_action label changed
  source.unavailable      a source went from available to unavailable
  source.available        that source came back
  scrutiny.status_raised  Scrutiny device_status grew above its previous value
  scrutiny.status_cleared device_status returned to 0
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any

from ..schema import Event, Sample, SourceStatus

SOURCE = "thresholds"


class ThresholdEngine:
    def __init__(self) -> None:
        # Key is "<rule>|<subject>". Value is a bool (degraded, source up), a str
        # (sync action) or an int (Scrutiny status).
        self.state: dict[str, Any] = {}

    def seed(self, stored_events: Iterable[dict]) -> None:
        """Rebuild state from stored events. Input order does not matter; the
        newest event per rule key wins."""
        newest: dict[str, tuple[float, Any]] = {}
        for ev in stored_events:
            detail = ev.get("detail") or {}
            key = detail.get("rule_key")
            if ev.get("source") != SOURCE or not isinstance(key, str) or "state" not in detail:
                continue
            ts = float(ev.get("ts", 0))
            if key not in newest or ts >= newest[key][0]:
                newest[key] = (ts, detail["state"])
        for key, (_, value) in newest.items():
            self.state[key] = value

    def evaluate(self, samples: Iterable[Sample], statuses: Iterable[SourceStatus],
                 now: float | None = None) -> list[Event]:
        now = time.time() if now is None else now
        out: list[Event] = []
        for s in samples:
            if s.value is None:
                continue  # unknown: neither a trigger nor a recovery
            if s.source == "mdraid" and s.metric == "degraded":
                self._degraded(s, now, out)
            elif s.source == "mdraid" and s.metric == "sync_action":
                self._sync(s, now, out)
            elif s.source == "scrutiny" and s.metric == "device_status":
                self._scrutiny(s, now, out)
        for st in statuses:
            self._source(st, now, out)
        return out

    def _emit(self, out: list[Event], key: str, kind: str, severity: str, now: float,
              title: str, state: Any, **detail: Any) -> None:
        self.state[key] = state
        out.append(Event(kind=kind, severity=severity, source=SOURCE, ts=now, title=title,
                         detail={"rule_key": key, "state": state, **detail},
                         dedup_key=f"{kind}:{key}:{now:.3f}"))

    def _degraded(self, s: Sample, now: float, out: list[Event]) -> None:
        arr = s.labels.get("array", "")
        key = f"md.degraded|array={arr}"
        active = s.value > 0  # type: ignore[operator]
        was = self.state.get(key)
        if active and was is not True:
            self._emit(out, key, "md.degraded", "critical", now,
                       f"md array {arr} is degraded", True, array=arr, degraded=s.value)
        elif not active and was is True:
            self._emit(out, key, "md.degraded_cleared", "info", now,
                       f"md array {arr} is no longer degraded", False, array=arr, degraded=s.value)
        elif was is None:
            self.state[key] = active

    def _sync(self, s: Sample, now: float, out: list[Event]) -> None:
        arr = s.labels.get("array", "")
        action = s.labels.get("action", "")
        key = f"md.sync|array={arr}"
        was = self.state.get(key)
        if was is None:
            self.state[key] = action  # first sight of an array is a baseline, not a change
        elif was != action:
            self._emit(out, key, "md.sync_changed", "info", now,
                       f"md array {arr} sync state changed from {was} to {action}", action,
                       array=arr, previous=was, current=action)

    def _scrutiny(self, s: Sample, now: float, out: list[Event]) -> None:
        subject = ",".join(f"{k}={v}" for k, v in sorted(s.labels.items()))
        key = f"scrutiny.status|{subject}"
        value = int(s.value)  # type: ignore[arg-type]
        was = self.state.get(key)
        prev = 0 if was is None else int(was)
        if value > prev:
            self._emit(out, key, "scrutiny.status_raised", "critical", now,
                       f"Scrutiny device_status grew from {prev} to {value}", value,
                       labels=dict(s.labels), previous=prev, current=value)
        elif value == 0 and prev > 0:
            self._emit(out, key, "scrutiny.status_cleared", "info", now,
                       "Scrutiny device_status returned to 0", 0, labels=dict(s.labels),
                       previous=prev, current=0)
        else:
            self.state[key] = value

    def _source(self, st: SourceStatus, now: float, out: list[Event]) -> None:
        key = f"source|source={st.source}"
        was = self.state.get(key)
        if was is True and not st.available:
            self._emit(out, key, "source.unavailable", "warning", now,
                       f"Source {st.source} became unavailable", False,
                       source_id=st.source, reason=st.reason)
        elif was is False and st.available:
            self._emit(out, key, "source.available", "info", now,
                       f"Source {st.source} is available again", True, source_id=st.source)
        elif was is None and st.available:
            self.state[key] = True
        # Unavailable from the start is normal, not a flip, so it is not recorded.
