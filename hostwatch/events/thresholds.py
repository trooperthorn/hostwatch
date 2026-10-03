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
  source.disappeared      a source that was present and available reports present false (critical)
  source.returned         that source is present and available again
  scrutiny.status_raised  Scrutiny device_status grew above its previous value
  scrutiny.status_cleared device_status returned to 0
  ups.on_battery          ups.status changed from on line to OB (warning)
  ups.low_battery         ups.status shows LB (critical)
  ups.on_line             ups.status is OL again after OB or LB
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
        samples_list = list(samples)
        for s in samples_list:
            if s.value is None:
                continue  # unknown: neither a trigger nor a recovery
            if s.source == "mdraid" and s.metric == "degraded":
                self._degraded(s, now, out)
            elif s.source == "mdraid" and s.metric == "sync_action":
                self._sync(s, now, out)
            elif s.source == "scrutiny" and s.metric == "device_status":
                self._scrutiny(s, now, out)
        self._ups(samples_list, now, out)
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

    def _ups(self, samples: list[Sample], now: float, out: list[Event]) -> None:
        """Edges of the ups.status flags. The state is "OL", "OB" or "LB" (LB wins over OB).

        All three core flags must be known in the cycle; otherwise nothing changes. The first
        sight of a UPS on line is a baseline; first sight on battery raises, like a degraded array.
        """
        flags: dict[str, Any] = {}
        status = ""
        for s in samples:
            if s.source == "nut" and s.metric == "ups_status_flag" and s.labels.get("flag") in ("OL", "OB", "LB"):
                flags[s.labels["flag"]] = s.value
                status = s.labels.get("status", status)
        if len(flags) < 3 or any(v is None for v in flags.values()):
            return
        new = "LB" if flags["LB"] else "OB" if flags["OB"] else "OL" if flags["OL"] else None
        if new is None:
            return
        key = "ups.power|ups"
        was = self.state.get(key)
        if new == was:
            return
        if new == "LB":
            self._emit(out, key, "ups.low_battery", "critical", now, "UPS battery is low", new, status=status)
        elif new == "OB" and was in (None, "OL"):
            self._emit(out, key, "ups.on_battery", "warning", now, "UPS is running on battery", new,
                       status=status)
        elif new == "OL" and was is not None:
            self._emit(out, key, "ups.on_line", "info", now, "UPS is back on line power", new, status=status)
        else:
            self.state[key] = new  # first OL baseline, or LB recovered while still on battery

    def _presence(self, st: SourceStatus, now: float, out: list[Event]) -> None:
        key = f"source.presence|source={st.source}"
        was = self.state.get(key)
        if st.present and st.available:
            if was is False:
                self._emit(out, key, "source.returned", "info", now,
                           f"Source {st.source} is present and available again", True, source_id=st.source)
            else:
                self.state[key] = True
        elif not st.present and was is True:
            self._emit(out, key, "source.disappeared", "critical", now,
                       f"Source {st.source} disappeared after it had been present", False,
                       source_id=st.source, reason=st.reason)

    def _source(self, st: SourceStatus, now: float, out: list[Event]) -> None:
        self._presence(st, now, out)
        if not st.present:
            return  # reported by the presence rule, not as an ordinary unavailable flip
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
