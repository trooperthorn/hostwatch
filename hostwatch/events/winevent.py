"""Windows boot classification and crash events from the System event log.

The reader asks the Windows seam for a fixed set of System log records and turns them into the same
events the Linux sources produce. Kernel-Power 41, EventLog 6008 and BugCheck 1001 are logged by the
next boot, so they describe how the previous boot ended. EventLog 6006 is logged by a clean shutdown.
WHEA-Logger records become hardware_error events with the shape rasdaemon uses.

Windows has no boot_id that the event log exposes, so a boot event is keyed by the time of its
earliest record (boot_id "win-<epoch seconds>"). Records that belong to one shutdown are grouped when
they are close in time, and a group is classified only after it has been quiet for SETTLE_S, because
the BugCheck record can arrive minutes after the Kernel-Power record. Classification never guesses:
an unexpected shutdown with no bugcheck is unknown_unclean, because a power cut and a hang cannot be
told apart without an outside witness.

The bookmark is the time of the newest record that is finished with, kept in winevent_bookmark.json.
The keys of records already turned into events are kept with load_classified and save_classified from
the boot module, in a data directory of their own, so a restart does not repeat an event. State is
staged in the agent outbox, so they become durable together with the requests that carry the events. A
failed cycle discards them and the next cycle reads the same records again. Without an outbox they are
written to files before the events are returned. A read is oldest first and capped at MAX_EVENTS; a full
window moves the bookmark only to the newest record returned, and the rest is read next cycle. A bookmark
that is not finite, not positive or later than now plus CLOCK_SKEW_S is corrupt: it is logged once and
replaced by the first run lookback. A log that cannot be read makes the source unavailable with the reason.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from pathlib import Path
from typing import Any, Callable

from ..outbox import Markers
from ..model import Event, SourceStatus
from ..windows import SeamError, WindowsSeam
from . import boot

log = logging.getLogger(__name__)

SOURCE = "winevent"
LOG_NAME = "System"
KIND = "hardware_error"
BOOKMARK_FILE = "winevent_bookmark.json"
STATE_SUBDIR = "winevent"
BOOKMARK_MARKER = "winevent.bookmark"
KEYS_MARKER = "winevent.keys"

PROVIDER_POWER = "Microsoft-Windows-Kernel-Power"
PROVIDER_EVENTLOG = "EventLog"
PROVIDER_BUGCHECK = "Microsoft-Windows-WER-SystemErrorReporting"
PROVIDER_WHEA = "Microsoft-Windows-WHEA-Logger"

BOOT_IDS = (41, 6006, 6008, 1001)
WHEA_IDS = (1, 17, 18, 19, 20, 47)
READ_IDS = sorted(set(BOOT_IDS) | set(WHEA_IDS))

SETTLE_S = 900.0
FIRST_RUN_LOOKBACK_S = 7 * 86400.0
MAX_EVENTS = 500
CLOCK_SKEW_S = 300.0
CLEAN_SPLIT_S = 120.0


def _is_boot_record(rec: dict[str, Any]) -> bool:
    prov, eid = str(rec.get("provider") or ""), rec.get("id")
    return ((eid == 41 and prov == PROVIDER_POWER) or (eid in (6006, 6008) and prov == PROVIDER_EVENTLOG)
            or (eid == 1001 and prov == PROVIDER_BUGCHECK))


def _is_whea_record(rec: dict[str, Any]) -> bool:
    return rec.get("provider") == PROVIDER_WHEA and rec.get("id") in WHEA_IDS


def record_key(rec: dict[str, Any]) -> str:
    """Stable key for one record. It starts with the zero padded time so that the trimmed key list keeps the newest."""
    ident = rec.get("record") if rec.get("record") is not None else rec.get("id")
    return f"{int(rec['time']):012d}:{rec.get('provider')}:{rec.get('id')}:{ident}"


def _valid(rec: Any) -> bool:
    if not isinstance(rec, dict):
        return False
    t = rec.get("time")
    return (isinstance(t, (int, float)) and not isinstance(t, bool) and t == t and abs(t) != float("inf")
            and isinstance(rec.get("id"), int) and not isinstance(rec.get("id"), bool))


def classify_windows_boot(records: list[dict[str, Any]], now: float | None = None) -> boot.Classification:
    """Classify one shutdown from its grouped records. Precedence: a BugCheck 1001 is kernel_panic,
    then Kernel-Power 41 or EventLog 6008 is unknown_unclean, then EventLog 6006 alone is clean_shutdown.
    Evidence that disagrees is kept in detail.contradiction."""
    now = time.time() if now is None else now
    recs = sorted(records, key=lambda r: r["time"])
    first = float(recs[0]["time"])
    found = {(r.get("provider"), r.get("id")): r for r in recs}
    bug = found.get((PROVIDER_BUGCHECK, 1001))
    power = found.get((PROVIDER_POWER, 41))
    unexpected = found.get((PROVIDER_EVENTLOG, 6008))
    clean = found.get((PROVIDER_EVENTLOG, 6006))
    detail: dict[str, Any] = {
        "boot_id": f"win-{int(first)}", "previous_boot_id": None, "heartbeat_ts": first, "detected_at": now,
        "records": [{"id": r["id"], "provider": r.get("provider"), "time": r["time"],
                     "message": str(r.get("message") or "")[:500]} for r in recs],
        "evidence_seen": {"bugcheck_1001": bug is not None, "kernel_power_41": power is not None,
                          "eventlog_6008": unexpected is not None, "eventlog_6006": clean is not None},
    }

    def with_notes(extra: dict[str, Any], note: str) -> dict[str, Any]:
        out = {**detail, **extra}
        if clean is not None:
            out["contradiction"] = note
        return out

    if bug is not None:
        return boot.Classification(boot.KERNEL_PANIC, with_notes({
            "evidence": "BugCheck 1001 reports a reboot from a bugcheck",
            "bugcheck_message": str(bug.get("message") or "")[:500]},
            "a clean shutdown record 6006 is present but a BugCheck was also recorded"))
    if power is not None or unexpected is not None:
        return boot.Classification(boot.UNKNOWN_UNCLEAN, with_notes({
            "evidence": "Kernel-Power 41 or EventLog 6008 reports the previous shutdown was unexpected, with no BugCheck",
            "reason": "a power cut and a hang cannot be told apart without a witness"},
            "a clean shutdown record 6006 is present but an unexpected shutdown was also recorded"))
    return boot.Classification(boot.CLEAN_SHUTDOWN, {**detail, "evidence": "EventLog 6006 reports an orderly shutdown"})


def group_boot_records(records: list[dict[str, Any]], gap_s: float = SETTLE_S) -> list[list[dict[str, Any]]]:
    """Group boot records whose neighbours are within gap_s of each other, oldest group first. A clean
    shutdown record (6006) closes its group when the next record is more than CLEAN_SPLIT_S later, so a
    crash that follows a clean shutdown is a separate event and not a contradiction."""
    groups: list[list[dict[str, Any]]] = []
    for rec in sorted(records, key=lambda r: r["time"]):
        last = groups[-1][-1] if groups else None
        closed = (last is not None and last.get("id") == 6006 and last.get("provider") == PROVIDER_EVENTLOG
                  and rec["time"] - last["time"] > CLEAN_SPLIT_S)
        if groups and not closed and rec["time"] - groups[-1][-1]["time"] <= gap_s:
            groups[-1].append(rec)
        else:
            groups.append([rec])
    return groups


def _whea_severity(rec: dict[str, Any]) -> tuple[str, str]:
    msg = str(rec.get("message") or "").lower()
    if "fatal" in msg:
        return "critical", "Fatal"
    if "uncorrect" in msg:
        return "critical", "Uncorrected"
    if "corrected" in msg:
        return "warning", "Corrected"
    level = rec.get("level")
    return ("critical" if isinstance(level, int) and level <= 2 else "warning"), "Unknown"


def whea_event(rec: dict[str, Any]) -> Event:
    """A WHEA-Logger record as a hardware_error event, shaped like a rasdaemon one: err_type, err_msg and a table."""
    severity, err_type = _whea_severity(rec)
    message = str(rec.get("message") or "").strip()
    first_line = message.splitlines()[0] if message else "record"
    detail: dict[str, Any] = {"table": "WHEA-Logger", "event_id": rec["id"], "provider": rec.get("provider"),
                              "level": rec.get("level"), "err_type": err_type, "err_msg": message[:1000]}
    if rec.get("record") is not None:
        detail["record"] = rec["record"]
    return Event(kind=KIND, severity=severity, source=SOURCE, ts=float(rec["time"]),
                 title=f"WHEA-Logger {rec['id']}: {first_line[:200]}", detail=detail,
                 dedup_key=f"winevent:whea:{record_key(rec)}")


def load_bookmark(state_dir: Path) -> float | None:
    try:
        value = json.loads((state_dir / BOOKMARK_FILE).read_text(encoding="utf-8"))["ts"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        return float(value)
    except OverflowError:
        return math.inf


def save_bookmark(state_dir: Path, ts: float) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    tmp = state_dir / (BOOKMARK_FILE + ".tmp")
    tmp.write_text(json.dumps({"log": LOG_NAME, "ts": ts}), encoding="utf-8")
    os.replace(tmp, state_dir / BOOKMARK_FILE)


class WinEventReader:
    def __init__(self, seam: WindowsSeam, data_dir: Path, clock: Callable[[], float] = time.time,
                 markers: Markers | None = None) -> None:
        """With markers (the agent outbox) the bookmark and the classified keys are staged and become
        durable with the requests that carry the events. Without markers they are saved to files at once."""
        self.seam = seam
        self.state_dir = data_dir / STATE_SUBDIR
        self.clock = clock
        self.markers = markers
        self._warned_bookmark = False

    def _load_state(self) -> tuple[float | None, set[str]]:
        if self.markers is None:
            return load_bookmark(self.state_dir), boot.load_classified(self.state_dir)
        raw = self.markers.get(BOOKMARK_MARKER)
        bookmark: float | None = None
        if raw is None:
            bookmark = load_bookmark(self.state_dir)
        else:
            try:
                value = json.loads(raw)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    bookmark = float(value)
            except (ValueError, OverflowError):
                bookmark = math.inf
        raw_keys = self.markers.get(KEYS_MARKER)
        if raw_keys is None:
            return bookmark, boot.load_classified(self.state_dir)
        try:
            parsed = json.loads(raw_keys)
            keys = {k for k in parsed if isinstance(k, str)} if isinstance(parsed, list) else set()
        except ValueError:
            keys = set()
        return bookmark, keys

    def _save_state(self, mark: float, keys: set[str]) -> None:
        if self.markers is None:
            boot.save_classified(self.state_dir, keys)
            save_bookmark(self.state_dir, mark)
            return
        self.markers.stage(KEYS_MARKER, json.dumps(sorted(keys)[-boot.MAX_CLASSIFIED:]))
        self.markers.stage(BOOKMARK_MARKER, json.dumps(mark))

    def read(self) -> tuple[SourceStatus, list[Event]]:
        now = self.clock()
        bookmark, done = self._load_state()
        corrupt = False
        if bookmark is not None and not (math.isfinite(bookmark) and 0 < bookmark <= now + CLOCK_SKEW_S):
            if not self._warned_bookmark:
                log.warning("event log bookmark %r is not usable; reading back %d days instead",
                            bookmark, int(FIRST_RUN_LOOKBACK_S // 86400))
                self._warned_bookmark = True
            bookmark, corrupt = None, True
        since = bookmark if bookmark is not None else now - FIRST_RUN_LOOKBACK_S
        try:
            raw = self.seam.events.read(LOG_NAME, READ_IDS, since, MAX_EVENTS, oldest_first=True)
        except SeamError as exc:
            return SourceStatus(source=SOURCE, available=False,
                                reason=f"cannot read the {LOG_NAME} event log: {exc}"), []
        capped = len(raw) >= MAX_EVENTS
        records = sorted((r for r in raw if _valid(r)), key=lambda r: r["time"])
        skipped = len(raw) - len(records)
        fresh = [r for r in records if record_key(r) not in done]
        events: list[Event] = []
        new_keys: set[str] = set()
        for rec in (r for r in fresh if _is_whea_record(r)):
            events.append(whea_event(rec))
            new_keys.add(record_key(rec))
        seen = float(records[-1]["time"]) if records else None
        # A full window may end in the middle of a shutdown, so its newest record stands in for now.
        horizon = seen if capped and seen is not None else now
        holdback: float | None = None
        for group in group_boot_records([r for r in fresh if _is_boot_record(r)]):
            if horizon - group[-1]["time"] < SETTLE_S:
                holdback = group[0]["time"] if holdback is None else min(holdback, group[0]["time"])
                continue
            events.append(boot.boot_event(classify_windows_boot(group, now), now))
            new_keys.update(record_key(r) for r in group)
        mark = holdback if holdback is not None else seen
        if mark is None and corrupt:
            mark = since
        if mark is not None:
            if holdback is None and bookmark is not None:
                mark = max(mark, bookmark)
            self._save_state(mark, done | new_keys)
        reason = f"{skipped} record(s) skipped because they were malformed" if skipped else ""
        return SourceStatus(source=SOURCE, available=True, reason=reason), events
