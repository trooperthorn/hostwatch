"""Heartbeat-based boot classifier.

The agent rewrites a small heartbeat file in the data directory on every cycle.
The file holds the current boot_id, a timestamp, and an agent_stopped_cleanly
flag that is false while running and set true only when the agent is told to stop
(SIGTERM). That flag says only that the agent stopped. A container stop is not a
host shutdown, so a clean host shutdown also needs journal evidence from the
previous boot. At the next start, a different boot_id means the host rebooted,
and the previous heartbeat plus fresh pstore and journal evidence say how the
previous boot ended.

Classification never guesses. Without a previous heartbeat, or without evidence
that separates the unclean causes, the result is "unknown" and the detail says
what was missing. See UNVERIFIED.md for the parts that are not yet confirmed on
real hardware.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..model import Event
from ..privfile import write_private

log = logging.getLogger("hostwatch.boot")

HEARTBEAT_FILE = "heartbeat.json"
BOOT_ID_REL = "sys/kernel/random/boot_id"

CLEAN_SHUTDOWN = "clean_shutdown"
AGENT_STOPPED = "agent_stopped"
WATCHDOG_RESET = "watchdog_reset"
KERNEL_PANIC = "kernel_panic"
UNKNOWN_UNCLEAN = "unknown_unclean"
POWER_LOSS = "power_loss"
UNKNOWN = "unknown"

PSTORE_SKEW_S = 60.0

# Boot classification precedence, strongest evidence first. Higher entries win
# when evidence contradicts; the contradiction is recorded in detail.contradiction.
PRECEDENCE = (
    "kernel_panic: fresh pstore record",
    "watchdog_reset: watchdog bootstatus card_reset",
    "clean_shutdown: journal shutdown sequence completed",
    "watchdog_reset: journal watchdog message without a completed shutdown",
    "power_loss: an outside witness (smart plug outage or UPS on battery) overlaps the unclean end",
    "unknown_unclean: journal read and ended abruptly, even if the agent stopped",
    "agent_stopped: agent stopped and the journal could not be read",
    "unknown",
)

SEVERITY = {CLEAN_SHUTDOWN: "info", AGENT_STOPPED: "warning", WATCHDOG_RESET: "critical", KERNEL_PANIC: "critical",
            POWER_LOSS: "critical", UNKNOWN_UNCLEAN: "critical", UNKNOWN: "warning"}


def read_boot_id(procfs: Path) -> str | None:
    """Return the kernel boot_id, or None when it cannot be read."""
    try:
        value = (procfs / BOOT_ID_REL).read_text().strip()
    except OSError:
        return None
    return value or None


def pstore_evidence(pstore_dir: Path, boot_start_ts: float | None, since_ts: float | None = None,
                    already_classified: set[str] | None = None) -> dict[str, Any]:
    """Split pstore records into fresh and stale. A record is fresh only when its
    mtime is later than boot_start_ts (when the previous boot began) and it was
    not counted in an earlier boot event (already_classified holds
    "name:mtime" keys). A record from before the previous boot began cannot
    say how that boot ended, even if it is close to the last heartbeat of a short
    boot. When the start is unknown (heartbeat from an older agent), the old rule
    applies as a fallback: later than since_ts minus PSTORE_SKEW_S. An unreadable
    directory is reported as unavailable, never as no records."""
    try:
        entries = sorted(pstore_dir.iterdir())
    except OSError as exc:
        return {"unavailable": f"pstore unavailable: cannot read {pstore_dir}: {exc}",
                "fresh": [], "stale": [], "fresh_keys": []}
    done = already_classified or set()
    fresh: list[str] = []
    stale: list[str] = []
    keys: list[str] = []
    for path in entries:
        try:
            mtime = path.lstat().st_mtime
        except OSError:
            continue
        key = f"{path.name}:{mtime!r}"
        if boot_start_ts is not None:
            is_fresh = mtime > boot_start_ts
        else:
            is_fresh = since_ts is None or mtime > since_ts - PSTORE_SKEW_S
        if is_fresh and key not in done:
            fresh.append(path.name)
            keys.append(key)
        else:
            stale.append(path.name)
    return {"unavailable": None, "fresh": fresh, "stale": stale, "fresh_keys": keys}


CLASSIFIED_FILE = "pstore_classified.json"
MAX_CLASSIFIED = 500


def load_classified(data_dir: Path) -> set[str]:
    """Pstore record keys already counted in an earlier boot event."""
    try:
        raw = json.loads((data_dir / CLASSIFIED_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {k for k in raw if isinstance(k, str)} if isinstance(raw, list) else set()


def save_classified(data_dir: Path, keys: set[str]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    tmp = data_dir / (CLASSIFIED_FILE + ".tmp")
    write_private(tmp, json.dumps(sorted(keys)[-MAX_CLASSIFIED:]))
    os.replace(tmp, data_dir / CLASSIFIED_FILE)


WATCHDOG_BOOTSTATUS_REL = "class/watchdog/watchdog0/bootstatus"
WDIOF_CARDRESET = 0x20


def read_bootstatus(sysfs: Path) -> dict[str, Any]:
    """Read the watchdog boot status flags. card_reset is True when the
    WDIOF_CARDRESET bit (0x20) is set. A missing file gives unavailable with the
    reason and card_reset None, never False."""
    path = sysfs / WATCHDOG_BOOTSTATUS_REL
    try:
        value = int(path.read_text(encoding="utf-8").strip(), 0)
    except OSError as exc:
        return {"value": None, "card_reset": None, "unavailable": f"bootstatus unavailable: cannot read {path}: {exc}"}
    except ValueError:
        return {"value": None, "card_reset": None, "unavailable": f"bootstatus unavailable: {path} is not a number"}
    return {"value": value, "card_reset": bool(value & WDIOF_CARDRESET), "unavailable": None}


class Heartbeat:
    """Atomic heartbeat writer. Writes go to a temp file and are renamed over the
    real file, so a power cut leaves either the old or the new content, never a
    torn file."""

    def __init__(self, data_dir: Path, boot_id: str) -> None:
        self.path = data_dir / HEARTBEAT_FILE
        self.boot_id = boot_id
        self._lock = threading.Lock()
        self._clean = False
        # The earliest heartbeat time seen for this boot_id, kept across agent
        # restarts inside the same boot. It is the best available boot start.
        previous = load_heartbeat(data_dir)
        first = previous.get("first_ts", previous.get("ts")) if previous and previous.get("boot_id") == boot_id else None
        self.first_ts = float(first) if isinstance(first, (int, float)) else time.time()

    def _write(self, clean: bool) -> None:
        payload = {"boot_id": self.boot_id, "ts": time.time(), "first_ts": self.first_ts,
                   "agent_stopped_cleanly": clean}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        write_private(tmp, json.dumps(payload), fsync=True)
        os.replace(tmp, self.path)

    def beat(self) -> None:
        """Record that the agent is alive. Does nothing after mark_clean, so a
        late cycle cannot undo the clean flag."""
        with self._lock:
            if not self._clean:
                self._write(False)

    def mark_clean(self) -> None:
        with self._lock:
            self._clean = True
            self._write(True)


def load_heartbeat(data_dir: Path) -> dict[str, Any] | None:
    """Read the previous heartbeat. Missing, unreadable, or malformed files all
    return None so the classifier reports unknown instead of guessing."""
    try:
        raw = json.loads((data_dir / HEARTBEAT_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("boot_id"), str) \
            or not isinstance(raw.get("ts"), (int, float)):
        return None
    if "agent_stopped_cleanly" not in raw:
        # Heartbeats from the previous version used the old flag name.
        raw["agent_stopped_cleanly"] = raw.get("clean_shutdown") is True
    return raw


@dataclass(frozen=True)
class Classification:
    kind: str
    detail: dict[str, Any] = field(default_factory=dict)


def classify(previous_heartbeat: dict[str, Any] | None, current_boot_id: str,
             pstore: dict[str, Any] | bool | None,
             journal_hints: dict[str, bool] | None = None,
             now: float | None = None,
             journal_unavailable: str | None = None,
             bootstatus: dict[str, Any] | None = None) -> Classification | None:
    """Classify how the previous boot ended, or return None when boot_id is
    unchanged (the agent merely restarted).

    pstore is the result of pstore_evidence (a bare bool means fresh records
    present or absent). journal_hints keys, all optional booleans:
    "host_shutdown" (the previous boot's journal shows the systemd shutdown
    target or 'Journal stopped'), "watchdog" (a watchdog-caused reset) and
    "abrupt_end" (the journal ends with no shutdown sequence). Missing keys mean
    the evidence is not available, not that it is negative. journal_unavailable
    is the reason the previous boot's journal could not be read. bootstatus is
    the result of read_bootstatus; its card_reset bit counts as watchdog
    evidence. An abrupt end alone gives unknown_unclean, never power_loss, because
    a power cut and a hang cannot be separated without an outside witness.
    """
    hints = journal_hints or {}
    now = time.time() if now is None else now
    if isinstance(pstore, bool):
        pstore = {"unavailable": None, "fresh": ["(unnamed)"] if pstore else [], "stale": []}
    pstore = pstore or {"unavailable": "pstore unavailable: not checked", "fresh": [], "stale": []}
    if previous_heartbeat is None:
        return Classification(UNKNOWN, {"reason": "no previous heartbeat (first run or unreadable file)",
                                        "boot_id": current_boot_id})
    prev_id = previous_heartbeat.get("boot_id")
    if prev_id == current_boot_id:
        return None
    stopped = previous_heartbeat.get("agent_stopped_cleanly") is True or \
        previous_heartbeat.get("clean_shutdown") is True
    detail: dict[str, Any] = {
        "boot_id": current_boot_id, "previous_boot_id": prev_id,
        "heartbeat_ts": previous_heartbeat.get("ts"),
        "heartbeat_age_s": round(now - float(previous_heartbeat["ts"]), 1),
        "agent_stopped_cleanly": stopped,
        "pstore_fresh": list(pstore["fresh"]), "pstore_stale": list(pstore["stale"]),
        "journal_hints": dict(hints), "detected_at": now,
    }
    if pstore["unavailable"]:
        detail["pstore"] = pstore["unavailable"]
    if journal_unavailable:
        detail["journal_previous_boot"] = journal_unavailable
    if bootstatus is not None:
        detail["watchdog_bootstatus"] = {"value": bootstatus.get("value"),
                                         "card_reset": bootstatus.get("card_reset"),
                                         "unavailable": bootstatus.get("unavailable")}
    card_reset = bool(bootstatus and bootstatus.get("card_reset"))
    shutdown = hints.get("host_shutdown") is True
    journal_wd = hints.get("watchdog") is True
    abrupt = hints.get("abrupt_end") is True
    detail["evidence_seen"] = {
        "pstore_fresh": list(pstore["fresh"]), "watchdog_bootstatus_card_reset": card_reset,
        "journal_shutdown_sequence": shutdown, "journal_watchdog_message": journal_wd,
        "journal_abrupt_end": abrupt, "agent_stopped_cleanly": stopped}
    detail["precedence"] = list(PRECEDENCE)

    def result(kind: str, evidence: str, contradictions: list[str]) -> Classification:
        out = {**detail, "evidence": evidence}
        if contradictions:
            out["contradiction"] = "; ".join(contradictions)
        return Classification(kind, out)

    if pstore["fresh"]:
        notes = []
        if stopped and shutdown:
            notes.append("pstore holds a fresh panic record but the agent stopped and the journal shows a completed shutdown")
        return result(KERNEL_PANIC, "pstore holds records newer than the previous boot's start", notes)
    if card_reset:
        notes = []
        if stopped:
            notes.append("watchdog bootstatus reports a card reset but the agent stopped cleanly")
        if shutdown:
            notes.append("watchdog bootstatus reports a card reset but the journal shows a completed shutdown")
        return result(WATCHDOG_RESET, "watchdog bootstatus has the card reset bit set, which outranks journal and agent evidence", notes)
    if shutdown:
        notes = []
        if not stopped:
            notes.append("the journal shows a completed shutdown but the agent did not record a clean stop")
        if journal_wd:
            notes.append("a watchdog message appears in the journal but it is part of a completed shutdown sequence")
        why = "the previous boot's journal shows a completed shutdown sequence"
        if stopped:
            why = "agent stopped and " + why
        return result(CLEAN_SHUTDOWN, why, notes)
    if journal_wd:
        notes = ["the journal has a watchdog message but the agent stopped cleanly"] if stopped else []
        return result(WATCHDOG_RESET, "journal watchdog message with no completed shutdown sequence", notes)
    if abrupt:
        why = "previous journal ended without a shutdown sequence"
        if stopped:
            why += ", although the agent stopped cleanly (a container stop is not a host shutdown)"
        return Classification(UNKNOWN_UNCLEAN, {**detail, "evidence": why,
                                                "reason": "a power cut and a hang cannot be told apart without a witness"})
    if stopped:
        return Classification(AGENT_STOPPED, {**detail, "reason": "the agent stopped cleanly but there is no journal evidence "
                                              "of a host shutdown, so a container stop cannot be told from a reboot"})
    if journal_unavailable:
        seen = f"previous boot journal unavailable ({journal_unavailable})"
    elif hints:
        seen = "journal hints were read (" + ", ".join(f"{k}={v}" for k, v in sorted(hints.items())) + ") but none shows a shutdown, watchdog or abrupt end"
    else:
        seen = "the previous boot's journal was not checked"
    reason = f"{seen}; no fresh pstore record and no watchdog bootstatus card reset; a power cut, a hard reset, and a hang cannot be told apart"
    return Classification(UNKNOWN, {**detail, "reason": reason})


def intermediate_boots(boots: list[dict], heartbeat_boot_id: str, current_boot_id: str) -> list[dict]:
    """Boots strictly between the heartbeat's boot and the current boot in a
    chronological boot list. Empty when either end is not in the list, because
    then the order cannot be known."""
    ids = [b["boot_id"] for b in boots]
    try:
        lo = ids.index(heartbeat_boot_id.replace("-", "").lower())
        hi = ids.index(current_boot_id.replace("-", "").lower())
    except ValueError:
        return []
    return boots[lo + 1:hi] if lo < hi else []


def dashed(flat: str) -> str:
    return f"{flat[:8]}-{flat[8:12]}-{flat[12:16]}-{flat[16:20]}-{flat[20:]}"


def missed_boot_classification(rec: dict, hints: dict[str, bool] | None, unavailable: str | None,
                               previous_boot_id: str, now: float | None = None) -> Classification:
    """An unknown event for a boot the agent never observed (the container was
    down for the whole boot). Its own journal hints are recorded as evidence but
    do not change the kind, because no heartbeat describes that boot."""
    now = time.time() if now is None else now
    detail: dict[str, Any] = {
        "boot_id": dashed(rec["boot_id"]), "previous_boot_id": previous_boot_id,
        "heartbeat_ts": rec.get("last_ts"), "detected_at": now,
        "journal_hints": dict(hints or {}),
        "reason": "the agent did not run during this boot, so how it ended was not observed"}
    if rec.get("first_ts") is not None:
        detail["boot_first_entry_ts"] = rec["first_ts"]
    if unavailable:
        detail["journal_previous_boot"] = unavailable
    return Classification(UNKNOWN, detail)


def boot_event(c: Classification, now: float | None = None) -> Event:
    """Build the event. dedup_key carries boot_id so Observe keeps one row
    per boot even if the agent resends. The event time is the previous heartbeat
    (last known alive); the time of detection is in detail.detected_at. With no
    previous heartbeat, the current time is used."""
    boot_id = c.detail.get("boot_id", "unknown")
    hb_ts = c.detail.get("heartbeat_ts")
    ts = float(hb_ts) if isinstance(hb_ts, (int, float)) else (time.time() if now is None else now)
    return Event(kind=f"boot.{c.kind}", severity=SEVERITY[c.kind], source="boot", ts=ts,
                 title=f"Previous boot ended: {c.kind.replace('_', ' ')}",
                 detail=c.detail, dedup_key=f"boot:{boot_id}",
                 boot_id=boot_id if boot_id != "unknown" else None)
