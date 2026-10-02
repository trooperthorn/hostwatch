"""Heartbeat-based boot classifier.

The agent rewrites a small heartbeat file in the data directory on every cycle.
The file holds the current boot_id, a timestamp, and a clean_shutdown flag that
is false while running and set true only when the agent is told to stop (SIGTERM
during an orderly shutdown). At the next start, a different boot_id means the
host rebooted, and the previous heartbeat plus any pstore and journal evidence
say how the previous boot ended.

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

from ..schema import Event

log = logging.getLogger("hostwatch.boot")

HEARTBEAT_FILE = "heartbeat.json"
BOOT_ID_REL = "sys/kernel/random/boot_id"

CLEAN_SHUTDOWN = "clean_shutdown"
WATCHDOG_RESET = "watchdog_reset"
KERNEL_PANIC = "kernel_panic"
POWER_LOSS = "power_loss"
UNKNOWN = "unknown"

SEVERITY = {CLEAN_SHUTDOWN: "info", WATCHDOG_RESET: "critical", KERNEL_PANIC: "critical",
            POWER_LOSS: "critical", UNKNOWN: "warning"}


def read_boot_id(procfs: Path) -> str | None:
    """Return the kernel boot_id, or None when it cannot be read."""
    try:
        value = (procfs / BOOT_ID_REL).read_text().strip()
    except OSError:
        return None
    return value or None


def pstore_has_records(pstore_dir: Path) -> bool:
    """True when the pstore directory exists and holds at least one record."""
    try:
        return any(pstore_dir.iterdir())
    except OSError:
        return False


class Heartbeat:
    """Atomic heartbeat writer. Writes go to a temp file and are renamed over the
    real file, so a power cut leaves either the old or the new content, never a
    torn file."""

    def __init__(self, data_dir: Path, boot_id: str) -> None:
        self.path = data_dir / HEARTBEAT_FILE
        self.boot_id = boot_id
        self._lock = threading.Lock()
        self._clean = False

    def _write(self, clean: bool) -> None:
        payload = {"boot_id": self.boot_id, "ts": time.time(), "clean_shutdown": clean}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
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
    return raw


@dataclass(frozen=True)
class Classification:
    kind: str
    detail: dict[str, Any] = field(default_factory=dict)


def classify(previous_heartbeat: dict[str, Any] | None, current_boot_id: str,
             pstore_present: bool, journal_hints: dict[str, bool] | None = None,
             now: float | None = None) -> Classification | None:
    """Classify how the previous boot ended, or return None when boot_id is
    unchanged (the agent merely restarted).

    journal_hints keys, all optional booleans: "watchdog" (the previous boot's
    journal or the kernel log shows a watchdog-caused reset) and "abrupt_end"
    (the previous boot's journal ends with no shutdown sequence). Missing keys
    mean the evidence is not available, not that it is negative.
    """
    hints = journal_hints or {}
    now = time.time() if now is None else now
    if previous_heartbeat is None:
        return Classification(UNKNOWN, {"reason": "no previous heartbeat (first run or unreadable file)",
                                        "boot_id": current_boot_id})
    prev_id = previous_heartbeat.get("boot_id")
    if prev_id == current_boot_id:
        return None
    detail: dict[str, Any] = {
        "boot_id": current_boot_id, "previous_boot_id": prev_id,
        "heartbeat_ts": previous_heartbeat.get("ts"),
        "heartbeat_age_s": round(now - float(previous_heartbeat["ts"]), 1),
        "clean_shutdown_flag": previous_heartbeat.get("clean_shutdown") is True,
        "pstore_present": pstore_present, "journal_hints": dict(hints),
    }
    if previous_heartbeat.get("clean_shutdown") is True:
        return Classification(CLEAN_SHUTDOWN, {**detail, "evidence": "clean flag set by agent at stop"})
    if pstore_present:
        return Classification(KERNEL_PANIC, {**detail, "evidence": "pstore holds records and the flag was not set"})
    if hints.get("watchdog"):
        return Classification(WATCHDOG_RESET, {**detail, "evidence": "watchdog hint and the flag was not set"})
    if hints.get("abrupt_end"):
        return Classification(POWER_LOSS, {**detail, "evidence": "previous journal ended without a shutdown sequence"})
    return Classification(UNKNOWN, {**detail, "reason": "flag not set and no pstore or journal evidence; "
                                    "a power cut, a hard reset, and a hang cannot be told apart"})


def boot_event(c: Classification, now: float | None = None) -> Event:
    """Build the wire event. dedup_key carries boot_id so the hub keeps one row
    per boot even if the agent resends."""
    boot_id = c.detail.get("boot_id", "unknown")
    return Event(kind=f"boot.{c.kind}", severity=SEVERITY[c.kind], source="boot",
                 ts=time.time() if now is None else now,
                 title=f"Previous boot ended: {c.kind.replace('_', ' ')}",
                 detail=c.detail, dedup_key=f"boot:{boot_id}")
