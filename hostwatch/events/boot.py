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

from ..schema import Event

log = logging.getLogger("hostwatch.boot")

HEARTBEAT_FILE = "heartbeat.json"
BOOT_ID_REL = "sys/kernel/random/boot_id"

CLEAN_SHUTDOWN = "clean_shutdown"
AGENT_STOPPED = "agent_stopped"
WATCHDOG_RESET = "watchdog_reset"
KERNEL_PANIC = "kernel_panic"
POWER_LOSS = "power_loss"
UNKNOWN = "unknown"

PSTORE_SKEW_S = 60.0

SEVERITY = {CLEAN_SHUTDOWN: "info", AGENT_STOPPED: "warning", WATCHDOG_RESET: "critical", KERNEL_PANIC: "critical",
            POWER_LOSS: "critical", UNKNOWN: "warning"}


def read_boot_id(procfs: Path) -> str | None:
    """Return the kernel boot_id, or None when it cannot be read."""
    try:
        value = (procfs / BOOT_ID_REL).read_text().strip()
    except OSError:
        return None
    return value or None


def pstore_evidence(pstore_dir: Path, since_ts: float | None) -> dict[str, Any]:
    """Split pstore records into fresh and stale. A record is fresh only when its
    mtime is later than since_ts (the previous heartbeat) minus PSTORE_SKEW_S;
    older records predate the previous boot's last sign of life and cannot be
    evidence of how it ended. An unreadable directory is reported as
    unavailable, never as no records."""
    try:
        entries = sorted(pstore_dir.iterdir())
    except OSError as exc:
        return {"unavailable": f"pstore unavailable: cannot read {pstore_dir}: {exc}",
                "fresh": [], "stale": []}
    fresh: list[str] = []
    stale: list[str] = []
    for path in entries:
        try:
            mtime = path.lstat().st_mtime
        except OSError:
            continue
        if since_ts is None or mtime > since_ts - PSTORE_SKEW_S:
            fresh.append(path.name)
        else:
            stale.append(path.name)
    return {"unavailable": None, "fresh": fresh, "stale": stale}


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
        payload = {"boot_id": self.boot_id, "ts": time.time(), "agent_stopped_cleanly": clean}
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
             now: float | None = None) -> Classification | None:
    """Classify how the previous boot ended, or return None when boot_id is
    unchanged (the agent merely restarted).

    pstore is the result of pstore_evidence (a bare bool means fresh records
    present or absent). journal_hints keys, all optional booleans:
    "host_shutdown" (the previous boot's journal shows the systemd shutdown
    target or 'Journal stopped'), "watchdog" (a watchdog-caused reset) and
    "abrupt_end" (the journal ends with no shutdown sequence). Missing keys mean
    the evidence is not available, not that it is negative.
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
    if stopped and hints.get("host_shutdown"):
        return Classification(CLEAN_SHUTDOWN, {**detail, "evidence": "agent stopped and the previous boot's journal shows a host shutdown"})
    if pstore["fresh"]:
        return Classification(KERNEL_PANIC, {**detail, "evidence": "pstore holds records newer than the previous heartbeat"})
    if stopped:
        return Classification(AGENT_STOPPED, {**detail, "reason": "the agent stopped cleanly but there is no journal evidence "
                                              "of a host shutdown, so a container stop cannot be told from a reboot"})
    if hints.get("watchdog"):
        return Classification(WATCHDOG_RESET, {**detail, "evidence": "watchdog hint and the agent did not stop cleanly"})
    if hints.get("abrupt_end"):
        return Classification(POWER_LOSS, {**detail, "evidence": "previous journal ended without a shutdown sequence"})
    return Classification(UNKNOWN, {**detail, "reason": "no fresh pstore or journal evidence; "
                                    "a power cut, a hard reset, and a hang cannot be told apart"})


def boot_event(c: Classification, now: float | None = None) -> Event:
    """Build the wire event. dedup_key carries boot_id so the hub keeps one row
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
