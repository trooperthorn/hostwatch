"""Read-only journal watcher.

The journal is read through journalctl with --directory pointing at the
journal mounted read-only into the container, so the container never writes to
it. Output is requested as JSON, one object per line. The last cursor seen is
saved in the data directory, and the next read passes it as --after-cursor, so
a restart does not repeat entries.

The reader is pluggable: a reader is any callable taking the journal directory
and the saved cursor (or None) and returning an iterable of JSON lines. Tests
pass a fake reader. A missing journalctl binary or a missing directory makes
the source unavailable with a reason. The message formats in PATTERNS are
assumptions that are not yet confirmed on hardware; see UNVERIFIED.md.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from ..outbox import Markers
from ..schema import Event, SourceStatus

SOURCE = "journal"
CURSOR_FILE = "journal.cursor"
CURSOR_MARKER = "journal.cursor"
JOURNALCTL_TIMEOUT_S = 30

Reader = Callable[[Path, str | None], Iterable[str]]


class ReaderError(Exception):
    """The reader could not produce output; the message becomes the reason."""


# (compiled pattern, event kind, severity, short title). The first match wins,
# so more specific patterns come first.
PATTERNS: tuple[tuple[re.Pattern[str], str, str, str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), kind, sev, title) for p, kind, sev, title in (
        (r"watchdog.*(did not stop|timeout|timed out|hardware watchdog|reset|bark)|"
         r"\bwatchdog\b.*\b(expired|triggered)\b", "watchdog.event", "warning", "Watchdog message in the journal"),
        (r"md/raid\d*:.*(degraded|not enough operational|disk failure|Disk failure)|"
         r"\bmd\d+:.*(degraded|Disk failure)|raid\d+ array.*degraded|\[U?_U?\]|\[_U\]|\[U_\]",
         "md.degraded", "critical", "RAID array is degraded"),
        (r"e1000e.*hardware error|e1000e.*Detected Hardware Unit Hang", "net.e1000e_hardware_error",
         "warning", "e1000e hardware error"),
        (r"\bmce:|machine check|Hardware Error.*(MCE|Machine Check)", "hardware.mce", "critical",
         "Machine check exception"),
        (r"I/O error, dev |blk_update_request: I/O error|Buffer I/O error", "disk.io_error", "critical",
         "Disk I/O error"),
        (r"ata\d+(\.\d+)?:.*(hard resetting link|link is slow|SATA link up|COMRESET|failed to resume link)|"
         r"ata\d+(\.\d+)?:.*(exception Emask|SError)", "disk.ata_link_reset", "warning",
         "ATA link reset or exception"),
        (r"(cpu|core)\d*.*(clock throttled|temperature above threshold)|thermal.*throttl|"
         r"package temperature above threshold", "thermal.throttle", "warning", "Thermal throttling"),
    )
)


def default_reader(directory: Path, cursor: str | None) -> Iterable[str]:
    """Run journalctl read-only against the journal directory."""
    exe = shutil.which("journalctl")
    if exe is None:
        raise ReaderError("journalctl is not installed")
    cmd = [exe, f"--directory={directory}", "-o", "json", "--no-pager"]
    if cursor:
        cmd += ["--after-cursor", cursor]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=JOURNALCTL_TIMEOUT_S, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReaderError(f"journalctl could not run: {exc}") from exc
    if proc.returncode != 0:
        raise ReaderError(f"journalctl exited {proc.returncode}: {proc.stderr.strip()[:200]}")
    return proc.stdout.splitlines()


def _message_text(value: object) -> str | None:
    """journalctl renders a binary MESSAGE as a list of byte values."""
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(b, int) and 0 <= b < 256 for b in value):
        return bytes(value).decode("utf-8", errors="replace")
    return None


def classify(message: str) -> tuple[str, str, str] | None:
    for pattern, kind, severity, title in PATTERNS:
        if pattern.search(message):
            return kind, severity, title
    return None


class JournalWatcher:
    def __init__(self, directory: Path, data_dir: Path, reader: Reader | None = None,
                 markers: Markers | None = None) -> None:
        """With markers (the agent outbox), the cursor is staged and becomes
        durable together with the batch that carries the events read. Without
        markers the cursor is saved to a file at once, for standalone use."""
        self.directory = directory
        self.cursor_path = data_dir / CURSOR_FILE
        self.reader = reader or default_reader
        self.markers = markers

    def load_cursor(self) -> str | None:
        if self.markers is not None:
            saved = self.markers.get(CURSOR_MARKER)
            return saved if saved else self._load_cursor_file()
        return self._load_cursor_file()

    def _load_cursor_file(self) -> str | None:
        """Also the one-time import of the cursor file an older agent wrote."""
        try:
            text = self.cursor_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return text or None

    def _save_cursor(self, cursor: str) -> None:
        if self.markers is not None:
            self.markers.stage(CURSOR_MARKER, cursor)
            return
        self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cursor_path.with_suffix(".tmp")
        tmp.write_text(cursor, encoding="utf-8")
        tmp.replace(self.cursor_path)

    def read(self) -> tuple[SourceStatus, list[Event]]:
        if not self.directory.is_dir():
            return SourceStatus(source=SOURCE, available=False,
                                reason=f"{self.directory} does not exist or is not a directory"), []
        cursor = self.load_cursor()
        try:
            lines = list(self.reader(self.directory, cursor))
        except ReaderError as exc:
            return SourceStatus(source=SOURCE, available=False, reason=str(exc)), []
        events: list[Event] = []
        skipped = 0
        last_cursor = cursor
        for line in lines:
            try:
                entry = json.loads(line)
            except (ValueError, TypeError):
                skipped += 1
                continue
            if not isinstance(entry, dict):
                skipped += 1
                continue
            entry_cursor = entry.get("__CURSOR")
            if isinstance(entry_cursor, str) and entry_cursor:
                last_cursor = entry_cursor
            message = _message_text(entry.get("MESSAGE"))
            hit = classify(message) if message else None
            if hit is None or not isinstance(entry_cursor, str) or not entry_cursor:
                continue
            kind, severity, title = hit
            events.append(Event(
                kind=kind, severity=severity, source=SOURCE, ts=self._timestamp(entry),
                title=f"{title}: {message[:200]}",
                detail={"message": message, "cursor": entry_cursor,
                        "unit": entry.get("_SYSTEMD_UNIT"), "priority": entry.get("PRIORITY")},
                dedup_key=f"journal:{entry_cursor}"))
        if last_cursor and last_cursor != cursor:
            try:
                self._save_cursor(last_cursor)
            except OSError as exc:
                return SourceStatus(source=SOURCE, available=True,
                                    reason=f"cursor could not be saved: {exc}"), events
        reason = f"{skipped} unreadable lines skipped" if skipped else ""
        return SourceStatus(source=SOURCE, available=True, reason=reason), events

    @staticmethod
    def _timestamp(entry: dict) -> float:
        raw = entry.get("__REALTIME_TIMESTAMP")
        try:
            return int(raw) / 1_000_000
        except (TypeError, ValueError):
            return time.time()
