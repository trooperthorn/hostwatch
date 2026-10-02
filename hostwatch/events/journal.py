"""Read-only journal watcher.

The journal is read through journalctl with --directory pointing at the
journal mounted read-only into the container, so the container never writes to
it. When the persistent directory holds no journal files, the volatile
directory (HOSTWATCH_JOURNAL_VOLATILE) is read instead. Output is requested as JSON, one object per line. The last cursor seen is
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
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from ..outbox import Markers
from ..schema import Event, SourceStatus

SOURCE = "journal"
CURSOR_FILE = "journal.cursor"
CURSOR_MARKER = "journal.cursor"
JOURNALCTL_TIMEOUT_S = 30
FIRST_READ_MAX_LINES = 5000
WORKER_TIMEOUT_S = 60
# Messages journalctl prints on stderr that do not mean a failure.
BENIGN_STDERR = ("-- no entries --", "-- journal begins")

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
         r"\bmd\d+:.*(degraded|Disk failure)|raid\d+ array.*degraded|"
         r"\b(md\d+|md/raid\d*)\b.*\[U*_[U_]*\]",
         "md.degraded", "critical", "RAID array is degraded"),
        (r"e1000e.*hardware error|e1000e.*Detected Hardware Unit Hang", "net.e1000e_hardware_error",
         "warning", "e1000e hardware error"),
        (r"\bmce:|machine check|Hardware Error.*(MCE|Machine Check)", "hardware.mce", "critical",
         "Machine check exception"),
        (r"I/O error, dev |blk_update_request: I/O error|Buffer I/O error", "disk.io_error", "critical",
         "Disk I/O error"),
        (r"ata\d+(\.\d+)?:.*(hard resetting link|link is slow|COMRESET|failed to resume link)|"
         r"ata\d+(\.\d+)?:.*(exception Emask|SError)", "disk.ata_link_reset", "warning",
         "ATA link reset or exception"),
        (r"(cpu|core)\d*.*(clock throttled|temperature above threshold)|thermal.*throttl|"
         r"package temperature above threshold", "thermal.throttle", "warning", "Thermal throttling"),
    )
)


def _run_journalctl(exe: str, directory: Path, extra: list[str]) -> list[str]:
    cmd = [exe, f"--directory={directory}", "-o", "json", "--no-pager", *extra]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=JOURNALCTL_TIMEOUT_S, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReaderError(f"journalctl could not run: {exc}") from exc
    stderr = proc.stderr.strip()
    if proc.returncode != 0:
        raise ReaderError(f"journalctl exited {proc.returncode}: {stderr[:200]}")
    lines = proc.stdout.splitlines()
    if not lines and stderr and not stderr.lower().startswith(BENIGN_STDERR):
        # Exit 0 with no output and an error message means the journal was not
        # readable (for example a permission problem), not that it is quiet.
        raise ReaderError(f"journalctl produced no output: {stderr[:200]}")
    return lines


def default_reader(directory: Path, cursor: str | None) -> Iterable[str]:
    """Run journalctl read-only against the journal directory.

    With a cursor, only entries after it are read. Without one, the read is
    bounded to the current and the previous boot with a line cap each, so the
    first read cannot walk a multi-gigabyte journal."""
    exe = shutil.which("journalctl")
    if exe is None:
        raise ReaderError("journalctl is not installed")
    if cursor:
        return _run_journalctl(exe, directory, ["--after-cursor", cursor])
    cap = ["-n", str(FIRST_READ_MAX_LINES)]
    current = _run_journalctl(exe, directory, ["--boot=0", *cap])
    try:
        previous = _run_journalctl(exe, directory, ["--boot=-1", *cap])
    except ReaderError:
        previous = []  # a journal with a single boot has no previous boot
    return [*previous, *current]


PREVIOUS_BOOT_LINES = 200
# Messages systemd and journald log on an orderly stop. Assumed, not yet confirmed
# on hardware; see UNVERIFIED.md.
SHUTDOWN_PATTERN = re.compile(
    r"Reached target.*(Shutdown|Power-Off|Reboot|Final Step)|Journal stopped|"
    r"systemd-shutdown\[1\]|Shutting down\.", re.IGNORECASE)


def default_previous_boot_reader(directory: Path) -> Iterable[str]:
    """Run journalctl read-only for the last 200 entries of the previous boot."""
    exe = shutil.which("journalctl")
    if exe is None:
        raise ReaderError("journalctl is not installed")
    return _run_journalctl(exe, directory, ["-b", "-1", "-n", str(PREVIOUS_BOOT_LINES)])


def previous_boot_hints(lines: Iterable[str]) -> dict[str, bool]:
    """Derive boot classifier hints from the previous boot's last journal lines.
    host_shutdown: a shutdown message is present. watchdog: a watchdog message is
    present. abrupt_end: entries exist but none shows a shutdown. Raises
    ReaderError when there are no readable entries, because then nothing can be
    said either way."""
    seen = shutdown = watchdog = 0
    for line in lines:
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(entry, dict):
            continue
        message = _message_text(entry.get("MESSAGE"))
        if message is None:
            continue
        seen += 1
        if SHUTDOWN_PATTERN.search(message):
            shutdown += 1
        hit = classify(message)
        if hit is not None and hit[0] == "watchdog.event":
            watchdog += 1
    if not seen:
        raise ReaderError("the previous boot's journal has no readable entries")
    return {"host_shutdown": shutdown > 0, "watchdog": watchdog > 0, "abrupt_end": shutdown == 0}


def has_journal_files(directory: Path) -> bool:
    """True when at least one journal file under the directory can be opened."""
    try:
        for path in directory.rglob("*"):
            if path.suffix in {".journal", ".journal~"} and path.is_file():
                try:
                    with path.open("rb") as fh:
                        fh.read(1)
                except OSError:
                    continue
                return True
    except OSError:
        return False
    return False


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
                 markers: Markers | None = None, volatile: Path | None = None,
                 has_files: Callable[[Path], bool] = has_journal_files,
                 previous_boot_reader: Callable[[Path], Iterable[str]] | None = None) -> None:
        """With markers (the agent outbox), the cursor is staged and becomes
        durable together with the batch that carries the events read. Without
        markers the cursor is saved to a file at once, for standalone use."""
        self.directory = directory
        self.cursor_path = data_dir / CURSOR_FILE
        self.reader = reader or default_reader
        self.markers = markers
        self.volatile = volatile
        self.has_files = has_files
        self._reset_ports: set[str] = set()
        self.previous_boot_reader = previous_boot_reader or default_previous_boot_reader

    def previous_boot(self) -> dict[str, bool]:
        """Hints from the previous boot's last entries, read through the same
        directory choice as the live read. Raises ReaderError with the reason
        when the previous boot's journal cannot be read."""
        return previous_boot_hints(self.previous_boot_reader(self.choose_directory()))

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

    def choose_directory(self) -> Path:
        """The persistent directory when it holds journal files, else the
        volatile one. Raises ReaderError, with the reason, when neither does."""
        if self.directory.is_dir() and self.has_files(self.directory):
            return self.directory
        if self.volatile is not None and self.volatile.is_dir() and self.has_files(self.volatile):
            return self.volatile
        if not self.directory.is_dir():
            raise ReaderError(f"{self.directory} does not exist or is not a directory")
        raise ReaderError(f"no readable journal files in {self.directory}"
                          + (f" or {self.volatile}" if self.volatile else ""))

    def fetch(self, cursor: str | None) -> list[str]:
        """The blocking part of a read: pick a directory and run the reader."""
        return list(self.reader(self.choose_directory(), cursor))

    def read(self) -> tuple[SourceStatus, list[Event]]:
        cursor = self.load_cursor()
        try:
            lines = self.fetch(cursor)
        except ReaderError as exc:
            return SourceStatus(source=SOURCE, available=False, reason=str(exc)), []
        return self.process(cursor, lines)

    def process(self, cursor: str | None, lines: list[str]) -> tuple[SourceStatus, list[Event]]:
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
            hit = self._classify_entry(message) if message else None
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

    def _classify_entry(self, message: str) -> tuple[str, str, str] | None:
        """Like classify, but 'SATA link up' counts only after a reset on the
        same port, because it is also logged on every normal boot."""
        port = re.match(r"\s*(ata\d+)", message, re.IGNORECASE)
        key = port.group(1).lower() if port else None
        hit = classify(message)
        if hit is not None and hit[0] == "disk.ata_link_reset" and key:
            self._reset_ports.add(key)
            return hit
        if key and "sata link up" in message.lower() and key in self._reset_ports:
            self._reset_ports.discard(key)
            return ("disk.ata_link_reset", "warning", "ATA link reset or exception")
        return hit

    @staticmethod
    def _timestamp(entry: dict) -> float:
        raw = entry.get("__REALTIME_TIMESTAMP")
        try:
            return int(raw) / 1_000_000
        except (TypeError, ValueError):
            return time.time()


class BackgroundJournal:
    """Runs the blocking journal read on a worker thread so a slow journal never
    delays the sampling loop. Each call to read() returns at once: it collects
    the result of a finished worker (parsing and cursor staging happen here, on
    the calling thread, so the cursor stays tied to the events it produced) and
    starts a new worker when none is running."""

    def __init__(self, watcher: JournalWatcher, timeout_s: float = WORKER_TIMEOUT_S) -> None:
        self.watcher = watcher
        self.timeout_s = timeout_s
        self._thread: threading.Thread | None = None
        self._result: dict = {}
        self._cursor: str | None = None
        self._started = 0.0
        self._last = SourceStatus(source=SOURCE, available=False, reason="first journal read in progress")

    def _work(self, cursor: str | None, result: dict) -> None:
        try:
            result["lines"] = self.watcher.fetch(cursor)
        except ReaderError as exc:
            result["error"] = str(exc)
        except Exception as exc:  # the thread must always finish with a result
            result["error"] = f"{type(exc).__name__}: {exc}"

    def read(self) -> tuple[SourceStatus, list[Event]]:
        events: list[Event] = []
        thread = self._thread
        if thread is not None:
            if thread.is_alive():
                if time.monotonic() - self._started > self.timeout_s:
                    return SourceStatus(source=SOURCE, available=False,
                                        reason=f"journal read exceeded {self.timeout_s:g}s"), []
                return self._last, []
            self._thread = None
            result = self._result
            if "lines" in result:
                self._last, events = self.watcher.process(self._cursor, result["lines"])
            else:
                self._last = SourceStatus(source=SOURCE, available=False,
                                          reason=result.get("error", "journal read failed"))
        self._cursor = self.watcher.load_cursor()
        self._result = {}
        self._started = time.monotonic()
        self._thread = threading.Thread(target=self._work, args=(self._cursor, self._result),
                                        name="journal-reader", daemon=True)
        self._thread.start()
        return self._last, events
