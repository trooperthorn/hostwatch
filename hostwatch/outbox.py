"""Durable agent outbox.

The outbox holds OTLP requests, already encoded, until Observe answers 2xx, so an agent restart or
an Observe outage delays delivery but does not lose events. A request is stored with its headers,
including the Idempotency-Key, and its exact body. A replay after a restart therefore sends the
same bytes under the same key, which Observe recognises as a repeat and stores once.

Progress markers (journal cursor, rasdaemon high-water ids, pstore sent keys, the pending boot
events, the threshold state) live in the same file. A source stages a marker while it reads, and
`enqueue` writes the requests and every staged marker in one transaction. A crash therefore leaves
either both or neither: a marker never runs ahead of the events that were queued for it.

The queue is bounded in count, in bytes and in age, and each limit is enforced when a request is
added and again before each delivery pass. Metrics are the cheaper loss, because the next poll
brings a fresh reading, so they go first: a metrics request older than MAX_METRICS_AGE_S is
dropped, and when the queue is over a limit the oldest metrics request is dropped before any log
request. Log requests carry events, and an event is the thing the owner most wants to keep, so
they are kept for MAX_LOGS_AGE_S and are dropped only when no metrics request is left to drop.
Every drop is counted and reported through the agent's outbox source status.

Delivery sends log requests before metrics requests, each oldest first, so that after an outage the
events leave before the backlog of readings.

An item that cannot be encoded is left out of its request by the encoder and counted here, so one
bad value never blocks the queue.

A request that Observe refuses with a status that can never succeed (see agent.DEAD_LETTER_STATUSES)
moves to the dead_letters table with the status and no longer blocks the queue head. No other
answer moves a request: a 5xx, a 429, a 401 or a 403 describes the receiver, the key or the
network, so the request waits for them to be put right.

A row whose headers cannot be decoded can never be sent. It moves to dead_letters with status 0
and the decode error, and the queue moves on.

A file that SQLite reports as not a database or as malformed is renamed to
outbox.db.corrupt-<timestamp> together with any -wal, -shm or -journal sidecar, an error is
logged, and a fresh outbox starts. Damage in the middle of the file does not always show up as an
error on the first query, so the open also runs PRAGMA quick_check, and any later call that fails
with a corruption error recovers the same way and is run once more against the fresh file. Each
recovery is recorded as an incident that the agent turns into an observe.source.change log, so the
loss is reported to Observe and not only logged. Other errors, such as a locked database or an I/O error, say
nothing about the file contents, so they are raised and the file is left alone. `recovered_from`
names the renamed file so the agent can report the loss.

The dead_letters table is bounded in rows (MAX_DEAD_LETTERS) and in bytes (MAX_DEAD_LETTER_BYTES),
oldest first, so a run of large refused requests cannot fill the disk. The outbox file is created
with mode 0600 on POSIX.
"""

from __future__ import annotations

import functools
import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .otlp import OtlpRequest
from .privfile import ensure_private

log = logging.getLogger("hostwatch.outbox")

OUTBOX_FILE = "outbox.db"
MAX_DEAD_LETTERS = 1000
MAX_DEAD_LETTER_BYTES = 16 * 1024 * 1024
MAX_REQUESTS = 2000
MAX_BYTES = 32 * 1024 * 1024
MAX_METRICS_AGE_S = 6 * 3600.0
MAX_LOGS_AGE_S = 7 * 86400.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, entry_id TEXT NOT NULL, signal TEXT NOT NULL,
  path TEXT NOT NULL, headers TEXT NOT NULL, body BLOB NOT NULL, count INTEGER NOT NULL,
  created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS markers (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dead_letters (
  id INTEGER PRIMARY KEY AUTOINCREMENT, entry_id TEXT NOT NULL, signal TEXT NOT NULL,
  status INTEGER NOT NULL, ts REAL NOT NULL, headers TEXT NOT NULL, body BLOB NOT NULL, error TEXT);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
DROP TABLE IF EXISTS batches;
"""

CORRUPT_MARKERS = ("file is not a database", "malformed", "file is encrypted")
SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


def _is_corruption(exc: sqlite3.DatabaseError) -> bool:
    """True only for errors that mean the file content is unusable. Locked or
    I/O errors are transient and must not cause the file to be replaced."""
    return any(m in str(exc).lower() for m in CORRUPT_MARKERS)


def _recovering(method):
    """Run an Outbox method; if SQLite reports corruption, move the file aside, start a fresh one
    and run the method once more. Any other error is raised unchanged."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except sqlite3.DatabaseError as exc:
            if not _is_corruption(exc):
                raise
            self._recover(exc)
            return method(self, *args, **kwargs)
    return wrapper


class Markers(Protocol):
    """What an event source needs: read a marker, stage a new value (None
    clears it). Staged values are visible to `get` at once and become durable
    when the request that carries them is enqueued."""

    def get(self, key: str) -> str | None: ...
    def stage(self, key: str, value: str | None) -> None: ...


class MemoryMarkers:
    """Non-durable markers, for sources used without an outbox."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def stage(self, key: str, value: str | None) -> None:
        if value is None:
            self.values.pop(key, None)
        else:
            self.values[key] = value


@dataclass(frozen=True)
class QueuedRequest:
    seq: int
    entry_id: str
    signal: str
    path: str
    headers: dict[str, str]
    body: bytes
    count: int
    created: float


class Outbox:
    def __init__(self, path: Path, max_requests: int = MAX_REQUESTS, max_bytes: int = MAX_BYTES,
                 max_metrics_age_s: float = MAX_METRICS_AGE_S, max_logs_age_s: float = MAX_LOGS_AGE_S,
                 clock=time.time) -> None:
        if max_requests < 2:
            raise ValueError("max_requests must be at least 2")
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.max_metrics_age_s = max_metrics_age_s
        self.max_logs_age_s = max_logs_age_s
        self._clock = clock
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._path = path
        self.recovered_from: Path | None = None
        self._incidents: list[str] = []
        self._staged: dict[str, str | None] = {}
        self._warned_drop = 0
        try:
            self._db = self._open(path)
        except sqlite3.DatabaseError as exc:
            if not _is_corruption(exc):
                log.error("outbox %s could not be opened (%s); this is not corruption, so the file "
                          "was left in place", path, exc)
                raise
            self._quarantine(exc)
            self._db = self._open(path)

    def _quarantine(self, exc: Exception) -> None:
        path = self._path
        stamp = time.strftime("%Y%m%dT%H%M%S")
        moved = path.with_name(f"{path.name}.corrupt-{stamp}")
        n = 0
        while moved.exists():
            n += 1
            moved = path.with_name(f"{path.name}.corrupt-{stamp}-{n}")
        # Sidecars first: if one cannot be moved the error is raised with the main
        # file still in place, so the next start sees the same corruption and retries.
        for suffix in SIDECAR_SUFFIXES:
            side = path.with_name(path.name + suffix)
            if side.exists():
                side.rename(moved.with_name(moved.name + suffix))
        path.rename(moved)
        log.error("outbox %s could not be opened (%s); moved to %s and a fresh outbox was started. "
                  "Queued requests and source progress markers in it are lost", path, exc, moved)
        self.recovered_from = moved
        self._incidents.append(f"the outbox file was corrupt ({exc}) and was moved to {moved.name}; "
                               "queued requests and progress markers in it were lost")

    def _recover(self, exc: Exception) -> None:
        """Replace a file found corrupt while in use. Staged markers are kept: they describe
        what the sources have read, not what the lost file held."""
        with self._lock:
            try:
                self._db.close()
            except sqlite3.Error:
                pass
            self._quarantine(exc)
            self._db = self._open(self._path)
            self._warned_drop = 0

    def take_incidents(self) -> list[str]:
        """Texts describing recoveries since the last call, for the agent to report to Observe."""
        with self._lock:
            out, self._incidents = self._incidents, []
            return out

    @staticmethod
    def _open(path: Path) -> sqlite3.Connection:
        try:
            ensure_private(path)
        except OSError as exc:
            log.warning("cannot set mode 0600 on %s: %s", path, exc)
        db = sqlite3.connect(path, check_same_thread=False)
        try:
            db.execute("PRAGMA synchronous=FULL")
            try:
                legacy = db.execute("SELECT COUNT(*) FROM batches").fetchone()[0]
            except sqlite3.DatabaseError:
                legacy = 0  # no legacy table (or an unreadable file, which the checks below report)
            if legacy:
                log.warning("dropping %d unsent batches queued by an older version; "
                            "the old batch format is no longer sent", legacy)
            with db:
                db.executescript(_SCHEMA)
            db.execute("SELECT COUNT(*) FROM requests").fetchone()
            # A damaged page in the middle of the file can pass the checks above. quick_check
            # reads every page, so it finds that damage now and not in the middle of a send.
            problems = [r[0] for r in db.execute("PRAGMA quick_check").fetchall() if r[0] != "ok"]
            if problems:
                raise sqlite3.DatabaseError(f"database disk image is malformed: {problems[0]}")
        except sqlite3.DatabaseError:
            db.close()
            raise
        return db

    def discard_staged(self) -> None:
        """Forget staged markers, used when a cycle failed before its requests were written so no
        marker runs ahead of events that were never queued."""
        with self._lock:
            self._staged.clear()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # markers
    @_recovering
    def get(self, key: str) -> str | None:
        with self._lock:
            if key in self._staged:
                return self._staged[key]
            row = self._db.execute("SELECT value FROM markers WHERE key=?", (key,)).fetchone()
            return row[0] if row else None

    def stage(self, key: str, value: str | None) -> None:
        with self._lock:
            self._staged[key] = value

    def _write_staged(self) -> None:
        for key, value in self._staged.items():
            if value is None:
                self._db.execute("DELETE FROM markers WHERE key=?", (key,))
            else:
                self._db.execute("INSERT OR REPLACE INTO markers (key, value) VALUES (?, ?)", (key, value))

    @_recovering
    def commit_staged(self) -> None:
        """Make staged markers durable without a request. Used for the boot event, which must
        survive a restart before the first request is built."""
        with self._lock:
            with self._db:
                self._write_staged()
            self._staged.clear()

    # counters
    def _bump(self, name: str, by: int) -> None:
        self._db.execute("INSERT INTO counters (name, value) VALUES (?, ?) "
                         "ON CONFLICT(name) DO UPDATE SET value = value + excluded.value", (name, by))

    def _counter(self, name: str) -> int:
        row = self._db.execute("SELECT value FROM counters WHERE name=?", (name,)).fetchone()
        return row[0] if row else 0

    # queue
    @_recovering
    def enqueue(self, requests: list[OtlpRequest], entry_id: str) -> None:
        """Write the requests of one entry and all staged markers in one transaction. An entry with
        no requests still commits the staged markers."""
        with self._lock:
            if not requests and not self._staged:
                return  # nothing to write, so no transaction and no fsync
            now = self._clock()
            with self._db:
                for r in requests:
                    self._db.execute(
                        "INSERT INTO requests (entry_id, signal, path, headers, body, count, created) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (entry_id, r.signal, r.path, json.dumps(r.headers, sort_keys=True), r.body, r.count, now))
                self._write_staged()
                self._enforce(now)
            self._staged.clear()
            dropped = self.dropped_total()
            if dropped > self._warned_drop:
                log.warning("outbox over a limit (%d requests, %d bytes, or too old): %d data point(s) and "
                            "%d log record(s) dropped in total; events are dropped last",
                            self.max_requests, self.max_bytes, self.dropped_points_total(),
                            self.dropped_records_total())
                self._warned_drop = dropped

    @_recovering
    def prune(self) -> None:
        """Apply the age and size limits now. The agent calls it before each delivery pass, so a
        long outage does not leave stale readings to be sent when Observe comes back."""
        with self._lock, self._db:
            self._enforce(self._clock())

    def _drop(self, seq: int, signal: str, count: int) -> None:
        self._db.execute("DELETE FROM requests WHERE seq=?", (seq,))
        self._bump("dropped_requests", 1)
        self._bump("dropped_points" if signal == "metrics" else "dropped_records", count)
        self._bump("dropped_since_drain", 1)

    def _enforce(self, now: float) -> None:
        for signal, age in (("metrics", self.max_metrics_age_s), ("logs", self.max_logs_age_s)):
            for seq, count in self._db.execute(
                    "SELECT seq, count FROM requests WHERE signal=? AND created < ?",
                    (signal, now - age)).fetchall():
                self._drop(seq, signal, count)
        while True:
            n, size = self._db.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(body)), 0) FROM requests").fetchone()
            if n <= self.max_requests and size <= self.max_bytes:
                return
            row = (self._db.execute("SELECT seq, signal, count FROM requests WHERE signal='metrics' "
                                    "ORDER BY seq LIMIT 1").fetchone()
                   or self._db.execute("SELECT seq, signal, count FROM requests ORDER BY seq LIMIT 1").fetchone())
            if row is None:
                return
            self._drop(*row)

    @_recovering
    def depth(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]

    @_recovering
    def size_bytes(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COALESCE(SUM(LENGTH(body)), 0) FROM requests").fetchone()[0]

    @_recovering
    def peek(self) -> QueuedRequest | None:
        """The next request to send: log requests before metrics requests, each oldest first, so
        events that were queued during an outage leave before the backlog of readings. A row whose
        headers cannot be decoded is moved to dead_letters on the way, so one bad row never blocks
        the ones behind it."""
        with self._lock:
            while True:
                row = self._db.execute(
                    "SELECT seq, entry_id, signal, path, headers, body, count, created FROM requests "
                    "ORDER BY (signal = 'logs') DESC, seq LIMIT 1").fetchone()
                if row is None:
                    return None
                try:
                    headers = json.loads(row[4])
                    if not isinstance(headers, dict):
                        raise ValueError("headers are not an object")
                    return QueuedRequest(row[0], row[1], row[2], row[3], headers, bytes(row[5]), row[6], row[7])
                except ValueError as exc:
                    self.dead_letter(row[0], 0, f"undecodable headers: {exc}")

    @_recovering
    def ack(self, seq: int) -> None:
        """Remove a delivered request. Called only after a 2xx answer."""
        with self._lock, self._db:
            self._db.execute("DELETE FROM requests WHERE seq=?", (seq,))
            if self._db.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0:
                self._db.execute("DELETE FROM counters WHERE name='dropped_since_drain'")
                self._warned_drop = 0

    @_recovering
    def dead_letter(self, seq: int, status: int, error: str = "") -> None:
        with self._lock, self._db:
            row = self._db.execute("SELECT entry_id, signal, headers, body FROM requests WHERE seq=?",
                                   (seq,)).fetchone()
            if row is None:
                return
            self._db.execute("INSERT INTO dead_letters (entry_id, signal, status, ts, headers, body, error) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?)",
                             (row[0], row[1], status, time.time(), row[2], row[3], error[:500] or None))
            self._db.execute("DELETE FROM requests WHERE seq=?", (seq,))
            self._db.execute("DELETE FROM dead_letters WHERE id <= (SELECT MAX(id) FROM dead_letters) - ?",
                             (MAX_DEAD_LETTERS,))
            self._trim_dead_letters()
        log.error("request %s (%s) was refused with status %d and moved to the dead-letter table%s",
                  row[0], row[1], status, f": {error}" if error else "")

    def _trim_dead_letters(self) -> None:
        """Keep the dead letters under MAX_DEAD_LETTER_BYTES, oldest first. The newest row always
        stays, so the most recent refusal can be inspected even when it alone is large."""
        while True:
            size, newest = self._db.execute(
                "SELECT COALESCE(SUM(LENGTH(body) + LENGTH(headers)), 0), MAX(id) FROM dead_letters").fetchone()
            if size <= MAX_DEAD_LETTER_BYTES:
                return
            cur = self._db.execute("DELETE FROM dead_letters WHERE id = (SELECT MIN(id) FROM dead_letters) "
                                   "AND id < ?", (newest,))
            if cur.rowcount == 0:
                return

    @_recovering
    def note_rejected(self, signal: str, count: int) -> None:
        """Count data points or log records Observe accepted the request for but refused."""
        if count > 0:
            with self._lock, self._db:
                self._bump("rejected_points" if signal == "metrics" else "rejected_records", count)

    @_recovering
    def note_quarantined(self, signal: str, count: int) -> None:
        """Count items that could not be encoded and were left out of every request."""
        if count > 0:
            with self._lock, self._db:
                self._bump("quarantined_points" if signal == "metrics" else "quarantined_records", count)

    @_recovering
    def quarantined_total(self) -> int:
        with self._lock:
            return self._counter("quarantined_points") + self._counter("quarantined_records")

    @_recovering
    def dead_letter_count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM dead_letters").fetchone()[0]

    @_recovering
    def dropped_total(self) -> int:
        """Requests dropped for age or size since the file was created."""
        with self._lock:
            return self._counter("dropped_requests")

    @_recovering
    def dropped_points_total(self) -> int:
        with self._lock:
            return self._counter("dropped_points")

    @_recovering
    def dropped_records_total(self) -> int:
        with self._lock:
            return self._counter("dropped_records")

    @_recovering
    def dropped_since_drain(self) -> int:
        with self._lock:
            return self._counter("dropped_since_drain")

    @_recovering
    def rejected_points_total(self) -> int:
        with self._lock:
            return self._counter("rejected_points")

    @_recovering
    def rejected_records_total(self) -> int:
        with self._lock:
            return self._counter("rejected_records")
