"""A small durable outbox for command results.

A result waits in a SQLite file in the control data directory until watchpost answers 2xx, so a
network outage or a restart delays the report but does not lose it. The outbox is separate from the
collector's batch outbox and holds nothing but results. A command id appears at most once, and the first result queued for it
wins, so a later refusal of a replayed command can never overwrite the report of what really happened. The
one exception is a queued refusal, which a later result of a command that really ran replaces.

Overflow: when more than `max_results` results wait, the oldest is dropped and counted, because an
unbounded file on a host whose watchpost stays away for days is worse than a missing old report
(watchpost shows a command with no result as unknown, never as done). The running count is available from
`dropped_total()` and the daemon sends it with every result as `outbox_dropped`.

A result that watchpost refuses with a permanent 4xx answer is parked: moved to a `parked` table with the
reason and no longer sent, so one undeliverable result never blocks the ones behind it. It is kept, not
deleted, for the owner to inspect (`parked()`), up to the same cap.

A file that SQLite reports as not a database is renamed aside with a timestamp and a fresh outbox
starts; any other database error is raised and the file is left alone.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path

log = logging.getLogger("hostwatch.control.outbox")

OUTBOX_FILE = "control-outbox.db"
MAX_RESULTS = 200

_SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, command_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS parked (
  seq INTEGER PRIMARY KEY, command_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, reason TEXT NOT NULL,
  parked_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
"""
_CORRUPT = ("file is not a database", "malformed", "file is encrypted")


def _status_of(text: str) -> object:
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data.get("status") if isinstance(data, dict) else None


class ResultOutbox:
    def __init__(self, path: str | Path, max_results: int = MAX_RESULTS) -> None:
        if max_results < 1:
            raise ValueError("max_results must be at least 1")
        self.path = Path(path)
        self.max_results = max_results
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.recovered_from: Path | None = None
        try:
            self._db = self._open()
        except sqlite3.DatabaseError as exc:
            if not any(m in str(exc).lower() for m in _CORRUPT):
                raise
            moved = self.path.with_name(f"{self.path.name}.corrupt-{time.strftime('%Y%m%dT%H%M%S')}")
            n = 0
            while moved.exists():
                n += 1
                moved = self.path.with_name(f"{moved.name}-{n}")
            self.path.rename(moved)
            log.error("result outbox %s was unreadable (%s); moved to %s and a fresh one started. Unsent "
                      "results in it are lost and will show as unknown in watchpost", self.path, exc, moved)
            self.recovered_from = moved
            self._db = self._open()

    def _open(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, check_same_thread=False)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                db.executescript(_SCHEMA)
            db.execute("SELECT COUNT(*) FROM results").fetchone()
        except sqlite3.DatabaseError:
            db.close()
            raise
        return db

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def add(self, command_id: str, payload: dict) -> None:
        """Queue a result. The row is durable when this returns."""
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._lock, self._db:
            if self._db.execute("SELECT 1 FROM parked WHERE command_id=?", (command_id,)).fetchone():
                return  # watchpost refused this command's result for good; a repeat cannot fare better
            row = self._db.execute("SELECT seq, payload FROM results WHERE command_id=?", (command_id,)).fetchone()
            if row is None:
                self._db.execute("INSERT INTO results (command_id, payload) VALUES (?, ?)", (command_id, text))
            elif payload.get("status") != "refused" and _status_of(row[1]) == "refused":
                # A refusal can come from a forged command that borrowed a real id. The report of a command
                # that really ran replaces a queued refusal; it never replaces another real result.
                self._db.execute("UPDATE results SET payload=? WHERE seq=?", (text, row[0]))
            over = self._db.execute("SELECT COUNT(*) FROM results").fetchone()[0] - self.max_results
            if over > 0:
                self._db.execute("DELETE FROM results WHERE seq IN "
                                 "(SELECT seq FROM results ORDER BY seq LIMIT ?)", (over,))
                self._db.execute("INSERT INTO counters (name, value) VALUES ('dropped', ?) "
                                 "ON CONFLICT(name) DO UPDATE SET value = value + excluded.value", (over,))
                log.warning("result outbox over its cap of %d: %d oldest result(s) dropped", self.max_results, over)

    def has(self, command_id: str) -> bool:
        with self._lock:
            queued = self._db.execute("SELECT 1 FROM results WHERE command_id=?", (command_id,)).fetchone()
            parked = self._db.execute("SELECT 1 FROM parked WHERE command_id=?", (command_id,)).fetchone()
            return queued is not None or parked is not None

    def peek(self) -> tuple[int, dict] | None:
        """The oldest result. A row that cannot be decoded is removed and logged so it never blocks the rest."""
        with self._lock:
            while True:
                row = self._db.execute("SELECT seq, command_id, payload FROM results ORDER BY seq LIMIT 1").fetchone()
                if row is None:
                    return None
                try:
                    payload = json.loads(row[2])
                    if isinstance(payload, dict):
                        return row[0], payload
                except ValueError:
                    pass
                log.error("result outbox row for command %s could not be decoded; removed", row[1])
                self.ack(row[0])

    def ack(self, seq: int) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM results WHERE seq=?", (seq,))

    def park(self, seq: int, reason: str) -> None:
        """Move a result that watchpost refuses for good out of the queue, keeping it and the reason."""
        with self._lock, self._db:
            row = self._db.execute("SELECT command_id, payload FROM results WHERE seq=?", (seq,)).fetchone()
            if row is None:
                return
            self._db.execute("INSERT OR REPLACE INTO parked (seq, command_id, payload, reason, parked_at) "
                             "VALUES (?, ?, ?, ?, ?)", (seq, row[0], row[1], reason, int(time.time())))
            self._db.execute("DELETE FROM results WHERE seq=?", (seq,))
            over = self._db.execute("SELECT COUNT(*) FROM parked").fetchone()[0] - self.max_results
            if over > 0:
                self._db.execute("DELETE FROM parked WHERE seq IN (SELECT seq FROM parked ORDER BY seq LIMIT ?)",
                                 (over,))

    def parked(self) -> list[tuple[str, str]]:
        """(command id, reason) of every parked result, oldest first."""
        with self._lock:
            rows = self._db.execute("SELECT command_id, reason FROM parked ORDER BY seq").fetchall()
            return [(r[0], r[1]) for r in rows]

    def depth(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM results").fetchone()[0]

    def dropped_total(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT value FROM counters WHERE name='dropped'").fetchone()
            return row[0] if row else 0
