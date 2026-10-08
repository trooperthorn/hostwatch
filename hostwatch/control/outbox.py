"""A small durable outbox for command results.

A result waits in a SQLite file in the control data directory until Observe answers 2xx, so a
network outage or a restart delays the report but does not lose it. The outbox is separate from the
collector's outbox and holds nothing but results. A command id has at most one queued row per
status and at most one final one (done, failed or cancelled): the first final result queued for it wins, so
a later report can never overwrite the report of what really happened. A scheduled reboot queues a
`scheduled` row first and its final row later, in that order. A refusal is queued only when nothing else is
known about the id, and a queued refusal is replaced by a later result of a command that really ran.

Besides the queue the file keeps two small tables: `executed` holds the latest result of every command that
ran (capped), so a command that is pulled again after its report was lost is answered with the stored
result, and `scheduled` holds the reboots this host has promised and not yet resolved.

Overflow: when more than `max_results` results wait, the oldest is dropped and counted, because an
unbounded file on a host whose Observe stays away for days is worse than a missing old report
(Observe shows a command with no result as unknown, never as done). The running count is available from
`dropped_total()` and the daemon sends it with every result as `outbox_dropped`.

A result that Observe refuses with a permanent 4xx answer is parked: moved to a `parked` table with the
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
EXECUTED_CAP = 1000
FINAL_STATUSES = ("done", "failed", "cancelled")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, command_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT '',
  payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS executed (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, command_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scheduled (command_id TEXT PRIMARY KEY, due_at REAL NOT NULL, boot_id TEXT);
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
                      "results in it are lost and will show as unknown in Observe", self.path, exc, moved)
            self.recovered_from = moved
            self._db = self._open()

    def _open(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, check_same_thread=False)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                self._migrate(db)
                db.executescript(_SCHEMA)
            db.execute("SELECT COUNT(*) FROM results").fetchone()
        except sqlite3.DatabaseError:
            db.close()
            raise
        return db

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        """An outbox from before results had a status column held one row per command id."""
        scheduled = [r[1] for r in db.execute("PRAGMA table_info(scheduled)").fetchall()]
        if scheduled and "boot_id" not in scheduled:
            db.execute("ALTER TABLE scheduled ADD COLUMN boot_id TEXT")  # unknown for reboots already pending
        columns = [r[1] for r in db.execute("PRAGMA table_info(results)").fetchall()]
        if not columns or "status" in columns:
            return
        db.execute("ALTER TABLE results RENAME TO results_old")
        db.execute("CREATE TABLE results (seq INTEGER PRIMARY KEY AUTOINCREMENT, command_id TEXT NOT NULL, "
                   "status TEXT NOT NULL DEFAULT '', payload TEXT NOT NULL)")
        for seq, command_id, payload in db.execute(
                "SELECT seq, command_id, payload FROM results_old ORDER BY seq").fetchall():
            db.execute("INSERT INTO results (seq, command_id, status, payload) VALUES (?, ?, ?, ?)",
                       (seq, command_id, str(_status_of(payload) or ""), payload))
        db.execute("DROP TABLE results_old")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def add(self, command_id: str, payload: dict) -> None:
        """Queue a result. The row is durable when this returns."""
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        status = str(payload.get("status") or "")
        with self._lock, self._db:
            if self._db.execute("SELECT 1 FROM parked WHERE command_id=?", (command_id,)).fetchone():
                return  # Observe refused this command's result for good; a repeat cannot fare better
            known = [r[0] for r in self._db.execute(
                "SELECT status FROM results WHERE command_id=?", (command_id,)).fetchall()]
            ran = self._db.execute("SELECT 1 FROM executed WHERE command_id=?", (command_id,)).fetchone()
            if status == "refused":
                if known or ran:
                    return  # something real is already known about this id; a refusal must not hide it
            else:
                # A refusal can come from a forged command that borrowed a real id. The report of a command
                # that really ran replaces a queued refusal; it never replaces another real result.
                self._db.execute("DELETE FROM results WHERE command_id=? AND status='refused'", (command_id,))
                known = [k for k in known if k != "refused"]
                if status in known or any(k in FINAL_STATUSES for k in known):
                    return
                self._remember(command_id, status, text)
            self._db.execute("INSERT INTO results (command_id, status, payload) VALUES (?, ?, ?)",
                             (command_id, status, text))
            over = self._db.execute("SELECT COUNT(*) FROM results").fetchone()[0] - self.max_results
            if over > 0:
                self._db.execute("DELETE FROM results WHERE seq IN "
                                 "(SELECT seq FROM results ORDER BY seq LIMIT ?)", (over,))
                self._db.execute("INSERT INTO counters (name, value) VALUES ('dropped', ?) "
                                 "ON CONFLICT(name) DO UPDATE SET value = value + excluded.value", (over,))
                log.warning("result outbox over its cap of %d: %d oldest result(s) dropped", self.max_results, over)

    def _remember(self, command_id: str, status: str, text: str) -> None:
        """Keep the latest result of a command that ran. A final result is never replaced by a scheduled one."""
        row = self._db.execute("SELECT payload FROM executed WHERE command_id=?", (command_id,)).fetchone()
        if row is not None and _status_of(row[0]) in FINAL_STATUSES and status not in FINAL_STATUSES:
            return
        self._db.execute("INSERT INTO executed (command_id, payload) VALUES (?, ?) "
                         "ON CONFLICT(command_id) DO UPDATE SET payload=excluded.payload", (command_id, text))
        over = self._db.execute("SELECT COUNT(*) FROM executed").fetchone()[0] - EXECUTED_CAP
        if over > 0:
            self._db.execute("DELETE FROM executed WHERE seq IN (SELECT seq FROM executed ORDER BY seq LIMIT ?)",
                             (over,))

    def stored(self, command_id: str) -> dict | None:
        """The latest result of a command that ran on this host, or None."""
        with self._lock:
            row = self._db.execute("SELECT payload FROM executed WHERE command_id=?", (command_id,)).fetchone()
        try:
            data = json.loads(row[0]) if row else None
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def schedule(self, command_id: str, due_at: float, boot_id: str | None = None) -> None:
        """Record a pending reboot with the boot id of the host when it was scheduled."""
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO scheduled (command_id, due_at, boot_id) VALUES (?, ?, ?)",
                             (command_id, due_at, boot_id))

    def scheduled_boot_id(self, command_id: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT boot_id FROM scheduled WHERE command_id=?", (command_id,)).fetchone()
        return row[0] if row else None

    def set_scheduled_boot_id(self, command_id: str, boot_id: str) -> None:
        """Record the boot id of a pending reboot that was scheduled before boot ids were kept."""
        with self._lock, self._db:
            self._db.execute("UPDATE scheduled SET boot_id=? WHERE command_id=? AND boot_id IS NULL",
                             (boot_id, command_id))

    def unschedule(self, command_id: str) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM scheduled WHERE command_id=?", (command_id,))

    def scheduled(self) -> dict[str, float]:
        """Command id to the time its reboot was due, for every reboot not yet resolved."""
        with self._lock:
            rows = self._db.execute("SELECT command_id, due_at FROM scheduled ORDER BY rowid").fetchall()
            return {r[0]: r[1] for r in rows}

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
        """Move a result that Observe refuses for good out of the queue, keeping it and the reason."""
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
