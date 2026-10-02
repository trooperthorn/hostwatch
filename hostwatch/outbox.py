"""Durable agent outbox.

Batches wait in a SQLite file in the data directory until the hub answers 2xx,
so an agent restart or a hub outage delays delivery but does not lose events.
Progress markers (journal cursor, rasdaemon high-water ids, pstore sent keys,
the pending boot event) live in the same file. A source stages a marker while it
reads, and `enqueue` writes the batch and every staged marker in one
transaction. A crash therefore leaves either both or neither: a marker never
runs ahead of the events that were queued for it.

Overflow policy: when more than `max_batches` batches wait, the oldest batch is
stripped of its samples (counted as dropped). Its events are kept by moving
them into the next batch, which then gets a new batch_id, because the hub may
already have acknowledged the old id. A batch left with nothing is deleted.

A batch the hub refuses with a 4xx other than 401 (and other than the
retryable 408 and 429) can never succeed, so it moves to the dead_letters
table with the status and no longer blocks the queue head.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Protocol

from .schema import Batch

log = logging.getLogger("hostwatch.outbox")

OUTBOX_FILE = "outbox.db"
MAX_DEAD_LETTERS = 1000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS markers (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dead_letters (
  id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT NOT NULL, status INTEGER NOT NULL,
  ts REAL NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
"""


class Markers(Protocol):
    """What an event source needs: read a marker, stage a new value (None
    clears it). Staged values are visible to `get` at once and become durable
    when the batch that carries them is enqueued."""

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


class Outbox:
    def __init__(self, path: Path, max_batches: int = 240) -> None:
        if max_batches < 2:
            raise ValueError("max_batches must be at least 2")
        self.max_batches = max_batches
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA synchronous=FULL")
        with self._db:
            self._db.executescript(_SCHEMA)
        self._staged: dict[str, str | None] = {}
        self._warned_drop = 0

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # markers
    def get(self, key: str) -> str | None:
        with self._lock:
            if key in self._staged:
                return self._staged[key]
            row = self._db.execute("SELECT value FROM markers WHERE key=?", (key,)).fetchone()
            return row[0] if row else None

    def stage(self, key: str, value: str | None) -> None:
        with self._lock:
            self._staged[key] = value

    # queue
    def enqueue(self, batch: Batch) -> None:
        """Write the batch and all staged markers in one transaction."""
        with self._lock:
            with self._db:
                self._db.execute("INSERT INTO batches (batch_id, payload) VALUES (?, ?)",
                                 (batch.batch_id or str(uuid.uuid4()), batch.model_dump_json()))
                self._write_staged()
                self._enforce_cap()
            self._staged.clear()
            dropped = self.dropped_since_drain()
            if dropped > self._warned_drop:
                log.warning("outbox over its cap of %d batches: %d sample(s) dropped since the queue last "
                            "drained; events were kept", self.max_batches, dropped)
                self._warned_drop = dropped

    def _write_staged(self) -> None:
        for key, value in self._staged.items():
            if value is None:
                self._db.execute("DELETE FROM markers WHERE key=?", (key,))
            else:
                self._db.execute("INSERT OR REPLACE INTO markers (key, value) VALUES (?, ?)", (key, value))

    def commit_staged(self) -> None:
        """Make staged markers durable without a batch. Used for the boot event,
        which must survive a restart before the first batch is built."""
        with self._lock:
            with self._db:
                self._write_staged()
            self._staged.clear()

    def _bump(self, name: str, by: int) -> None:
        self._db.execute("INSERT INTO counters (name, value) VALUES (?, ?) "
                         "ON CONFLICT(name) DO UPDATE SET value = value + excluded.value", (name, by))

    def _counter(self, name: str) -> int:
        row = self._db.execute("SELECT value FROM counters WHERE name=?", (name,)).fetchone()
        return row[0] if row else 0

    def _enforce_cap(self) -> None:
        while self._db.execute("SELECT COUNT(*) FROM batches").fetchone()[0] > self.max_batches:
            seq, payload = self._db.execute(
                "SELECT seq, payload FROM batches ORDER BY seq LIMIT 1").fetchone()
            old = Batch.model_validate_json(payload)
            dropped = len(old.samples)
            if dropped:
                self._bump("dropped_samples", dropped)
                self._bump("dropped_since_drain", dropped)
            nxt_seq, nxt_payload = self._db.execute(
                "SELECT seq, payload FROM batches WHERE seq > ? ORDER BY seq LIMIT 1", (seq,)).fetchone()
            if old.events:
                nxt = Batch.model_validate_json(nxt_payload)
                nxt = nxt.model_copy(update={"events": [*old.events, *nxt.events],
                                             "batch_id": str(uuid.uuid4())})
                self._db.execute("UPDATE batches SET batch_id=?, payload=? WHERE seq=?",
                                 (nxt.batch_id, nxt.model_dump_json(), nxt_seq))
            self._db.execute("DELETE FROM batches WHERE seq=?", (seq,))

    def depth(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM batches").fetchone()[0]

    def peek(self) -> tuple[int, Batch] | None:
        with self._lock:
            row = self._db.execute("SELECT seq, payload FROM batches ORDER BY seq LIMIT 1").fetchone()
        return (row[0], Batch.model_validate_json(row[1])) if row else None

    def ack(self, seq: int) -> None:
        """Remove a delivered batch. Called only after a 2xx answer."""
        with self._lock, self._db:
            self._db.execute("DELETE FROM batches WHERE seq=?", (seq,))
            if self._db.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 0:
                self._db.execute("DELETE FROM counters WHERE name='dropped_since_drain'")
                self._warned_drop = 0

    def dead_letter(self, seq: int, status: int) -> None:
        with self._lock, self._db:
            row = self._db.execute("SELECT batch_id, payload FROM batches WHERE seq=?", (seq,)).fetchone()
            if row is None:
                return
            self._db.execute("INSERT INTO dead_letters (batch_id, status, ts, payload) VALUES (?, ?, ?, ?)",
                             (row[0], status, time.time(), row[1]))
            self._db.execute("DELETE FROM batches WHERE seq=?", (seq,))
            self._db.execute("DELETE FROM dead_letters WHERE id <= "
                             "(SELECT MAX(id) FROM dead_letters) - ?", (MAX_DEAD_LETTERS,))
        log.error("hub refused batch %s with status %d; moved to the dead-letter table", row[0], status)

    def dead_letter_count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM dead_letters").fetchone()[0]

    def dropped_total(self) -> int:
        with self._lock:
            return self._counter("dropped_samples")

    def dropped_since_drain(self) -> int:
        with self._lock:
            return self._counter("dropped_since_drain")
