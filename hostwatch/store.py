"""SQLite storage for samples and source availability.

Raw samples are kept for HOSTWATCH_RAW_RETENTION_DAYS. Before raw rows are
pruned, they are rolled up into hourly min/avg/max rows that are kept for
HOSTWATCH_ROLLUP_RETENTION_DAYS. Unavailable samples (value NULL) are stored
so gaps are visible as gaps, but are excluded from rollup math.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from .schema import Batch

DDL = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS samples (
  ts REAL NOT NULL, host TEXT NOT NULL, source TEXT NOT NULL, metric TEXT NOT NULL,
  labels TEXT NOT NULL, value REAL, unit TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS samples_lookup ON samples(host, source, metric, ts);
CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts);
CREATE TABLE IF NOT EXISTS rollup_hourly (
  hour REAL NOT NULL, host TEXT NOT NULL, source TEXT NOT NULL, metric TEXT NOT NULL,
  labels TEXT NOT NULL, n INTEGER NOT NULL, vmin REAL, vavg REAL, vmax REAL, unit TEXT NOT NULL,
  PRIMARY KEY (hour, host, source, metric, labels)
);
CREATE TABLE IF NOT EXISTS sources (
  host TEXT NOT NULL, source TEXT NOT NULL, available INTEGER NOT NULL,
  reason TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY (host, source)
);
CREATE TABLE IF NOT EXISTS agents (
  host TEXT PRIMARY KEY, platform TEXT NOT NULL, agent_version TEXT NOT NULL, last_seen REAL NOT NULL
);
"""


# Schema versioning uses PRAGMA user_version. Phase 1 databases never set it, so
# a database with user_version 0 is treated as version 1 once its Phase 1 tables
# exist. Each migration step is additive: it only creates objects and is guarded
# with IF NOT EXISTS so that running it twice changes nothing.
SCHEMA_VERSION = 2

MIGRATIONS: dict[int, tuple[str, ...]] = {
    2: (
        """CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL, ts REAL NOT NULL,
  kind TEXT NOT NULL, severity TEXT NOT NULL, source TEXT NOT NULL, title TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}', dedup_key TEXT NOT NULL, boot_id TEXT,
  UNIQUE (host, dedup_key)
)""",
        "CREATE INDEX IF NOT EXISTS events_host_ts ON events(host, ts)",
        "CREATE INDEX IF NOT EXISTS events_kind ON events(kind)",
        """CREATE TABLE IF NOT EXISTS boot_state (
  host TEXT PRIMARY KEY, boot_id TEXT, heartbeat_ts REAL NOT NULL, boot_ts REAL, clean_shutdown INTEGER
)""",
    ),
}


class SchemaTooNewError(RuntimeError):
    """Raised when the database was written by a newer version of hostwatch."""


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                self._db.close()
                raise SchemaTooNewError(
                    f"{path} has schema version {version} but this hostwatch supports up to "
                    f"{SCHEMA_VERSION}. Upgrade hostwatch or restore an older database.")
            self._db.executescript(DDL)
            self._migrate()

    def _migrate(self) -> None:
        """Apply numbered migration steps above the stored version, atomically."""
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            version = 1  # Phase 1 tables were just ensured by DDL; adopt them as version 1.
        for target in range(version + 1, SCHEMA_VERSION + 1):
            self._db.execute("BEGIN")
            try:
                for stmt in MIGRATIONS[target]:
                    self._db.execute(stmt)
                self._db.execute(f"PRAGMA user_version = {target}")
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            version = target

    def add_events(self, host: str, events: list[dict]) -> int:
        """Insert events, ignoring any whose (host, dedup_key) already exists. Returns rows inserted."""
        rows = [(host, e["ts"], e["kind"], e["severity"], e["source"], e["title"],
                 json.dumps(e.get("detail", {}), sort_keys=True), e["dedup_key"], e.get("boot_id"))
                for e in events]
        with self._lock, self._db:
            before = self._db.total_changes
            self._db.executemany(
                "INSERT OR IGNORE INTO events (host, ts, kind, severity, source, title, detail, dedup_key, boot_id) "
                "VALUES (?,?,?,?,?,?,?,?,?)", rows)
            return self._db.total_changes - before

    def events(self, host: str | None = None, since: float | None = None,
               kind: str | None = None, limit: int = 100) -> list[dict]:
        where, params = [], []
        if host:
            where.append("host = ?")
            params.append(host)
        if since is not None:
            where.append("ts >= ?")
            params.append(since)
        if kind:
            where.append("kind = ?")
            params.append(kind)
        sql = ("SELECT id, host, ts, kind, severity, source, title, detail, dedup_key, boot_id FROM events"
               + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY ts DESC, id DESC LIMIT ?")
        params.append(limit)
        with self._lock:
            cur = self._db.execute(sql, params)
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            r["detail"] = json.loads(r["detail"])
        return rows

    def ingest(self, batch: Batch) -> int:
        rows = [(s.ts, batch.host, s.source, s.metric, json.dumps(s.labels, sort_keys=True), s.value, s.unit)
                for s in batch.samples]
        with self._lock, self._db:
            self._db.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?)", rows)
            self._db.executemany(
                "INSERT INTO sources VALUES (?,?,?,?,?) ON CONFLICT(host, source) DO UPDATE SET "
                "available=excluded.available, reason=excluded.reason, updated=excluded.updated",
                [(batch.host, st.source, int(st.available), st.reason, batch.sent_at) for st in batch.sources])
            self._db.execute(
                "INSERT INTO agents VALUES (?,?,?,?) ON CONFLICT(host) DO UPDATE SET "
                "platform=excluded.platform, agent_version=excluded.agent_version, last_seen=excluded.last_seen",
                (batch.host, batch.platform, batch.agent_version, batch.sent_at))
        return len(rows)

    def latest(self, host: str | None = None) -> list[dict]:
        sql = ("SELECT s.host, s.source, s.metric, s.labels, s.value, s.unit, s.ts FROM samples s "
               "JOIN (SELECT host, source, metric, labels, MAX(ts) AS mts FROM samples "
               "WHERE ts > ? {flt} GROUP BY host, source, metric, labels) m "
               "ON s.host=m.host AND s.source=m.source AND s.metric=m.metric AND s.labels=m.labels AND s.ts=m.mts "
               "ORDER BY s.host, s.source, s.metric")
        params: list = [time.time() - 3600]
        flt = ""
        if host:
            flt = "AND host = ?"
            params.append(host)
        with self._lock:
            cur = self._db.execute(sql.format(flt=flt), params)
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            r["labels"] = json.loads(r["labels"])
        return rows

    def sources(self) -> list[dict]:
        with self._lock:
            cur = self._db.execute("SELECT host, source, available, reason, updated FROM sources ORDER BY host, source")
            return [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]

    def agents(self) -> list[dict]:
        with self._lock:
            cur = self._db.execute("SELECT host, platform, agent_version, last_seen FROM agents ORDER BY host")
            return [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]

    def gaps(self, host: str, source: str, metric: str, since: float, max_gap_s: float) -> list[tuple[float, float]]:
        """Return (start, end) intervals longer than max_gap_s with no non-NULL sample. Used by the Phase 1 exit test."""
        with self._lock:
            ts = [r[0] for r in self._db.execute(
                "SELECT DISTINCT ts FROM samples WHERE host=? AND source=? AND metric=? AND ts>=? "
                "AND value IS NOT NULL ORDER BY ts", (host, source, metric, since))]
        return [(a, b) for a, b in zip(ts, ts[1:]) if b - a > max_gap_s]

    def maintain(self, raw_days: int, rollup_days: int) -> None:
        cutoff = time.time() - raw_days * 86400
        cutoff_hour = cutoff - (cutoff % 3600)
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO rollup_hourly "
                "SELECT ts - (ts % 3600) AS hour, host, source, metric, labels, COUNT(value), "
                "MIN(value), AVG(value), MAX(value), unit FROM samples "
                "WHERE ts < ? AND value IS NOT NULL GROUP BY hour, host, source, metric, labels",
                (cutoff_hour,))
            self._db.execute("DELETE FROM samples WHERE ts < ?", (cutoff_hour,))
            self._db.execute("DELETE FROM rollup_hourly WHERE hour < ?", (time.time() - rollup_days * 86400,))
