"""Read-only rasdaemon database ingestion.

rasdaemon records memory controller errors, PCIe AER errors and machine check
exceptions in a SQLite database (default /host/rasdaemon/ras-mc_event.db). The
database is opened with a file: URI and mode=ro, so SQLite itself refuses any
write; the host keeps its own copy of the evidence.

Each of the tables mc_event, aer_event and mce_record is read only when it
exists, because which tables exist depends on the rasdaemon version and the
hardware. A missing table is skipped with a reason. A missing or unreadable
database makes the whole source unavailable. The table and column names are
assumptions that are not yet confirmed on hardware; see UNVERIFIED.md.

The reader keeps one high-water row id per table as a marker. With the agent
outbox as the marker store, the new high-water id is committed in the same
transaction as the batch that carries the events, so a restart resumes from
what was durably queued. Without a store the ids live in memory. The hub also
keeps one row per dedup key, so a re-read of old rows does not create
duplicates there.
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime
from pathlib import Path

from ..outbox import MemoryMarkers, Markers
from ..schema import Event, SourceStatus

SOURCE = "rasdaemon"
KIND = "hardware_error"
TABLES = ("mc_event", "aer_event", "mce_record")
MAX_ROWS_PER_READ = 500

# Columns copied into the event detail when the table has them.
DETAIL_COLUMNS = {
    "mc_event": ("err_count", "err_type", "err_msg", "label", "mc", "top_layer",
                 "mid_layer", "lower_layer", "address", "grain", "syndrome", "driver_detail"),
    "aer_event": ("dev_name", "err_type", "err_msg"),
    "mce_record": ("mcgstatus", "bank", "status", "addr", "misc", "cpu", "cpuvendor",
                   "error_msg", "mcistatus_msg", "mcastatus_msg"),
}


def parse_timestamp(value: object) -> float | None:
    """Parse the rasdaemon timestamp text; return None when it cannot be read."""
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value.strip(), fmt).timestamp()
        except ValueError:
            continue
    return None


def classify_severity(table: str, row: dict) -> str:
    """Map a row to warning or critical. Corrected errors are warnings,
    uncorrected or fatal errors and any machine check record are critical.
    A row whose type is not recognised is a warning, never silently info."""
    if table == "mce_record":
        return "critical"
    err_type = str(row.get("err_type") or "").lower()
    if "uncorrect" in err_type or "fatal" in err_type:
        return "critical"
    return "warning"


def open_readonly(path: Path) -> sqlite3.Connection:
    """Open the database read-only through a file: URI."""
    uri = path.absolute().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True, timeout=5)


class RasdaemonReader:
    def __init__(self, db_path: Path, markers: Markers | None = None) -> None:
        self.db_path = db_path
        self.markers: Markers = markers if markers is not None else MemoryMarkers()

    def _high_water(self, table: str) -> int:
        try:
            return int(self.markers.get(f"rasdaemon.high_water.{table}") or 0)
        except ValueError:
            return 0

    def read(self) -> tuple[SourceStatus, list[Event]]:
        if not self.db_path.is_file():
            return SourceStatus(source=SOURCE, available=False,
                                reason=f"{self.db_path} does not exist"), []
        try:
            conn = open_readonly(self.db_path)
        except sqlite3.Error as exc:
            return SourceStatus(source=SOURCE, available=False,
                                reason=f"cannot open {self.db_path}: {exc}"), []
        events: list[Event] = []
        notes: list[str] = []
        try:
            conn.row_factory = sqlite3.Row
            present = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for table in TABLES:
                if table not in present:
                    notes.append(f"table {table} is absent")
                    continue
                try:
                    events.extend(self._read_table(conn, table))
                except sqlite3.Error as exc:
                    notes.append(f"table {table} could not be read: {exc}")
        except sqlite3.Error as exc:
            return SourceStatus(source=SOURCE, available=False,
                                reason=f"cannot read {self.db_path}: {exc}"), []
        finally:
            conn.close()
        if len(notes) == len(TABLES):
            return SourceStatus(source=SOURCE, available=False, reason="; ".join(notes)), []
        return SourceStatus(source=SOURCE, available=True, reason="; ".join(notes)), events

    def _read_table(self, conn: sqlite3.Connection, table: str) -> list[Event]:
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if "id" not in cols:
            raise sqlite3.Error("no id column")
        wanted = [c for c in DETAIL_COLUMNS[table] if c in cols]
        if "timestamp" in cols:
            wanted.append("timestamp")
        select = ", ".join(["id", *wanted])
        last = self._high_water(table)
        rows = conn.execute(
            f"SELECT {select} FROM {table} WHERE id > ? ORDER BY id LIMIT ?",
            (last, MAX_ROWS_PER_READ)).fetchall()
        events: list[Event] = []
        for row in rows:
            data = dict(row)
            rid = data.pop("id")
            raw_ts = data.pop("timestamp", None)
            ts = parse_timestamp(raw_ts)
            detail = {k: v for k, v in data.items() if v is not None}
            detail["table"] = table
            if ts is None:
                # Unavailable beats wrong: keep the raw text and mark the time as read time.
                detail["timestamp_raw"] = raw_ts
                detail["ts_is_read_time"] = True
                ts = time.time()
            msg = data.get("err_msg") or data.get("error_msg") or data.get("err_type") or "record"
            events.append(Event(
                kind=KIND, severity=classify_severity(table, data), source=SOURCE, ts=ts,
                title=f"rasdaemon {table} {rid}: {msg}",
                detail=detail, dedup_key=f"rasdaemon:{table}:{rid}"))
            self.markers.stage(f"rasdaemon.high_water.{table}", str(rid))
        return events
