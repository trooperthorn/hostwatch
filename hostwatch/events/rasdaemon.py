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
transaction as the requests that carry the events, so a restart resumes from
what was durably queued. Without a store the ids live in memory. Observe also
keeps one row per dedup key, so a re-read of old rows does not create
duplicates there.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from ..outbox import MemoryMarkers, Markers
from ..model import Event, SourceStatus

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


def parse_timestamp(value: object) -> tuple[float | None, bool]:
    """Parse the rasdaemon timestamp text into (epoch seconds, uncertain).

    A timestamp with an explicit offset is exact. One without a zone is read as
    UTC and reported uncertain, because the zone rasdaemon used is not known and
    the process time zone must never decide the answer. Unreadable text gives
    (None, False)."""
    if isinstance(value, (int, float)):
        return float(value), False
    if not isinstance(value, str):
        return None, False
    text = value.strip()
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S %z").timestamp(), False
    except ValueError:
        pass
    try:
        naive = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None, False
    return naive.replace(tzinfo=timezone.utc).timestamp(), True


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
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    conn.text_factory = _decode_text
    return conn


def _decode_text(raw: bytes) -> str | bytes:
    """Return text when the bytes are valid UTF-8, otherwise the raw bytes, so one
    undecodable value cannot make SQLite fail the whole query. The caller turns
    leftover bytes into hex text."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return bytes(raw)


def _plain(value: object) -> object:
    """Make a column value safe for JSON: bytes become hex text."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return value


class RasdaemonReader:
    def __init__(self, db_path: Path, markers: Markers | None = None) -> None:
        self.db_path = db_path
        self.markers: Markers = markers if markers is not None else MemoryMarkers()
        self._skipped = 0

    def _high_water(self, table: str) -> int:
        try:
            return int(self.markers.get(f"rasdaemon.high_water.{table}") or 0)
        except ValueError:
            return 0

    def read(self) -> tuple[SourceStatus, list[Event]]:
        try:
            os.stat(self.db_path)
        except FileNotFoundError:
            # No database means rasdaemon is not installed or records nowhere here: not present.
            return SourceStatus(source=SOURCE, available=False, present=False,
                                reason=f"{self.db_path} does not exist"), []
        except OSError as exc:
            return SourceStatus(source=SOURCE, available=False,
                                reason=f"cannot read {self.db_path}: {exc}"), []
        if not self.db_path.is_file():
            return SourceStatus(source=SOURCE, available=False,
                                reason=f"{self.db_path} is not a file"), []
        try:
            conn = open_readonly(self.db_path)
        except sqlite3.Error as exc:
            return SourceStatus(source=SOURCE, available=False,
                                reason=f"cannot open {self.db_path}: {exc}"), []
        events: list[Event] = []
        notes: list[str] = []
        self._skipped = 0
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
        if self._skipped:
            notes.append(f"{self._skipped} row(s) skipped because they could not be converted")
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
        recreated = False
        if last > 0:
            # The row last read must still exist with the same timestamp text.
            # A lower maximum id is not enough: a recreated database can grow
            # past the old mark before the next read. The timestamp in the dedup
            # key keeps Observe from merging new rows with old rows that reused an id.
            stored = self.markers.get(f"rasdaemon.last_ts.{table}")
            at_mark = conn.execute(f"SELECT {'timestamp' if 'timestamp' in cols else 'NULL'} "
                                   f"FROM {table} WHERE id = ?", (last,)).fetchone()
            if at_mark is None or (stored is not None and json.loads(stored) != _plain(at_mark[0])):
                recreated = True
                last = 0
                self.markers.stage(f"rasdaemon.high_water.{table}", "0")
                self.markers.stage(f"rasdaemon.last_ts.{table}", None)
        rows = conn.execute(
            f"SELECT {select} FROM {table} WHERE id > ? ORDER BY id LIMIT ?",
            (last, MAX_ROWS_PER_READ)).fetchall()
        events: list[Event] = []
        for row in rows:
            data = dict(row)
            rid = data.pop("id")
            raw_ts = _plain(data.get("timestamp"))
            try:
                events.append(self._make_event(table, data, rid, recreated))
            except Exception:
                self._skipped += 1
            self.markers.stage(f"rasdaemon.high_water.{table}", str(rid))
            self.markers.stage(f"rasdaemon.last_ts.{table}", json.dumps(raw_ts))
        return events

    @staticmethod
    def _make_event(table: str, data: dict, rid: int, recreated: bool) -> Event:
        data = {k: _plain(v) for k, v in data.items()}
        raw_ts = data.pop("timestamp", None)
        ts, uncertain = parse_timestamp(raw_ts)
        if ts is not None and ts != ts or ts in (float("inf"), float("-inf")):
            ts = None
        detail = {k: v for k, v in data.items() if v is not None}
        detail["table"] = table
        if recreated:
            detail["database_recreated"] = True
        if uncertain:
            detail["ts_uncertain"] = True
            detail["timestamp_raw"] = raw_ts
        if ts is None:
            # Unavailable beats wrong: keep the raw text and mark the time as read time.
            detail["timestamp_raw"] = raw_ts
            detail["ts_is_read_time"] = True
            ts = time.time()
        msg = data.get("err_msg") or data.get("error_msg") or data.get("err_type") or "record"
        return Event(
            kind=KIND, severity=classify_severity(table, data), source=SOURCE, ts=ts,
            title=f"rasdaemon {table} {rid}: {msg}",
            detail=detail, dedup_key=f"rasdaemon:{table}:{rid}:{raw_ts}")
