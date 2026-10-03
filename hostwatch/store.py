"""SQLite storage for samples and source availability.

Raw samples are kept for HOSTWATCH_RAW_RETENTION_DAYS. Before raw rows are
pruned, they are rolled up into hourly min/avg/max rows that are kept for
HOSTWATCH_ROLLUP_RETENTION_DAYS. Unavailable samples (value NULL) are stored
so gaps are visible as gaps, but are excluded from rollup math.
"""

from __future__ import annotations

import hashlib
import json
import secrets
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
SCHEMA_VERSION = 10

# Longest history range served from raw samples. Longer ranges use the hourly rollups.
HISTORY_RAW_MAX_S = 2 * 86400.0

def _add_sources_present(db: sqlite3.Connection) -> None:
    """Add sources.present (default 1, so rows from older agents read as present) once."""
    cols = {r[1] for r in db.execute("PRAGMA table_info(sources)")}
    if "present" not in cols:
        db.execute("ALTER TABLE sources ADD COLUMN present INTEGER NOT NULL DEFAULT 1")


def _add_api_keys_host(db: sqlite3.Connection) -> None:
    """Add api_keys.host (NULL means unbound, which is what every earlier key stays) once."""
    cols = {r[1] for r in db.execute("PRAGMA table_info(api_keys)")}
    if "host" not in cols:
        db.execute("ALTER TABLE api_keys ADD COLUMN host TEXT")


def _add_users_is_admin(db: sqlite3.Connection) -> None:
    """Add users.is_admin (default 0) once. The earliest user is the one bootstrap-admin created,
    so it becomes an admin and no deployment loses admin access. Guarded so a repeat run changes nothing."""
    cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
    if "is_admin" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        db.execute("UPDATE users SET is_admin = 1 WHERE id = (SELECT MIN(id) FROM users)")


AUDIT_NO_UPDATE_SQL = """CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END"""
AUDIT_NO_DELETE_SQL = """CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END"""

MIGRATIONS: dict[int, tuple] = {
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
    3: (
        """CREATE TABLE IF NOT EXISTS batch_ids (
  host TEXT NOT NULL, batch_id TEXT NOT NULL, received REAL NOT NULL, PRIMARY KEY (host, batch_id)
)""",
        "CREATE INDEX IF NOT EXISTS batch_ids_received ON batch_ids(received)",
    ),
    4: (
        """CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, hash TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0, failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until REAL, created REAL NOT NULL
)""",
        """CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), created REAL NOT NULL,
  expires REAL NOT NULL, last_seen REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
)""",
        """CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT NOT NULL UNIQUE, hash TEXT NOT NULL,
  scopes TEXT NOT NULL, owner TEXT NOT NULL, created REAL NOT NULL, revoked_at REAL, last_used REAL
)""",
        """CREATE TABLE IF NOT EXISTS cert_bindings (
  subject TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), created REAL NOT NULL,
  revoked_at REAL
)""",
        """CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL,
  method TEXT NOT NULL, path TEXT NOT NULL, status INTEGER NOT NULL, remote TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}'
)""",
        "CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log(ts)",
        # Application-layer protection only. Anyone who can open the database file
        # directly can drop these triggers or edit the file, so this is not tamper-proofing.
        AUDIT_NO_UPDATE_SQL,
        AUDIT_NO_DELETE_SQL,
    ),
    5: (
        # Publish progress per consumer: the last events.id already sent. Additive, no existing row changes.
        """CREATE TABLE IF NOT EXISTS publish_cursors (
  name TEXT PRIMARY KEY, last_id INTEGER NOT NULL, updated REAL NOT NULL
)""",
    ),
    # Whether a source is absent by design. Existing rows default to present.
    6: (_add_sources_present,),
    # When each source was first and last seen present and available, and when an operator
    # declared its removal deliberate. Additive: a new table, no existing row changes.
    7: (
        """CREATE TABLE IF NOT EXISTS source_seen (
  host TEXT NOT NULL, source TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
  forgotten_at REAL, PRIMARY KEY (host, source)
)""",
    ),
    # Admin flag on users. Additive: one guarded column, the earliest user is marked admin.
    8: (_add_users_is_admin,),
    # Operator acknowledgement of a crash event, so it stops holding the host critical.
    # Additive: a new table, no existing row changes.
    9: (
        """CREATE TABLE IF NOT EXISTS event_acks (
  event_id INTEGER PRIMARY KEY, acked_at REAL NOT NULL, actor TEXT NOT NULL
)""",
    ),
    # Optional host a key is bound to. Additive: one guarded nullable column, existing keys stay unbound.
    10: (_add_api_keys_host,),
}


class SchemaTooNewError(RuntimeError):
    """Raised when the database was written by a newer version of hostwatch."""


AUDIT_PATH_MAX = 256


def sanitize_audit_path(path: str) -> str:
    """Make a request path safe to store: control characters (including those decoded from
    percent-encoded input such as newline or NUL) become "?", and the result is capped at
    AUDIT_PATH_MAX characters, so a hostile path cannot forge log lines or bloat a row."""
    cleaned = "".join("?" if (ord(c) < 32 or 0x7F <= ord(c) <= 0x9F) else c for c in str(path))
    return cleaned[:AUDIT_PATH_MAX]


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
                    if callable(stmt):
                        stmt(self._db)
                    else:
                        self._db.execute(stmt)
                self._db.execute(f"PRAGMA user_version = {target}")
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            version = target

    # ---- Auth: users, sessions, API keys, audit (schema version 4) ----
    # Secrets are never stored in plain text. Password hashes are produced by the
    # caller (argon2id). Session tokens and API keys are random with 256 bits, so a
    # plain SHA-256 of them is sufficient and only the hash is stored.

    @staticmethod
    def _digest(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def _rows(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            cur = self._db.execute(sql, params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def create_user(self, username: str, password_hash: str, now: float | None = None,
                    is_admin: bool = False) -> int:
        """Insert a user and return its id. A duplicate username raises sqlite3.IntegrityError."""
        with self._lock, self._db:
            cur = self._db.execute("INSERT INTO users (username, hash, created, is_admin) VALUES (?,?,?,?)",
                                   (username, password_hash, time.time() if now is None else now,
                                    1 if is_admin else 0))
            return int(cur.lastrowid)

    def bind_cert(self, subject: str, user_id: int, now: float | None = None) -> None:
        """Map a certificate subject (or `san:<entry>`) to a user. Re-binding replaces and un-revokes."""
        with self._lock, self._db:
            self._db.execute("INSERT INTO cert_bindings (subject, user_id, created, revoked_at) VALUES (?,?,?,NULL) "
                             "ON CONFLICT(subject) DO UPDATE SET user_id=excluded.user_id, "
                             "created=excluded.created, revoked_at=NULL",
                             (subject, user_id, time.time() if now is None else now))

    def revoke_cert(self, subject: str, now: float | None = None) -> bool:
        with self._lock, self._db:
            cur = self._db.execute("UPDATE cert_bindings SET revoked_at=? WHERE subject=? AND revoked_at IS NULL",
                                   (time.time() if now is None else now, subject))
            return cur.rowcount > 0

    def list_cert_bindings(self) -> list[dict]:
        return self._rows("SELECT b.subject, u.username, b.created, b.revoked_at FROM cert_bindings b "
                          "JOIN users u ON u.id = b.user_id ORDER BY b.subject")

    def find_cert_user(self, subject: str) -> dict | None:
        """The enabled user bound to a subject by an unrevoked binding, or None."""
        rows = self._rows("SELECT u.id, u.username, u.is_admin FROM cert_bindings b JOIN users u ON u.id = b.user_id "
                          "WHERE b.subject = ? AND b.revoked_at IS NULL AND u.disabled = 0", (subject,))
        return rows[0] if rows else None

    def get_user(self, username: str) -> dict | None:
        rows = self._rows("SELECT id, username, hash, disabled, failed_count, locked_until, created, is_admin "
                          "FROM users WHERE username = ?", (username,))
        return rows[0] if rows else None

    def record_login_failure(self, username: str, max_failures: int, lock_seconds: float,
                             now: float | None = None) -> dict | None:
        """Count a failed login. Reaching max_failures sets locked_until and restarts the count.
        Returns the updated user row, or None for an unknown user."""
        now = time.time() if now is None else now
        with self._lock, self._db:
            row = self._db.execute("SELECT failed_count FROM users WHERE username = ?", (username,)).fetchone()
            if row is None:
                return None
            count = row[0] + 1
            if count >= max_failures:
                self._db.execute("UPDATE users SET failed_count = 0, locked_until = ? WHERE username = ?",
                                 (now + lock_seconds, username))
            else:
                self._db.execute("UPDATE users SET failed_count = ? WHERE username = ?", (count, username))
        return self.get_user(username)

    def set_password_hash(self, username: str, password_hash: str) -> None:
        with self._lock, self._db:
            self._db.execute("UPDATE users SET hash = ? WHERE username = ?", (password_hash, username))

    def reset_failures(self, username: str) -> None:
        with self._lock, self._db:
            self._db.execute("UPDATE users SET failed_count = 0, locked_until = NULL WHERE username = ?",
                             (username,))

    def count_users(self) -> int:
        return int(self._rows("SELECT COUNT(*) AS n FROM users")[0]["n"])

    def set_user_disabled(self, username: str, disabled: bool) -> bool:
        """Disable or enable a user. Returns False for an unknown user. A disabled user's sessions stop working at once."""
        with self._lock, self._db:
            return self._db.execute("UPDATE users SET disabled = ? WHERE username = ?",
                                    (1 if disabled else 0, username)).rowcount > 0

    def set_user_admin(self, username: str, is_admin: bool) -> bool:
        """Grant or revoke the admin flag. Returns False for an unknown user."""
        with self._lock, self._db:
            return self._db.execute("UPDATE users SET is_admin = ? WHERE username = ?",
                                    (1 if is_admin else 0, username)).rowcount > 0

    def revoke_user_sessions(self, username: str) -> int:
        """Revoke every live session of a user. Returns how many were revoked."""
        with self._lock, self._db:
            return self._db.execute(
                "UPDATE sessions SET revoked = 1 WHERE revoked = 0 AND user_id = "
                "(SELECT id FROM users WHERE username = ?)", (username,)).rowcount

    def list_api_keys(self) -> list[dict]:
        """Every key without its secret or hash, newest first."""
        rows = self._rows("SELECT id, prefix, scopes, owner, host, created, revoked_at, last_used "
                          "FROM api_keys ORDER BY id DESC")
        for r in rows:
            r["scopes"] = json.loads(r["scopes"])
        return rows

    def create_session(self, user_id: int, ttl_s: float, now: float | None = None) -> str:
        """Create a session and return the random token. Only its hash is stored."""
        now = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        with self._lock, self._db:
            self._db.execute("INSERT INTO sessions (id_hash, user_id, created, expires, last_seen, revoked) "
                             "VALUES (?,?,?,?,?,0)", (self._digest(token), user_id, now, now + ttl_s, now))
        return token

    def get_session(self, token: str, now: float | None = None) -> dict | None:
        """Return the live session with its username, or None if unknown, revoked, expired,
        or the user is disabled. Updates last_seen."""
        now = time.time() if now is None else now
        h = self._digest(token)
        with self._lock, self._db:
            cur = self._db.execute(
                "SELECT s.id_hash, s.user_id, u.username, u.is_admin, s.created, s.expires, s.last_seen FROM sessions s "
                "JOIN users u ON u.id = s.user_id "
                "WHERE s.id_hash = ? AND s.revoked = 0 AND s.expires > ? AND u.disabled = 0", (h, now))
            row = cur.fetchone()
            if row is None:
                return None
            out = dict(zip([c[0] for c in cur.description], row))
            self._db.execute("UPDATE sessions SET last_seen = ? WHERE id_hash = ?", (now, h))
            out["last_seen"] = now
            return out

    def revoke_session(self, token: str) -> bool:
        with self._lock, self._db:
            return self._db.execute("UPDATE sessions SET revoked = 1 WHERE id_hash = ? AND revoked = 0",
                                    (self._digest(token),)).rowcount > 0

    def create_api_key(self, scopes: list[str], owner: str, now: float | None = None,
                       host: str | None = None) -> tuple[str, dict]:
        """Create a key. Returns (full key, row). The full key is shown once and is not recoverable."""
        now = time.time() if now is None else now
        prefix = secrets.token_hex(4)
        full = f"hw_{prefix}_{secrets.token_urlsafe(32)}"
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT INTO api_keys (prefix, hash, scopes, owner, host, created) VALUES (?,?,?,?,?,?)",
                (prefix, self._digest(full), json.dumps(sorted(scopes)), owner, host, now))
            key_id = int(cur.lastrowid)
        return full, {"id": key_id, "prefix": prefix, "scopes": sorted(scopes), "owner": owner,
                      "host": host, "created": now, "revoked_at": None, "last_used": None}

    def find_api_key(self, key: str, now: float | None = None) -> dict | None:
        """Return the active key row for a presented key, or None if unknown or revoked.
        A revoked key stops matching on the very next call. Updates last_used."""
        now = time.time() if now is None else now
        parts = key.split("_", 2)
        if len(parts) != 3 or parts[0] != "hw":
            return None
        with self._lock, self._db:
            cur = self._db.execute("SELECT id, prefix, hash, scopes, owner, host, created, revoked_at, last_used "
                                   "FROM api_keys WHERE prefix = ? AND revoked_at IS NULL", (parts[1],))
            row = cur.fetchone()
            if row is None:
                return None
            out = dict(zip([c[0] for c in cur.description], row))
            if not secrets.compare_digest(out.pop("hash"), self._digest(key)):
                return None
            self._db.execute("UPDATE api_keys SET last_used = ? WHERE id = ?", (now, out["id"]))
            out["last_used"] = now
            out["scopes"] = json.loads(out["scopes"])
            return out

    def classify_api_key_failure(self, key: str) -> tuple[str | None, str]:
        """Explain why a presented key was rejected. Returns (prefix, reason). The prefix is
        non-secret and is returned only when it matches a stored key; reason is unknown, revoked
        or bad_secret. Does not touch last_used."""
        parts = key.split("_", 2)
        if len(parts) != 3 or parts[0] != "hw":
            return None, "unknown"
        with self._lock:
            rows = self._db.execute("SELECT revoked_at FROM api_keys WHERE prefix = ?", (parts[1],)).fetchall()
        if not rows:
            return None, "unknown"
        if any(r[0] is None for r in rows):
            return parts[1], "bad_secret"
        return parts[1], "revoked"

    def revoke_api_key(self, key_id: int, now: float | None = None) -> bool:
        with self._lock, self._db:
            return self._db.execute("UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                                    (time.time() if now is None else now, key_id)).rowcount > 0

    def revoke_api_keys_by_owner(self, owner: str, now: float | None = None) -> int:
        """Revoke every active key held by an owner. Returns how many were revoked."""
        with self._lock, self._db:
            return self._db.execute("UPDATE api_keys SET revoked_at = ? WHERE owner = ? AND revoked_at IS NULL",
                                    (time.time() if now is None else now, owner)).rowcount

    def append_audit(self, actor: str, kind: str, method: str, path: str, status: int, remote: str,
                     detail: dict | None = None, now: float | None = None) -> int:
        """Append one audit row. There is deliberately no update or delete method, and triggers
        abort UPDATE and DELETE. This is application-layer protection, not tamper-proofing.
        The path is sanitised here so every writer gets the same protection."""
        path = sanitize_audit_path(path)
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT INTO audit_log (ts, actor, kind, method, path, status, remote, detail) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (time.time() if now is None else now, actor, kind, method, path, status, remote,
                 json.dumps(detail or {}, sort_keys=True)))
            return int(cur.lastrowid)

    def prune_audit(self, retention_days: int, now: float | None = None) -> int:
        """Delete audit rows older than the retention window and record the prune.

        This is the only code path that deletes audit rows. It drops the delete trigger,
        deletes, recreates the trigger and appends one audit row (kind audit_prune) stating
        the count and cutoff, all in one transaction, so a failure rolls everything back and
        the trigger stays in place. SQLite DDL is transactional. A window of 0 keeps every
        row. Returns the number of rows pruned. Nothing is recorded when no row is old enough."""
        if retention_days <= 0:
            return 0
        now = time.time() if now is None else now
        cutoff = now - retention_days * 86400
        with self._lock:
            self._db.execute("BEGIN")
            try:
                if not self._db.execute("SELECT 1 FROM audit_log WHERE ts < ? LIMIT 1", (cutoff,)).fetchone():
                    self._db.execute("ROLLBACK")
                    return 0
                self._db.execute("DROP TRIGGER audit_log_no_delete")
                pruned = self._db.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,)).rowcount
                self._db.execute(AUDIT_NO_DELETE_SQL)
                self._db.execute(
                    "INSERT INTO audit_log (ts, actor, kind, method, path, status, remote, detail) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (now, "system", "audit_prune", "PRUNE", "audit_log", 200, "local",
                     json.dumps({"pruned": pruned, "cutoff": cutoff, "retention_days": retention_days},
                                sort_keys=True)))
                self._db.execute("COMMIT")
                return pruned
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def audit_rows(self, limit: int = 100, kind: str | None = None, actor: str | None = None,
                   before_id: int | None = None, since: float | None = None,
                   until: float | None = None) -> list[dict]:
        """Newest first. `since` is inclusive and `until` is exclusive, both in epoch seconds."""
        where, params = [], []
        if since is not None:
            where.append("ts >= ?")
            params.append(since)
        if until is not None:
            where.append("ts < ?")
            params.append(until)
        for col, val in (("kind", kind), ("actor", actor)):
            if val is not None:
                where.append(f"{col} = ?")
                params.append(val)
        if before_id is not None:
            where.append("id < ?")
            params.append(before_id)
        rows = self._rows("SELECT id, ts, actor, kind, method, path, status, remote, detail FROM audit_log"
                          + (" WHERE " + " AND ".join(where) if where else "")
                          + " ORDER BY id DESC LIMIT ?", (*params, limit))
        for r in rows:
            r["detail"] = json.loads(r["detail"])
        return rows

    @staticmethod
    def _event_rows(host: str, events: list[dict]) -> list[tuple]:
        return [(host, e["ts"], e["kind"], e["severity"], e["source"], e["title"],
                 json.dumps(e.get("detail", {}), sort_keys=True), e["dedup_key"], e.get("boot_id"))
                for e in events]

    _INSERT_EVENT = ("INSERT INTO events (host, ts, kind, severity, source, title, detail, dedup_key, boot_id) "
                     "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(host, dedup_key) DO NOTHING")

    def add_events(self, host: str, events: list[dict]) -> int:
        """Insert events, ignoring any whose (host, dedup_key) already exists. Returns rows inserted."""
        rows = self._event_rows(host, events)
        with self._lock, self._db:
            before = self._db.total_changes
            self._db.executemany(self._INSERT_EVENT, rows)
            return self._db.total_changes - before

    def event_by_key(self, host: str, dedup_key: str) -> dict | None:
        """The stored event with this dedup key for the host, or None."""
        rows = self._rows("SELECT id, host, ts, kind, severity, source, title, detail, dedup_key, boot_id "
                          "FROM events WHERE host = ? AND dedup_key = ?", (host, dedup_key))
        if not rows:
            return None
        rows[0]["detail"] = json.loads(rows[0]["detail"])
        return rows[0]

    def merge_event_detail(self, host: str, dedup_key: str, patch: dict) -> bool:
        """Add top-level keys to a stored event's detail. Existing keys are kept unless the patch
        names them. False when the event does not exist. No schema change: detail is JSON text."""
        with self._lock, self._db:
            row = self._db.execute("SELECT id, detail FROM events WHERE host = ? AND dedup_key = ?",
                                   (host, dedup_key)).fetchone()
            if row is None:
                return False
            merged = {**json.loads(row[1]), **patch}
            self._db.execute("UPDATE events SET detail = ? WHERE id = ?", (json.dumps(merged, sort_keys=True), row[0]))
            return True

    def events_in_window(self, host: str, kinds: tuple[str, ...], lo: float, hi: float) -> list[dict]:
        """Every event of the given kinds for the host with lo <= ts <= hi, oldest first. The
        filter runs in SQL and there is deliberately no row cap, so unrelated newer events cannot
        hide one."""
        marks = ",".join("?" for _ in kinds)
        with self._lock:
            cur = self._db.execute(
                "SELECT id, host, ts, kind, severity, source, title, detail, dedup_key, boot_id FROM events "
                f"WHERE host = ? AND kind IN ({marks}) AND ts >= ? AND ts <= ? ORDER BY ts, id",
                (host, *kinds, lo, hi))
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            r["detail"] = json.loads(r["detail"])
        return rows

    def pending_witness_events(self) -> list[dict]:
        """Boot events whose last power witness assessment was incomplete and still awaits a retry."""
        with self._lock:
            cur = self._db.execute(
                "SELECT id, host, ts, kind, severity, source, title, detail, dedup_key, boot_id FROM events "
                "WHERE source = 'boot' AND json_extract(detail, '$.power_witness.retry_pending') = 1 ORDER BY id")
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            r["detail"] = json.loads(r["detail"])
        return rows

    def boot_events(self, host: str, boot_id: str) -> list[dict]:
        """Boot events stored for the host and boot id."""
        rows = self._rows("SELECT id, host, ts, kind, severity, source, title, detail, dedup_key, boot_id "
                          "FROM events WHERE host = ? AND boot_id = ? AND source = 'boot' ORDER BY id",
                          (host, boot_id))
        for r in rows:
            r["detail"] = json.loads(r["detail"])
        return rows

    def events(self, host: str | None = None, since: float | None = None,
               kind: str | None = None, limit: int = 100, source: str | None = None,
               before: float | None = None, before_id: int | None = None) -> list[dict]:
        """Newest first. `before` pages backwards: only rows older than that ts. When
        several rows share the cursor ts, `before_id` (the id of the last row seen)
        keeps the rest of them from being skipped. All values are bound parameters."""
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
        if source:
            where.append("source = ?")
            params.append(source)
        if before is not None:
            if before_id is not None:
                where.append("(ts < ? OR (ts = ? AND id < ?))")
                params.extend([before, before, before_id])
            else:
                where.append("ts < ?")
                params.append(before)
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

    def ack_event(self, event_id: int, actor: str, now: float | None = None) -> bool:
        """Record that an operator acknowledged an event. False when the event does not exist.
        A repeat acknowledgement keeps the first one."""
        with self._lock, self._db:
            if self._db.execute("SELECT 1 FROM events WHERE id = ?", (event_id,)).fetchone() is None:
                return False
            self._db.execute("INSERT OR IGNORE INTO event_acks (event_id, acked_at, actor) VALUES (?,?,?)",
                             (event_id, time.time() if now is None else now, actor))
            return True

    def acked_event_ids(self, ids: list[int]) -> set[int]:
        if not ids:
            return set()
        with self._lock:
            marks = ",".join("?" * len(ids))
            return {r[0] for r in self._db.execute(
                f"SELECT event_id FROM event_acks WHERE event_id IN ({marks})", ids)}

    def get_cursor(self, name: str) -> int | None:
        """The last events.id a publisher reported as sent, or None if it has never run."""
        with self._lock:
            row = self._db.execute("SELECT last_id FROM publish_cursors WHERE name = ?", (name,)).fetchone()
        return None if row is None else int(row[0])

    def set_cursor(self, name: str, last_id: int, now: float | None = None) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO publish_cursors (name, last_id, updated) VALUES (?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET last_id = excluded.last_id, updated = excluded.updated",
                (name, last_id, time.time() if now is None else now))

    def max_event_id(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])

    def events_after(self, last_id: int, sources: tuple[str, ...], limit: int = 100) -> list[dict]:
        """Events with id above `last_id` from the given sources, oldest id first."""
        marks = ",".join("?" for _ in sources)
        with self._lock:
            cur = self._db.execute(
                "SELECT id, host, ts, kind, severity, source, title, detail, boot_id FROM events "
                f"WHERE id > ? AND source IN ({marks}) ORDER BY id LIMIT ?", (last_id, *sources, limit))
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            r["detail"] = json.loads(r["detail"])
        return rows

    def ingest(self, batch: Batch) -> int:
        """Store a batch and return the number of samples stored (0 for a repeated batch_id)."""
        return self.ingest_batch(batch)[0]

    def ingest_batch(self, batch: Batch) -> tuple[int, int, bool]:
        """Store samples, source status, agent row, events and the batch id in one
        transaction. Returns (samples stored, events stored, duplicate). A batch_id
        already recorded for the host is acknowledged and nothing is stored again."""
        with self._lock, self._db:
            if batch.batch_id is not None:
                if self._db.execute("SELECT 1 FROM batch_ids WHERE host=? AND batch_id=?",
                                    (batch.host, batch.batch_id)).fetchone():
                    return 0, 0, True
                self._db.execute("INSERT INTO batch_ids VALUES (?,?,?)", (batch.host, batch.batch_id, time.time()))
            rows = [(s.ts, batch.host, s.source, s.metric, json.dumps(s.labels, sort_keys=True), s.value, s.unit)
                    for s in batch.samples]
            self._db.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?)", rows)
            self._db.executemany(
                "INSERT INTO sources (host, source, available, reason, updated, present) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(host, source) DO UPDATE SET available=excluded.available, "
                "reason=excluded.reason, updated=excluded.updated, present=excluded.present",
                [(batch.host, st.source, int(st.available), st.reason, batch.sent_at, int(st.present))
                 for st in batch.sources])
            self._db.executemany(
                "INSERT INTO source_seen (host, source, first_seen, last_seen) VALUES (?,?,?,?) "
                "ON CONFLICT(host, source) DO UPDATE SET last_seen=MAX(last_seen, excluded.last_seen), "
                "forgotten_at=NULL",
                [(batch.host, st.source, batch.sent_at, batch.sent_at) for st in batch.sources
                 if st.present and st.available])
            self._db.execute(
                "INSERT INTO agents VALUES (?,?,?,?) ON CONFLICT(host) DO UPDATE SET "
                "platform=excluded.platform, agent_version=excluded.agent_version, last_seen=excluded.last_seen",
                (batch.host, batch.platform, batch.agent_version, batch.sent_at))
            before = self._db.total_changes
            self._db.executemany(
                self._INSERT_EVENT, self._event_rows(batch.host, [e.model_dump() for e in batch.events]))
            return len(rows), self._db.total_changes - before, False

    def add_sample(self, host: str, source: str, metric: str, value: float | None, unit: str,
                   labels: dict[str, str], ts: float) -> None:
        """Store one hub-side sample (the wall power reading). A value of None is stored as
        unavailable, never as zero."""
        with self._lock, self._db:
            self._db.execute("INSERT INTO samples VALUES (?,?,?,?,?,?,?)",
                             (ts, host, source, metric, json.dumps(labels, sort_keys=True), value, unit))

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
            cur = self._db.execute("SELECT host, source, available, reason, updated, present FROM sources ORDER BY host, source")
            return [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]

    def source_seen(self, host: str | None = None) -> list[dict]:
        """When each source was first and last seen present and available, and when it was forgotten."""
        sql = "SELECT host, source, first_seen, last_seen, forgotten_at FROM source_seen"
        if host is not None:
            return self._rows(sql + " WHERE host = ? ORDER BY source", (host,))
        return self._rows(sql + " ORDER BY host, source")

    def forget_source(self, host: str, source: str, now: float | None = None) -> bool:
        """Record that the operator removed a source on purpose, so present false reads as absent
        again. Returns False when the host never had that source seen present and available.
        A later present and available report clears the mark."""
        with self._lock, self._db:
            return self._db.execute(
                "UPDATE source_seen SET forgotten_at = ? WHERE host = ? AND source = ?",
                (time.time() if now is None else now, host, source)).rowcount > 0

    def agents(self) -> list[dict]:
        with self._lock:
            cur = self._db.execute("SELECT host, platform, agent_version, last_seen FROM agents ORDER BY host")
            return [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]

    def _hourly_sql(self, host: str, source: str, metric: str, lo: float, until: float) -> tuple[str, tuple]:
        """SQL and parameters for hourly rows: stored rollups plus raw samples newer than the last rollup.

        Raw samples are only read from the hour after the newest stored rollup hour, so an hour
        is never counted twice. Call with the lock held."""
        last = self._db.execute(
            "SELECT MAX(hour) FROM rollup_hourly WHERE host = ? AND source = ? AND metric = ? "
            "AND hour >= ? AND hour < ? AND n > 0", (host, source, metric, lo, until)).fetchone()[0]
        raw_lo = lo if last is None else max(lo, last + 3600.0)
        sql = ("SELECT hour, labels, n, vmin, vavg, vmax, unit FROM rollup_hourly "
               "WHERE host = ? AND source = ? AND metric = ? AND hour >= ? AND hour < ? AND n > 0 "
               "UNION ALL "
               "SELECT ts - (ts % 3600), labels, COUNT(value), MIN(value), AVG(value), MAX(value), unit FROM samples "
               "WHERE host = ? AND source = ? AND metric = ? AND ts >= ? AND ts < ? AND value IS NOT NULL "
               "GROUP BY ts - (ts % 3600), labels")
        return sql, (host, source, metric, lo, until, host, source, metric, raw_lo, until)

    def gaps(self, host: str, source: str, metric: str, since: float, max_gap_s: float,
             until: float | None = None, raw_max_s: float = HISTORY_RAW_MAX_S) -> list[tuple[float, float]]:
        """Return (start, end) intervals longer than max_gap_s with no non-NULL sample. Used by the Phase 1 exit test.

        A range longer than raw_max_s is computed from the same combined hourly series that
        history shows, so its points are hour starts."""
        end = time.time() + 1.0 if until is None else until
        with self._lock:
            if end - since > raw_max_s:
                lo = since - (since % 3600)
                sql, params = self._hourly_sql(host, source, metric, lo, end)
                ts = [r[0] for r in self._db.execute(f"SELECT DISTINCT hour FROM ({sql}) ORDER BY hour", params)]
            else:
                ts = [r[0] for r in self._db.execute(
                    "SELECT DISTINCT ts FROM samples WHERE host=? AND source=? AND metric=? AND ts>=? "
                    "AND value IS NOT NULL ORDER BY ts", (host, source, metric, since))]
        return [(a, b) for a, b in zip(ts, ts[1:]) if b - a > max_gap_s]

    def history(self, host: str, source: str, metric: str, since: float, until: float, step: float,
                raw_max_s: float = HISTORY_RAW_MAX_S, limit: int = 100000) -> dict:
        """Min, average and maximum per step bucket, one series per label set.

        A range no longer than raw_max_s reads the samples table. A longer range reads
        rollup_hourly plus hourly aggregates of raw samples newer than the last
        rollup, so it has hour resolution and the step is raised to a whole number of hours. Unavailable samples (NULL value) never enter the math. All SQL is
        parameterized. At most limit buckets are returned, oldest first."""
        use_rollup = (until - since) > raw_max_s
        if use_rollup:
            step = max(3600.0, 3600.0 * round(step / 3600.0))
            # Whole hours only: a rollup hour that starts before since is partly outside the range.
            lo = since - (since % 3600)
        else:
            sql = ("SELECT labels, CAST(ts / ? AS INTEGER) AS b, MIN(value), AVG(value), MAX(value), "
                   "COUNT(value), MAX(unit) FROM samples "
                   "WHERE host = ? AND source = ? AND metric = ? AND ts >= ? AND ts < ? AND value IS NOT NULL "
                   "GROUP BY labels, b ORDER BY labels, b LIMIT ?")
            lo = since
        with self._lock:
            if use_rollup:
                inner, iparams = self._hourly_sql(host, source, metric, lo, until)
                sql = ("SELECT labels, CAST(hour / ? AS INTEGER) AS b, MIN(vmin), SUM(vavg * n) / SUM(n), MAX(vmax), "
                       f"SUM(n), MAX(unit) FROM ({inner}) GROUP BY labels, b ORDER BY labels, b LIMIT ?")
                rows = self._db.execute(sql, (step, *iparams, limit)).fetchall()
            else:
                rows = self._db.execute(sql, (step, host, source, metric, lo, until, limit)).fetchall()
        series: dict[str, dict] = {}
        unit = ""
        for labels, b, vmin, vavg, vmax, n, u in rows:
            unit = u or unit
            entry = series.setdefault(labels, {"labels": json.loads(labels), "points": []})
            entry["points"].append({"ts": b * step, "min": vmin, "avg": vavg, "max": vmax, "n": n})
        return {"host": host, "source": source, "metric": metric, "unit": unit,
                "resolution": "rollup" if use_rollup else "raw", "step": step,
                "since": since, "until": until, "series": list(series.values())}

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
            self._db.execute("DELETE FROM batch_ids WHERE received < ?", (cutoff,))
            self._db.execute("DELETE FROM rollup_hourly WHERE hour < ?", (time.time() - rollup_days * 86400,))
