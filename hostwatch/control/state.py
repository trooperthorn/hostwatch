"""Persisted replay state: the highest sequence number executed and recent command ids.

The file is written to a temporary name, flushed to disk and renamed over the old one, so a
crash leaves either the old state or the new state, never a torn file. A file that exists but
cannot be parsed raises `StateError`. The caller treats that as a refusal of every command:
guessing a fresh state would let an old signed command run again.

Rollback protection: the state carries a generation number and a keyed checksum (HMAC-SHA256),
and a second file, the anchor, repeats the generation with its own checksum. The state is written
first and the anchor second. A state file restored from an older copy has a lower generation than
the anchor, or a checksum that does not match, and is refused. A state with a missing or
mismatched anchor, a missing state beside an anchor, and a state with no checksum are all errors
(fail closed). Only a folder with neither file is a fresh start. The check cannot detect a restore
of both files together; that needs a copy kept off the host.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

STATE_FILE = "control-state.json"
ANCHOR_SUFFIX = ".anchor"
MAX_IDS = 1000
# Used only when the caller gives no secret (tests); the daemon passes a key derived from its control key.
DEFAULT_KEY = b"hostwatch-control-state-v1"


class StateError(Exception):
    """The state file is unreadable, invalid or cannot be written."""


def derive_key(secret: str | bytes) -> bytes:
    """A state checksum key from the control key, so the checksum is not forgeable without it."""
    raw = secret.encode("utf-8") if isinstance(secret, str) else secret
    return hmac.new(raw, b"hostwatch-control-replay-state-v1", hashlib.sha256).digest()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class ReplayState:
    def __init__(self, path: str | Path, key: bytes | None = None):
        self.path = Path(path)
        self.anchor_path = self.path.with_name(self.path.name + ANCHOR_SUFFIX)
        self._key = key if key is not None else DEFAULT_KEY
        self.last_seq: int | None = None
        self.ids: list[str] = []
        self.generation = 0
        self._load()

    def _mac(self, *parts: object) -> str:
        body = json.dumps(list(parts), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self._key, body, hashlib.sha256).hexdigest()

    def _read(self, path: Path) -> dict | None:
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StateError(f"cannot read {path}: {exc}") from exc
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise StateError(f"{path} is corrupt: {exc}") from exc
        if not isinstance(data, dict):
            raise StateError(f"{path} is corrupt: not an object")
        return data

    def _load(self) -> None:
        data, anchor = self._read(self.path), self._read(self.anchor_path)
        if data is None and anchor is None:
            return
        if data is None:
            raise StateError(f"{self.path} is missing but {self.anchor_path} exists; the state was removed")
        try:
            last, ids, gen, mac = data["last_seq"], data["ids"], data["gen"], data["mac"]
        except KeyError as exc:
            raise StateError(f"{self.path} is corrupt or has no checksum: missing {exc}") from exc
        last_ok = last is None or _is_int(last)
        if not (last_ok and isinstance(ids, list) and all(isinstance(i, str) for i in ids)
                and _is_int(gen) and isinstance(mac, str)):
            raise StateError(f"{self.path} is corrupt: unexpected field types")
        if not hmac.compare_digest(mac, self._mac(last, ids, gen)):
            raise StateError(f"{self.path} failed its checksum; it was edited or the control key changed")
        if anchor is None:
            raise StateError(f"{self.anchor_path} is missing; the state may have been restored from a copy")
        agen, amac = anchor.get("gen"), anchor.get("mac")
        if not _is_int(agen) or not isinstance(amac, str):
            raise StateError(f"{self.anchor_path} is corrupt: unexpected field types")
        if agen > gen:
            raise StateError(f"{self.path} is older than the anchor (generation {gen}, expected {agen}); "
                             "an earlier state was restored")
        # A crash between the two writes leaves the state one generation ahead of the anchor, which is fine.
        if agen == gen and not hmac.compare_digest(amac, self._mac("anchor", agen, mac)):
            raise StateError(f"{self.anchor_path} does not match {self.path}")
        self.last_seq, self.ids, self.generation = last, ids, gen
    def seen(self, command_id: str) -> bool:
        return command_id in self.ids

    def seq_ok(self, seq: int) -> bool:
        return self.last_seq is None or seq > self.last_seq

    def _write(self, path: Path, payload: dict) -> None:
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(json.dumps(payload, sort_keys=True).encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def record(self, command_id: str, seq: int) -> None:
        """Persist the command, then update memory. A failed write leaves memory unchanged."""
        ids = (self.ids + [command_id])[-MAX_IDS:]
        gen = self.generation + 1
        mac = self._mac(seq, ids, gen)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._write(self.path, {"last_seq": seq, "ids": ids, "gen": gen, "mac": mac})
            self._write(self.anchor_path, {"gen": gen, "mac": self._mac("anchor", gen, mac)})
        except OSError as exc:
            raise StateError(f"cannot write {self.path}: {exc}") from exc
        self.last_seq, self.ids, self.generation = seq, ids, gen
