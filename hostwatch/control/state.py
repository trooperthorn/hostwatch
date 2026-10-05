"""Persisted replay state: the highest sequence number executed and recent command ids.

The file is written to a temporary name, flushed to disk and renamed over the old one, so a
crash leaves either the old state or the new state, never a torn file. A file that exists but
cannot be parsed raises `StateError`. The caller treats that as a refusal of every command:
guessing a fresh state would let an old signed command run again.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

STATE_FILE = "control-state.json"
MAX_IDS = 1000


class StateError(Exception):
    """The state file is unreadable, invalid or cannot be written."""


class ReplayState:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.last_seq: int | None = None
        self.ids: list[str] = []
        self._load()

    def _load(self) -> None:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise StateError(f"cannot read {self.path}: {exc}") from exc
        try:
            data = json.loads(raw.decode("utf-8"))
            last, ids = data["last_seq"], data["ids"]
        except (ValueError, KeyError, TypeError) as exc:
            raise StateError(f"{self.path} is corrupt: {exc}") from exc
        last_ok = last is None or (isinstance(last, int) and not isinstance(last, bool) and last >= 0)
        if not (last_ok and isinstance(ids, list) and all(isinstance(i, str) for i in ids)):
            raise StateError(f"{self.path} is corrupt: unexpected field types")
        self.last_seq, self.ids = last, ids

    def seen(self, command_id: str) -> bool:
        return command_id in self.ids

    def seq_ok(self, seq: int) -> bool:
        return self.last_seq is None or seq > self.last_seq

    def record(self, command_id: str, seq: int) -> None:
        """Persist the command, then update memory. A failed write leaves memory unchanged."""
        ids = (self.ids + [command_id])[-MAX_IDS:]
        payload = json.dumps({"last_seq": seq, "ids": ids}, sort_keys=True).encode("utf-8")
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except OSError as exc:
            raise StateError(f"cannot write {self.path}: {exc}") from exc
        self.last_seq, self.ids = seq, ids
