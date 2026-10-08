"""Persisted replay state: the highest sequence number executed and recent command ids.

The file is written to a temporary name, flushed to disk and renamed over the old one, so a
crash leaves either the old state or the new state, never a torn file. A file that exists but
cannot be parsed raises `StateError`. The caller treats that as a refusal of every command:
guessing a fresh state would let an old signed command run again.

Rollback protection: the state carries a generation number and a keyed checksum (HMAC-SHA256),
and a second file, the anchor, repeats the generation with its own checksum. The state is written
first and the anchor second. A state file restored from an older copy has a lower generation than
the anchor, or a checksum that does not match, and is refused. The anchor must be at the
state's generation (its checksum then binds it to the state) or exactly one behind (a crash between
the two writes; its keyed generation checksum is still checked). Any other anchor, a missing or
mismatched anchor, a missing state beside an anchor, and a state with no checksum are all errors
(fail closed). Only a folder with neither file is a fresh start. The check cannot detect a restore
of both files together; that needs a copy kept off the host.

Format versions. Version 1 (the first release) was `{"last_seq", "ids"}` with no checksum. Version 2
adds `v`, `gen` and `mac`, and the anchor file. A version 1 file is never trusted silently: loading it
raises `LegacyStateError`, which names the file and the operator command that upgrades it
(`python -m hostwatch control state-upgrade`). `migrate_legacy` keeps its `last_seq` and ids, so replay
protection survives the upgrade. A file with a higher version than this code knows is refused.
`reset_state` is the operator-run last resort when the key was changed or the host fell far behind.
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
STATE_VERSION = 2
UPGRADE_HINT = "python -m hostwatch control state-upgrade"
RESET_HINT = "python -m hostwatch control state-reset --yes [--last-seq N]"


class StateError(Exception):
    """The state file is unreadable, invalid or cannot be written."""


class LegacyStateError(StateError):
    """The state file is the unchecked version 1 format and must be upgraded by the operator."""


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
        if "gen" not in data and "mac" not in data and "v" not in data and "last_seq" in data and "ids" in data:
            raise LegacyStateError(f"{self.path} is in the old unchecked format (version 1); stop the service and run "
                                   f"`{UPGRADE_HINT}` once to upgrade it and keep its replay protection")
        version = data.get("v", STATE_VERSION)
        if not _is_int(version) or version > STATE_VERSION:
            raise StateError(f"{self.path} has format version {version!r}, which this build does not understand")
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
        if agen == gen:
            if not hmac.compare_digest(amac, self._mac("anchor", agen, mac)):
                raise StateError(f"{self.anchor_path} does not match {self.path}")
        elif agen == gen - 1:
            # A crash between the two writes leaves the state one generation ahead. The anchor's own keyed
            # generation checksum still has to be right, so an unkeyed anchor cannot hide a restored state.
            gmac = anchor.get("gmac")
            if not isinstance(gmac, str) or not hmac.compare_digest(gmac, self._mac("anchor-gen", agen)):
                raise StateError(f"{self.anchor_path} failed its checksum")
        else:
            raise StateError(f"{self.anchor_path} (generation {agen}) does not follow {self.path} (generation {gen})")
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

    def _commit(self, seq: int | None, ids: list[str], gen: int) -> None:
        mac = self._mac(seq, ids, gen)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._write(self.path, {"v": STATE_VERSION, "last_seq": seq, "ids": ids, "gen": gen, "mac": mac})
            self._write(self.anchor_path, {"v": STATE_VERSION, "gen": gen, "mac": self._mac("anchor", gen, mac),
                                           "gmac": self._mac("anchor-gen", gen)})
        except OSError as exc:
            raise StateError(f"cannot write {self.path}: {exc}") from exc
        self.last_seq, self.ids, self.generation = seq, ids, gen

    def record(self, command_id: str, seq: int) -> None:
        """Persist the command, then update memory. A failed write leaves memory unchanged."""
        self._commit(seq, (self.ids + [command_id])[-MAX_IDS:], self.generation + 1)


def _bare(path: Path, key: bytes | None) -> ReplayState:
    """A ReplayState that has not read its files, for the operator tools below."""
    state = ReplayState.__new__(ReplayState)
    state.path = path
    state.anchor_path = path.with_name(path.name + ANCHOR_SUFFIX)
    state._key = key if key is not None else DEFAULT_KEY
    state.last_seq, state.ids, state.generation = None, [], 0
    return state


def migrate_legacy(path: str | Path, key: bytes | None = None) -> ReplayState:
    """Upgrade a version 1 state file in place, keeping its last_seq and ids. Operator-run only.

    Refuses anything that is not a plain version 1 file with no anchor beside it."""
    path = Path(path)
    state = _bare(path, key)
    data = state._read(path)
    if data is None:
        raise StateError(f"{path} does not exist; there is nothing to upgrade")
    if state._read(state.anchor_path) is not None or "gen" in data or "mac" in data or "v" in data:
        raise StateError(f"{path} is not an old format (version 1) state file; nothing to upgrade")
    last, ids = data.get("last_seq"), data.get("ids")
    if not ((last is None or _is_int(last)) and isinstance(ids, list) and all(isinstance(i, str) for i in ids)):
        raise StateError(f"{path} is corrupt: unexpected field types")
    state._commit(last, ids[-MAX_IDS:], 1)
    return ReplayState(path, key)


def reset_state(path: str | Path, key: bytes | None = None, last_seq: int | None = None) -> None:
    """Remove both state files, and optionally start again from a given baseline seq. Operator-run only.

    This throws away the replay history, so it is a last resort (a changed state key, or a host that
    fell more than the allowed seq jump behind). Giving `last_seq` keeps the seq-jump bound meaningful."""
    path = Path(path)
    if last_seq is not None and not _is_int(last_seq):
        raise StateError("last_seq must be a non-negative integer")
    for target in (path, path.with_name(path.name + ANCHOR_SUFFIX)):
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise StateError(f"cannot remove {target}: {exc}") from exc
    if last_seq is not None:
        _bare(path, key)._commit(last_seq, [], 1)
