"""Read-only pstore ingestion.

The pstore directory (default /host/pstore) holds crash records the kernel left
for the next boot. Each record file becomes one event. The files are only read,
never deleted or modified, so the host keeps its own copy of the evidence.

The dedup key is the file name plus a hash of the whole content, so reading the same
record again gives the same key and Observe keeps one row. A record that is
rewritten with different content gets a new key. The exact file names and the
record layout are not confirmed on hardware; see UNVERIFIED.md.
"""

from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path

from ..model import Event, SourceStatus

SOURCE = "pstore"
MAX_READ_BYTES = 1024 * 1024
CHUNK_BYTES = 64 * 1024
EXCERPT_CHARS = 400

PANIC = "pstore.kernel_panic"
OOPS = "pstore.kernel_oops"
RECORD = "pstore.record"


_PANIC_RE = re.compile(r"Kernel panic - not syncing|^[ \t]*Panic#\d+\b", re.MULTILINE)
_OOPS_RE = re.compile(
    r"^[ \t]*(?:\[[ \d.]+\][ \t]*)?(?:Oops#\d+\b|(?:BUG|Oops)\b:)", re.MULTILINE)


def classify_record(name: str, text: str) -> tuple[str, str]:
    """Return (kind, severity). Only dmesg-* files are searched, and only for
    explicit markers: a panic message or Panic#N header, an Oops#N header, or a
    line that starts with BUG: or Oops:. Anything else is a generic record."""
    if not name.startswith("dmesg-"):
        return RECORD, "warning"
    if _PANIC_RE.search(text):
        return PANIC, "critical"
    if _OOPS_RE.search(text):
        return OOPS, "critical"
    return RECORD, "warning"


def _read_file(path: Path) -> tuple[bytes, bytes, int, str]:
    """Return (head, tail, size, sha256 of the whole file), reading in chunks."""
    h = hashlib.sha256()
    head = b""
    tail = b""
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_BYTES)
            if not chunk:
                break
            h.update(chunk)
            if size < MAX_READ_BYTES:
                head += chunk[:MAX_READ_BYTES - size]
            tail = (tail + chunk)[-MAX_READ_BYTES:]
            size += len(chunk)
    return head, tail, size, h.hexdigest()[:16]


def read_pstore(root: Path) -> tuple[SourceStatus, list[Event]]:
    """Read every regular record file under root. Symlinks are skipped. A
    missing or unreadable directory, or a directory whose records all failed to
    read, is reported unavailable with a reason."""
    try:
        entries = sorted(root.iterdir())
    except FileNotFoundError:
        return SourceStatus(source=SOURCE, available=False, reason=f"{root} does not exist"), []
    except OSError as exc:
        return SourceStatus(source=SOURCE, available=False, reason=f"cannot read {root}: {exc}"), []
    events: list[Event] = []
    skipped = 0
    attempted = 0
    for path in entries:
        try:
            st = path.lstat()
        except OSError:
            attempted += 1
            skipped += 1
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        attempted += 1
        try:
            head, tail, size, digest = _read_file(path)
        except OSError:
            skipped += 1
            continue
        truncated = size > MAX_READ_BYTES
        text = head.decode("utf-8", errors="replace")
        scan = text
        if truncated:
            scan = text + chr(10) + tail.decode("utf-8", errors="replace")
        kind, severity = classify_record(path.name, scan)
        events.append(Event(
            kind=kind, severity=severity, source=SOURCE, ts=st.st_mtime,
            title=f"pstore record {path.name}",
            detail={"file": path.name, "size_bytes": size, "sha256_16": digest,
                    "truncated": truncated, "excerpt": text[:EXCERPT_CHARS]},
            dedup_key=f"pstore:{path.name}:{digest}"))
    if attempted and skipped == attempted:
        return SourceStatus(
            source=SOURCE, available=False,
            reason=f"all {attempted} record file(s) could not be read"), []
    reason = f"{skipped} record file(s) could not be read" if skipped else ""
    return SourceStatus(source=SOURCE, available=True, reason=reason), events
