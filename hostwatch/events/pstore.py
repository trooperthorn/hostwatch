"""Read-only pstore ingestion.

The pstore directory (default /host/pstore) holds crash records the kernel left
for the next boot. Each record file becomes one event. The files are only read,
never deleted or modified, so the host keeps its own copy of the evidence.

The dedup key is the file name plus a hash of the content, so reading the same
record again gives the same key and the hub keeps one row. A record that is
rewritten with different content gets a new key. The exact file names and the
record layout are not confirmed on hardware; see UNVERIFIED.md.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..schema import Event, SourceStatus

SOURCE = "pstore"
MAX_READ_BYTES = 1024 * 1024
EXCERPT_CHARS = 400

PANIC = "pstore.kernel_panic"
OOPS = "pstore.kernel_oops"
RECORD = "pstore.record"


def classify_record(name: str, text: str) -> tuple[str, str]:
    """Return (kind, severity). Only dmesg-* files are searched for a panic or
    oops marker; any other record type is kept as a generic record."""
    if not name.startswith("dmesg-"):
        return RECORD, "warning"
    lowered = text.lower()
    if "kernel panic" in lowered or "panic#" in lowered:
        return PANIC, "critical"
    if "oops" in lowered or "bug:" in lowered:
        return OOPS, "critical"
    return RECORD, "warning"


def read_pstore(root: Path) -> tuple[SourceStatus, list[Event]]:
    """Read every record file under root. A missing or unreadable directory is
    reported unavailable with a reason and gives no events."""
    try:
        entries = sorted(p for p in root.iterdir() if p.is_file())
    except FileNotFoundError:
        return SourceStatus(source=SOURCE, available=False, reason=f"{root} does not exist"), []
    except OSError as exc:
        return SourceStatus(source=SOURCE, available=False, reason=f"cannot read {root}: {exc}"), []
    events: list[Event] = []
    skipped = 0
    for path in entries:
        try:
            with open(path, "rb") as fh:
                data = fh.read(MAX_READ_BYTES)
            mtime = path.stat().st_mtime
        except OSError:
            skipped += 1
            continue
        text = data.decode("utf-8", errors="replace")
        kind, severity = classify_record(path.name, text)
        digest = hashlib.sha256(data).hexdigest()[:16]
        events.append(Event(
            kind=kind, severity=severity, source=SOURCE, ts=mtime,
            title=f"pstore record {path.name}",
            detail={"file": path.name, "size_bytes": len(data), "sha256_16": digest,
                    "excerpt": text[:EXCERPT_CHARS]},
            dedup_key=f"pstore:{path.name}:{digest}"))
    reason = f"{skipped} record file(s) could not be read" if skipped else ""
    return SourceStatus(source=SOURCE, available=True, reason=reason), events
