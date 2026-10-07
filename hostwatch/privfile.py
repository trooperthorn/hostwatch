"""Private files for the agent's data directory.

On POSIX the outbox, the boot heartbeat and the liveness marker are created with mode 0600, so
another local account cannot read queued telemetry or the host's boot history. On Windows the
data directory's ACL is the control and these helpers do nothing beyond opening the file.
"""

from __future__ import annotations

import os
from pathlib import Path

PRIVATE_MODE = 0o600
_POSIX = os.name == "posix"


def ensure_private(path: Path) -> None:
    """Create `path` empty with mode 0600 if it is missing, and tighten it if it exists."""
    if not _POSIX:
        return
    fd = os.open(path, os.O_RDWR | os.O_CREAT, PRIVATE_MODE)
    try:
        os.fchmod(fd, PRIVATE_MODE)
    finally:
        os.close(fd)


def write_private(path: Path, data: str, fsync: bool = False) -> None:
    """Write text to `path`, creating it with mode 0600 on POSIX."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, PRIVATE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        if _POSIX:
            os.fchmod(fh.fileno(), PRIVATE_MODE)
        fh.write(data)
        fh.flush()
        if fsync:
            os.fsync(fh.fileno())
