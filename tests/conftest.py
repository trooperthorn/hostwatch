"""Fixtures build fake sysfs/procfs trees so collectors are tested against
known values without real hardware."""

from __future__ import annotations

from pathlib import Path

import pytest


def write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


@pytest.fixture
def fs(tmp_path):
    sysfs, procfs = tmp_path / "sys", tmp_path / "proc"
    sysfs.mkdir(); procfs.mkdir()
    return sysfs, procfs, write
