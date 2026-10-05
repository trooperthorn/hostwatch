"""The monitoring app is called Observe; its former name must not appear in tracked files."""
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FORMER_NAME = "watch" + "post"


def test_the_former_app_name_appears_nowhere_in_tracked_files():
    try:
        names = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git is not available, so the tracked file list cannot be read")
    hits = []
    for name in names:
        if FORMER_NAME in name.lower():
            hits.append(name)
            continue
        path = ROOT / name
        if not path.is_file():
            continue
        if FORMER_NAME.encode() in path.read_bytes().lower():
            hits.append(name)
    assert hits == []
