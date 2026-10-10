"""The installed hostwatch distribution as this interpreter sees it.

`agent.update` for the control component reports the version before and after `pip install`. The version
in pyproject.toml rarely changes between commits on the edge branch, so when pip recorded the git commit it
installed from (`direct_url.json` in the dist-info directory) the short commit id is added. The old value
is read in process by the running daemon; the new value is read by running the venv interpreter with
`-m hostwatch.control.installed` after the install, so it describes the code that will run next.
"""

from __future__ import annotations

import importlib.metadata
import json
import sys

DISTRIBUTION = "hostwatch"


def describe() -> str | None:
    """`<version>` or `<version> (<commit>)`, or None when hostwatch is not an installed distribution."""
    try:
        dist = importlib.metadata.distribution(DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError:
        return None
    version = dist.version
    commit = None
    try:
        raw = dist.read_text("direct_url.json")
        info = json.loads(raw) if raw else None
    except (OSError, ValueError):
        info = None
    if isinstance(info, dict):
        vcs = info.get("vcs_info")
        if isinstance(vcs, dict) and isinstance(vcs.get("commit_id"), str) and vcs["commit_id"]:
            commit = vcs["commit_id"][:12]
    return f"{version} ({commit})" if commit else version


def main() -> int:
    print(describe() or "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
