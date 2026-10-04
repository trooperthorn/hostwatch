"""Fake Windows seam implementations loaded from a JSON fixture, for tests on any platform."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hostwatch.windows import CommandResult, SeamError, WindowsSeam

FIXTURE = Path(__file__).parent / "fixtures" / "windows" / "seam.json"


def load(path: Path = FIXTURE) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class FakeEventLogReader:
    def __init__(self, logs: dict[str, list[dict[str, Any]]]) -> None:
        self.logs, self.calls = logs, []

    def read(self, log_name, event_ids=None, since=None, max_events=100):
        self.calls.append((log_name, event_ids, since, max_events))
        if log_name not in self.logs:
            raise SeamError(f"no such log: {log_name}")
        found = [e for e in self.logs[log_name]
                 if (not event_ids or e["id"] in event_ids) and (since is None or e["time"] >= since)]
        return sorted(found, key=lambda e: -e["time"])[:max_events]


class FakeCimQuery:
    def __init__(self, classes: dict[str, list[dict[str, Any]]]) -> None:
        self.classes, self.calls = classes, []

    def query(self, class_name, properties=None, namespace=None):
        self.calls.append((class_name, properties, namespace))
        if class_name not in self.classes:
            raise SeamError(f"no such class: {class_name}")
        rows = self.classes[class_name]
        return [{k: v for k, v in r.items() if k in properties} if properties else dict(r) for r in rows]


class FakePipeStatusReader:
    def __init__(self, pipes: dict[str, dict[str, Any]]) -> None:
        self.pipes, self.calls = pipes, []

    def read(self, pipe_name):
        self.calls.append(pipe_name)
        if pipe_name not in self.pipes:
            raise SeamError(f"cannot read pipe {pipe_name}: not found")
        return dict(self.pipes[pipe_name])


class FakeCommandRunner:
    """Records every command and answers from a queue of canned results, never starting a process."""

    def __init__(self, results: list[CommandResult] | None = None) -> None:
        self.results, self.calls = list(results or []), []

    def run(self, args, timeout_s):
        self.calls.append((list(args), timeout_s))
        if not self.results:
            raise SeamError("FakeCommandRunner has no canned result left")
        return self.results.pop(0)


def fake_seam(path: Path = FIXTURE) -> WindowsSeam:
    data = load(path)
    return WindowsSeam(events=FakeEventLogReader(data.get("events", {})),
                       cim=FakeCimQuery(data.get("cim", {})),
                       pipe=FakePipeStatusReader(data.get("pipes", {})),
                       runner=FakeCommandRunner())
