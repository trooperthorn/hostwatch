"""Bounded collector runs that never hold up the agent loop.

A collector can hang: a network call that never answers, a disk that stalls a CIM query. The agent
therefore never calls a collector on its own thread. It starts the call on a worker thread and waits
for a limited time. A call that outlives its limit is left running, because Python cannot stop a
thread, and the collector counts as busy until the call returns. A busy collector is not started a
second time, so a hang costs one thread and never piles up.

The event path uses `start` and `finish` so it can look at a result when one is ready and carry on
when it is not: a slow collector then delays nothing but its own next reading.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any


class CollectorTimeout(Exception):
    """A collector call did not return within its time limit."""


class Job:
    def __init__(self, fn: Callable[[], Any]) -> None:
        self.started = time.monotonic()
        self.result: Any = None
        self.error: BaseException | None = None
        # Set when the caller gave up on this call. A result that arrives later is discarded.
        self.abandoned = False
        self._done = threading.Event()
        self._fn = fn
        self._thread = threading.Thread(target=self._run, name="hostwatch-collector", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            self.result = self._fn()
        except BaseException as exc:  # carried to the caller, never lost with the thread
            self.error = exc
        finally:
            self._done.set()

    @property
    def done(self) -> bool:
        return self._done.is_set()

    def wait(self, timeout: float) -> bool:
        return self._done.wait(timeout)

    def age(self) -> float:
        return time.monotonic() - self.started

    def value(self) -> Any:
        """The result, or the exception the call raised."""
        if self.error is not None:
            raise self.error
        return self.result


class CollectorRunner:
    """At most one running call per collector id."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._locks: dict[str, threading.Lock] = {}

    def _exclusive(self, collector: str, fn: Callable[[], Any]) -> Callable[[], Any]:
        """Wrap `fn` so two runs of one collector never overlap, whatever asked for them: a
        collector keeps state between calls and is not written to be re-entered."""
        lock = self._locks.setdefault(collector, threading.Lock())

        def locked() -> Any:
            with lock:
                return fn()
        return locked

    def current(self, key: str) -> Job | None:
        return self._jobs.get(key)

    def start(self, key: str, fn: Callable[[], Any], collector: str | None = None) -> Job:
        """The job already running for `key`, or a new one. A finished job that nobody collected
        is replaced only through `finish`, so a result is never dropped unseen. Jobs that name the
        same `collector` run one after the other."""
        job = self._jobs.get(key)
        if job is not None and job.abandoned and job.done:
            job = None  # its answer came too late to be a reading; ask again
        if job is None:
            job = self._jobs[key] = Job(self._exclusive(collector, fn) if collector else fn)
        return job

    def finish(self, key: str) -> None:
        self._jobs.pop(key, None)

    def run(self, key: str, fn: Callable[[], Any], limit: float, collector: str | None = None) -> Any:
        """Run `fn` and return its result, raising what it raised, or CollectorTimeout when it takes
        longer than `limit` seconds or an earlier call for `key` is still running."""
        job = self.start(key, fn, collector)
        if not job.wait(limit):
            job.abandoned = True
            raise CollectorTimeout(f"no answer within {limit:g}s")
        self.finish(key)
        return job.value()
