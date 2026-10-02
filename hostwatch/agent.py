"""Agent loop: detect sources, collect, and push batches to the hub.

Even in the single-container "all" role the agent reaches the hub over HTTP
on loopback, so the wire schema is exercised exactly as a remote agent would.
If the hub is unreachable, batches are held in a bounded in-memory queue and
sent oldest-first when it returns. The queue is not persisted: an agent
restart during a hub outage loses at most HOSTWATCH_INTERVAL * MAX_QUEUE.
"""

from __future__ import annotations

import collections
import logging
import platform as _platform
import threading
import time
from pathlib import Path

import httpx

from . import __version__
from .collectors import build_collectors
from .config import Config
from .schema import Batch, SourceStatus

log = logging.getLogger("hostwatch.agent")
MAX_QUEUE = 240  # one hour at the default 15s interval


def detect_platform(sysfs: Path) -> str:
    model = Path("/proc/device-tree/model")
    try:
        if model.read_text().startswith("Raspberry Pi"):
            return "rpi"
    except OSError:
        pass
    return "x86" if _platform.machine() == "x86_64" else _platform.machine()


class Agent:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.collectors = build_collectors(cfg)
        self.platform = detect_platform(cfg.sysfs)
        self.status: dict[str, SourceStatus] = {}
        self.queue: collections.deque[Batch] = collections.deque(maxlen=MAX_QUEUE)
        self._last_detect = 0.0
        self._stop = threading.Event()

    def detect(self) -> None:
        for c in self.collectors:
            try:
                ok, reason = c.detect()
            except Exception as exc:
                ok, reason = False, f"detect error: {type(exc).__name__}: {exc}"
            prev = self.status.get(c.id)
            if prev is None or prev.available != ok:
                log.info("source %s: %s %s", c.id, "available" if ok else "unavailable", reason)
            self.status[c.id] = SourceStatus(source=c.id, available=ok, reason=reason)
        self._last_detect = time.monotonic()

    def collect_once(self) -> Batch:
        if time.monotonic() - self._last_detect > self.cfg.redetect_s:
            self.detect()
        samples = []
        for c in self.collectors:
            if not self.status[c.id].available:
                continue
            try:
                samples.extend(c.collect())
            except Exception as exc:
                log.warning("collector %s failed: %s", c.id, exc)
                self.status[c.id] = SourceStatus(source=c.id, available=False,
                                                 reason=f"collect error: {type(exc).__name__}: {exc}")
        return Batch(agent_version=__version__, host=self.cfg.host_name, platform=self.platform,
                     sent_at=time.time(), sources=list(self.status.values()), samples=samples)

    def flush(self, client: httpx.Client) -> None:
        while self.queue:
            batch = self.queue[0]
            r = client.post(f"{self.cfg.hub_url}/internal/v1/ingest", content=batch.model_dump_json(),
                            headers={"Authorization": f"Bearer {self.cfg.ingest_token}",
                                     "Content-Type": "application/json"}, timeout=10)
            r.raise_for_status()
            self.queue.popleft()

    def run(self) -> None:
        self.detect()
        with httpx.Client() as client:
            while not self._stop.is_set():
                started = time.monotonic()
                self.queue.append(self.collect_once())
                try:
                    self.flush(client)
                except Exception as exc:
                    log.warning("hub unreachable (%s); %d batch(es) queued", exc, len(self.queue))
                self._stop.wait(max(0.0, self.cfg.interval_s - (time.monotonic() - started)))

    def stop(self) -> None:
        self._stop.set()
