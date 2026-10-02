"""Agent loop: detect sources, collect, and push batches to the hub.

Even in the single-container "all" role the agent reaches the hub over HTTP
on loopback, so the wire schema is exercised exactly as a remote agent would.
If the hub is unreachable, batches are held in a bounded in-memory queue and
sent oldest-first when it returns. The queue is not persisted: an agent
restart during a hub outage loses at most HOSTWATCH_INTERVAL * MAX_QUEUE.
"""

from __future__ import annotations

import collections
from collections.abc import Callable
import logging
import platform as _platform
import threading
import time
import uuid
from pathlib import Path

import httpx

from . import __version__
from .collectors import build_collectors
from .config import Config
from .events import boot, pstore
from .events.journal import JournalWatcher
from .events.rasdaemon import RasdaemonReader
from .events.thresholds import ThresholdEngine
from .schema import Batch, Event, SourceStatus

log = logging.getLogger("hostwatch.agent")
MAX_QUEUE = 240  # one hour at the default 15s interval
MAX_SEEN_KEYS = 10000

EventSource = Callable[[], tuple[SourceStatus, list[Event]]]


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
        self.heartbeat: boot.Heartbeat | None = None
        self.pending_events: list[Event] = []
        self.thresholds = ThresholdEngine()
        journal = JournalWatcher(cfg.journal, cfg.data_dir)
        rasdaemon = RasdaemonReader(cfg.rasdaemon_db)
        self.event_sources: dict[str, EventSource] = {
            "pstore": lambda: pstore.read_pstore(cfg.pstore),
            "rasdaemon": rasdaemon.read,
            "journal": journal.read,
        }
        # Pstore and rasdaemon re-read whole records, so keys already handed to a
        # batch are remembered and not sent again by this process.
        self._seen_keys: dict[str, None] = {}

    def seed_thresholds(self, client: httpx.Client) -> None:
        """Seed threshold state from events the hub already stores. Best effort:
        if the hub is unreachable, state starts empty and one event may repeat.
        Only source=thresholds events are requested and every page is read, so
        other event floods cannot push an open condition out of view."""
        headers = {"Authorization": f"Bearer {self.cfg.ingest_token}"}
        params: dict = {"host": self.cfg.host_name, "source": "thresholds", "limit": 1000}
        stored: list[dict] = []
        try:
            while True:
                r = client.get(f"{self.cfg.hub_url}/internal/v1/events", params=params, headers=headers, timeout=10)
                r.raise_for_status()
                stored.extend(r.json())
                cursor = r.headers.get("X-Next-Before")
                if cursor is None:
                    break
                params = {**params, "before": cursor}
                if r.headers.get("X-Next-Before-Id") is not None:
                    params["before_id"] = r.headers["X-Next-Before-Id"]
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                log.error("hub rejected the ingest token (401) while seeding threshold state; "
                          "check HOSTWATCH_INGEST_TOKEN on the agent and the hub")
            else:
                log.warning("hub answered %s while seeding threshold state", exc.response.status_code)
            return
        except Exception as exc:
            log.warning("hub unreachable, could not seed threshold state: %s", exc)
            return
        self.thresholds.seed(stored)

    def _collect_events(self) -> list[Event]:
        events: list[Event] = []
        for name, read in self.event_sources.items():
            try:
                status, found = read()
            except Exception as exc:
                status = SourceStatus(source=name, available=False,
                                      reason=f"read error: {type(exc).__name__}: {exc}")
                found = []
            self.status[name] = status
            for ev in found:
                if ev.dedup_key in self._seen_keys:
                    continue
                self._seen_keys[ev.dedup_key] = None
                events.append(ev)
        while len(self._seen_keys) > MAX_SEEN_KEYS:
            del self._seen_keys[next(iter(self._seen_keys))]
        return events

    def start_boot_check(self) -> None:
        """Classify how the previous boot ended, once, then start the heartbeat.
        The event is queued for the next batch; the hub deduplicates by boot_id.
        The pending event is held in memory, so an agent restart before it is
        delivered loses it (the heartbeat already names the new boot)."""
        boot_id = boot.read_boot_id(self.cfg.procfs)
        if boot_id is None:
            self.status["boot"] = SourceStatus(source="boot", available=False,
                                               reason=f"cannot read {self.cfg.procfs / boot.BOOT_ID_REL}")
            return
        previous = boot.load_heartbeat(self.cfg.data_dir)
        pstore = boot.pstore_has_records(self.cfg.sysfs / "fs/pstore")
        result = boot.classify(previous, boot_id, pstore, {})
        if result is not None:
            self.pending_events.append(boot.boot_event(result))
            log.info("boot classified as %s", result.kind)
        self.heartbeat = boot.Heartbeat(self.cfg.data_dir, boot_id)
        self.status["boot"] = SourceStatus(source="boot", available=True, reason="")

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
        events, self.pending_events = self.pending_events, []
        events.extend(self._collect_events())
        events.extend(self.thresholds.evaluate(samples, self.status.values()))
        return Batch(agent_version=__version__, host=self.cfg.host_name, platform=self.platform,
                     sent_at=time.time(), sources=list(self.status.values()), samples=samples,
                     events=events, batch_id=str(uuid.uuid4()))

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
        self.start_boot_check()
        with httpx.Client() as client:
            self.seed_thresholds(client)
            while not self._stop.is_set():
                started = time.monotonic()
                self._beat()
                self.queue.append(self.collect_once())
                try:
                    self.flush(client)
                except Exception as exc:
                    log.warning("hub unreachable (%s); %d batch(es) queued", exc, len(self.queue))
                self._stop.wait(max(0.0, self.cfg.interval_s - (time.monotonic() - started)))

    def _beat(self) -> None:
        if self.heartbeat is None:
            return
        try:
            self.heartbeat.beat()
        except OSError as exc:
            log.warning("heartbeat write failed: %s", exc)
            self.status["boot"] = SourceStatus(source="boot", available=False,
                                               reason=f"heartbeat write failed: {exc}")

    def stop(self) -> None:
        """Stop the loop and record an orderly shutdown in the heartbeat."""
        self._stop.set()
        if self.heartbeat is not None:
            try:
                self.heartbeat.mark_clean()
            except OSError as exc:
                log.warning("clean-shutdown heartbeat failed: %s", exc)
