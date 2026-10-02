"""Agent loop: detect sources, collect, and push batches to the hub.

Even in the single-container "all" role the agent reaches the hub over HTTP
on loopback, so the wire schema is exercised exactly as a remote agent would.
If the hub is unreachable, batches are held in a bounded in-memory queue and
sent oldest-first when it returns. The queue is not persisted: an agent
restart during a hub outage loses at most HOSTWATCH_INTERVAL * MAX_QUEUE.
"""

from __future__ import annotations

import json
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
from .events.journal import BackgroundJournal, JournalWatcher, ReaderError
from .events.rasdaemon import RasdaemonReader
from .events.thresholds import ThresholdEngine
from .outbox import OUTBOX_FILE, Outbox
from .schema import Batch, Event, SourceStatus

log = logging.getLogger("hostwatch.agent")
MAX_QUEUE = 240  # one hour at the default 15s interval
PENDING_BOOT_MARKER = "boot.pending_events"
PSTORE_SENT_MARKER = "pstore.sent_keys"
DEAD_LETTER_STATUSES = {400, 422}
MAX_BACKOFF_S = 300.0
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
        self.outbox = Outbox(cfg.data_dir / OUTBOX_FILE, MAX_QUEUE)
        # None means detection has never run. A numeric zero would compare
        # against time.monotonic(), which counts from host boot on Linux, so a
        # host up for less than redetect_s would never detect its sources.
        self._last_detect: float | None = None
        self._stop = threading.Event()
        self.heartbeat: boot.Heartbeat | None = None
        self.thresholds = ThresholdEngine()
        self.journal_watcher = JournalWatcher(cfg.journal, cfg.data_dir, markers=self.outbox,
                                              volatile=cfg.journal_volatile)
        journal = self.journal = BackgroundJournal(self.journal_watcher)
        rasdaemon = RasdaemonReader(cfg.rasdaemon_db, markers=self.outbox)
        self.event_sources: dict[str, EventSource] = {
            "pstore": self._read_pstore,
            "rasdaemon": rasdaemon.read,
            "journal": journal.read,
        }
        # Pstore and rasdaemon re-read whole records, so keys already handed to a
        # batch are remembered and not sent again by this process.
        self._seen_keys: dict[str, None] = {}
        self._cycle_keys: list[str] = []
        # Threshold events are held back until the seed from the hub succeeds.
        self.seeded = False
        self._seed_failures = 0
        self._next_seed = 0.0
        self._flush_failures = 0
        self._next_flush = 0.0
        # Monotonic time of the first failed delivery of the current stall.
        self._stall_since: float | None = None
        self._stopped = threading.Event()

    @property
    def pending_events(self) -> list[Event]:
        """Events waiting for the next batch, held in the outbox so a restart
        before delivery does not lose them."""
        raw = self.outbox.get(PENDING_BOOT_MARKER)
        if not raw:
            return []
        try:
            return [Event.model_validate(e) for e in json.loads(raw)]
        except ValueError:
            log.error("pending event marker is unreadable and was ignored")
            return []

    def _stage_pending(self, events: list[Event]) -> None:
        self.outbox.stage(PENDING_BOOT_MARKER,
                          json.dumps([e.model_dump() for e in events]) if events else None)

    def _read_pstore(self) -> tuple[SourceStatus, list[Event]]:
        """Pstore records are re-read whole, so the keys already queued are
        kept as a marker and committed with the batch that carries the rest."""
        status, found = pstore.read_pstore(self.cfg.pstore)
        try:
            sent = json.loads(self.outbox.get(PSTORE_SENT_MARKER) or "[]")
        except ValueError:
            sent = []
        new = [e for e in found if e.dedup_key not in sent]
        if new:
            self.outbox.stage(PSTORE_SENT_MARKER,
                              json.dumps((sent + [e.dedup_key for e in new])[-MAX_SEEN_KEYS:]))
        return status, new

    def seed_thresholds(self, client: httpx.Client) -> bool:
        """Seed threshold state from events the hub already stores. Returns True
        once seeded. On failure it returns False and the run loop retries with
        backoff; threshold events are held back until it succeeds, so a repeat
        of an open condition cannot be emitted from empty state.
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
            elif exc.response.status_code == 403:
                log.error("hub refused the read (403) while seeding threshold state: the shared ingest token "
                          "has the ingest scope only; the agent needs a scoped key with read:events")
            else:
                log.warning("hub answered %s while seeding threshold state", exc.response.status_code)
            return False
        except Exception as exc:
            log.warning("hub unreachable, could not seed threshold state: %s", exc)
            return False
        self.thresholds.seed(stored)
        self.seeded = True
        return True

    def _try_seed(self, client: httpx.Client) -> None:
        if self.seeded or time.monotonic() < self._next_seed:
            return
        try:
            seeded = self.seed_thresholds(client)
        except Exception as exc:  # a bad answer must not end the loop
            log.warning("threshold seeding failed: %s: %s", type(exc).__name__, exc)
            seeded = False
        if seeded:
            log.info("threshold state seeded; threshold events are enabled")
            self.status.pop("thresholds", None)
            return
        self._seed_failures += 1
        self.status["thresholds"] = SourceStatus(
            source="thresholds", available=False,
            reason=f"threshold events are held back until the hub seed succeeds ({self._seed_failures} failed attempt(s))")
        self._next_seed = time.monotonic() + self._backoff(self._seed_failures)

    def _backoff(self, failures: int) -> float:
        return min(self.cfg.interval_s * 2 ** max(0, failures - 1), MAX_BACKOFF_S)

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
                self._cycle_keys.append(ev.dedup_key)
                events.append(ev)
        while len(self._seen_keys) > MAX_SEEN_KEYS:
            del self._seen_keys[next(iter(self._seen_keys))]
        return events

    def _guarded_boot_check(self) -> None:
        """Run start_boot_check so a failure leaves the boot source unknown, with
        the reason, and the loop running. The heartbeat is still started when the
        boot id can be read, so the next start has something to compare."""
        try:
            self.start_boot_check()
            return
        except Exception as exc:
            log.exception("boot check failed; the previous boot's end is unknown")
            reason = f"boot classification failed, the previous boot's end is unknown: {type(exc).__name__}: {exc}"
        try:
            if self.heartbeat is None:
                boot_id = boot.read_boot_id(self.cfg.procfs)
                if boot_id is not None:
                    self.heartbeat = boot.Heartbeat(self.cfg.data_dir, boot_id)
        except Exception:
            log.exception("heartbeat could not be started after the boot check failed")
        self.status["boot"] = SourceStatus(source="boot", available=False, reason=reason)

    def start_boot_check(self) -> None:
        """Classify how the previous boot ended, once, then start the heartbeat.
        The event is queued for the next batch; the hub deduplicates by boot_id.
        The pending event is committed to the outbox at once, so an agent restart
        before it is delivered does not lose it (the heartbeat already names the
        new boot, so it could not be classified again)."""
        boot_id = boot.read_boot_id(self.cfg.procfs)
        if boot_id is None:
            self.status["boot"] = SourceStatus(source="boot", available=False,
                                               reason=f"cannot read {self.cfg.procfs / boot.BOOT_ID_REL}")
            return
        previous = boot.load_heartbeat(self.cfg.data_dir)
        classified = boot.load_classified(self.cfg.data_dir)
        start = previous.get("first_ts") if previous else None
        pstore = boot.pstore_evidence(self.cfg.pstore, start if isinstance(start, (int, float)) else None,
                                      previous.get("ts") if previous else None, classified)
        hints: dict[str, bool] = {}
        journal_unavailable: str | None = None
        bootstatus = boot.read_bootstatus(self.cfg.sysfs)
        if previous is not None and previous.get("boot_id") != boot_id:
            try:
                hints = self.journal_watcher.previous_boot(previous["boot_id"])
            except ReaderError as exc:
                journal_unavailable = str(exc)
        result = boot.classify(previous, boot_id, pstore, hints, journal_unavailable=journal_unavailable,
                               bootstatus=bootstatus)
        if result is not None:
            events = [boot.boot_event(result), *self._missed_boot_events(previous, boot_id)]
            have = {e.dedup_key for e in self.pending_events}
            self._stage_pending([*self.pending_events, *(e for e in events if e.dedup_key not in have)])
            self.outbox.commit_staged()
            if pstore.get("fresh_keys"):
                try:
                    boot.save_classified(self.cfg.data_dir, classified | set(pstore["fresh_keys"]))
                except OSError as exc:
                    log.warning("cannot record classified pstore records: %s", exc)
            log.info("boot classified as %s", result.kind)
        self.heartbeat = boot.Heartbeat(self.cfg.data_dir, boot_id)
        self.status["boot"] = SourceStatus(source="boot", available=True, reason="")

    def _missed_boot_events(self, previous: dict | None, boot_id: str) -> list:
        """Unknown events for boots that began and ended while the agent was not
        running, found through the pluggable boot list reader."""
        if previous is None or previous.get("boot_id") == boot_id:
            return []
        try:
            boots = self.journal_watcher.list_boots()
        except ReaderError:
            return []  # the boot list is optional evidence; the main event stands
        out = []
        prev_id = previous["boot_id"]
        for rec in boot.intermediate_boots(boots, prev_id, boot_id):
            hints, why = None, None
            try:
                hints = self.journal_watcher.previous_boot(rec["boot_id"])
            except ReaderError as exc:
                why = str(exc)
            out.append(boot.boot_event(boot.missed_boot_classification(rec, hints, why, prev_id)))
        return out

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
        if self._last_detect is None or time.monotonic() - self._last_detect > self.cfg.redetect_s:
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
        events = self.pending_events
        self._stage_pending([])
        events.extend(self._collect_events())
        self._outbox_status()
        if self.seeded:
            events.extend(self.thresholds.evaluate(samples, self.status.values()))
        return Batch(agent_version=__version__, host=self.cfg.host_name, platform=self.platform,
                     sent_at=time.time(), sources=list(self.status.values()), samples=samples,
                     events=events, batch_id=str(uuid.uuid4()))

    def _outbox_status(self) -> None:
        dropped = self.outbox.dropped_since_drain()
        dead = self.outbox.dead_letter_count()
        notes = []
        if dropped:
            notes.append(f"outbox full: {dropped} sample(s) dropped since the queue last drained "
                         f"({self.outbox.dropped_total()} in total); events were kept")
        if dead:
            notes.append(f"{dead} batch(es) refused by the hub or undecodable are in the dead-letter table")
        undecodable = self.outbox.undecodable_total()
        if undecodable:
            notes.append(f"{undecodable} outbox row(s) could not be decoded and were moved to the dead-letter table")
        if self._stall_since is not None:
            notes.append(f"delivery to the hub has stalled for {time.monotonic() - self._stall_since:.0f}s; "
                         f"{self.outbox.depth()} batch(es) are queued and kept")
        if self.outbox.recovered_from is not None:
            notes.append(f"the outbox file was corrupt and was moved to {self.outbox.recovered_from.name}; "
                         "batches and progress markers in it were lost")
        self.status["outbox"] = SourceStatus(source="outbox", available=not dropped, reason="; ".join(notes))

    def cycle(self) -> None:
        """Collect one batch and write it, with the source markers it covers,
        to the outbox in a single transaction."""
        self.outbox.enqueue(self.collect_once())

    def safe_cycle(self) -> bool:
        """Run one cycle without letting an exception end the loop. On failure
        the staged markers and the in-process dedup keys of the failed cycle are
        discarded so nothing is skipped, the failure is logged, and the agent
        source is reported unavailable with the reason until a cycle succeeds."""
        self._cycle_keys = []
        threshold_state = dict(self.thresholds.state)
        try:
            self._beat()
            self.cycle()
        except Exception as exc:
            log.exception("agent cycle failed; the loop continues")
            self.outbox.discard_staged()
            # Threshold conditions opened by the failed cycle were never queued, so
            # forget them and let the next cycle emit them again.
            self.thresholds.state = threshold_state
            self.journal.rewind()
            for key in self._cycle_keys:
                self._seen_keys.pop(key, None)
            self.status["agent"] = SourceStatus(source="agent", available=False,
                                                reason=f"cycle error: {type(exc).__name__}: {exc}")
            return False
        self.status["agent"] = SourceStatus(source="agent", available=True, reason="")
        return True

    def flush(self, client: httpx.Client) -> None:
        """Send queued batches oldest first. A batch leaves the outbox only after
        a 2xx answer. A 400 or 422 can never succeed and is dead-lettered so the
        head is not blocked. Any other failure, including every 5xx, raises and
        the batch stays queued: those describe the hub, not the batch."""
        while (head := self.outbox.peek()) is not None:
            seq, batch = head
            r = client.post(f"{self.cfg.hub_url}/internal/v1/ingest", content=batch.model_dump_json(),
                            headers={"Authorization": f"Bearer {self.cfg.ingest_token}",
                                     "Content-Type": "application/json"}, timeout=10)
            if r.status_code in DEAD_LETTER_STATUSES:
                self.outbox.dead_letter(seq, r.status_code)
                continue
            if r.is_success:
                self.outbox.ack(seq)
                continue
            raise httpx.HTTPStatusError(f"hub answered {r.status_code}", request=r.request, response=r)

    def _try_flush(self, client: httpx.Client) -> None:
        if time.monotonic() < self._next_flush:
            return
        try:
            self.flush(client)
        except Exception as exc:
            self._flush_failures += 1
            if self._stall_since is None:
                self._stall_since = time.monotonic()
            wait = self._backoff(self._flush_failures)
            self._next_flush = time.monotonic() + wait
            log.warning("delivery failed (%s); %d batch(es) queued, next attempt in %.0fs", exc,
                        self.outbox.depth(), wait)
        else:
            self._flush_failures, self._next_flush = 0, 0.0
            self._stall_since = None

    def run(self) -> None:
        """The loop. It writes the clean-shutdown flag itself when it exits, so a
        signal handler only has to call stop()."""
        try:
            self.detect()
            self._guarded_boot_check()
            with httpx.Client() as client:
                while not self._stop.is_set():
                    started = time.monotonic()
                    try:
                        self._try_seed(client)
                        self.safe_cycle()
                        self._try_flush(client)
                    except Exception:  # last resort: nothing may end the loop
                        log.exception("unexpected error in the agent loop; continuing")
                    self._stop.wait(max(0.0, self.cfg.interval_s - (time.monotonic() - started)))
        finally:
            self.finish()

    def _beat(self) -> None:
        if self.heartbeat is None:
            return
        try:
            self.heartbeat.beat()
            current = self.status.get("boot")
            if current is not None and not current.available and current.reason.startswith("heartbeat write failed"):
                self.status["boot"] = SourceStatus(source="boot", available=True, reason="")
        except OSError as exc:
            log.warning("heartbeat write failed: %s", exc)
            self.status["boot"] = SourceStatus(source="boot", available=False,
                                               reason=f"heartbeat write failed: {exc}")

    def stop(self) -> None:
        """Ask the loop to end. Safe in a signal handler: it only sets a flag and
        takes no lock. The run loop writes the clean flag on its way out."""
        self._stop.set()

    def finish(self) -> None:
        """Record an orderly shutdown in the heartbeat, then release waiters."""
        try:
            if self.heartbeat is not None:
                try:
                    self.heartbeat.mark_clean()
                except OSError as exc:
                    log.warning("clean-shutdown heartbeat failed: %s", exc)
        finally:
            self._stopped.set()

    def stop_and_wait(self, timeout: float = 15.0) -> bool:
        """Stop and wait for the run loop to finish, for callers that are not a
        signal handler (the hub shutdown hook)."""
        self.stop()
        return self._stopped.wait(timeout)
