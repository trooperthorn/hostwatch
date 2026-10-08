"""Agent loop: detect sources, collect them by polling tier, and send OTLP to Observe.

Collection is scheduled per tier (tiers.py). Observe tells the agent each tier's rate through
GET /internal/v1/agent-config; until it answers, and whenever it cannot be reached, the defaults
apply, and every rate is clamped to the limits Observe itself enforces. Each tier run becomes one
outbox entry: the metrics of that tier and any logs they produced, encoded as OTLP requests.

Events are not held to a tier. Every EVENT_POLL_S seconds the agent reads its event sources
(boot classification, kernel journal, pstore, rasdaemon, TrueNAS alerts) and, every WATCH_S
seconds, the cheap local sources whose state changes are events (RAID, ZFS, UPS) and the health probe of
the slow storage sources (Scrutiny, Windows storage, SMART, TrueNAS), and sends what it finds as OTLP logs
at once. A storage poll that runs every fifteen minutes therefore never delays a failure. Collectors run on
worker threads with a time limit (runner.py), so a slow one never holds up the event read. Source
detection and the agent-config request run on worker threads as well, and a collector that fails after
it was detected is read again after a short back-off instead of at the next full detection.

Requests go to POST /v1/metrics and POST /v1/logs only. They are written to a durable outbox
first and leave it only after Observe answers 2xx, so an Observe outage or an agent restart does
not lose events. A replay sends the same bytes under the same Idempotency-Key.
"""

from __future__ import annotations

import json
import logging
import math
import platform as _platform
import socket
import ssl
import sys
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import __version__, otel_map, otlp, tiers
from .collectors import build_collectors
from .config import Config
from .events import boot, pstore
from .events.journal import BackgroundJournal, JournalWatcher, ReaderError
from .events.rasdaemon import RasdaemonReader
from .events.thresholds import ThresholdEngine
from .model import Event, Sample, SourceStatus
from .otel_map import LogRecord, MapContext, Point
from .outbox import OUTBOX_FILE, Outbox
from .privfile import write_private
from .runner import CollectorRunner, CollectorTimeout
from .windows import WindowsSeam

log = logging.getLogger("hostwatch.agent")
PENDING_BOOT_MARKER = "boot.pending_events"
PSTORE_SENT_MARKER = "pstore.sent_keys"
THRESHOLD_MARKER = "thresholds.state"
ALIVE_FILE = "agent.alive"
# Statuses that can never succeed for the request that was sent, so it is dead-lettered and the
# queue moves on: malformed (400), a reused idempotency key with another body (409), too large
# (413), an unsupported type (415) and unprocessable (422). Everything else describes Observe,
# the network or the key (401, 403, 404, 429 and every 5xx), so the request stays queued.
# A delivery pass commits its removals at the end, and also after this many, so a crash late in a
# long drain resends at most this many requests.
ACK_COMMIT_EVERY = 50
DEAD_LETTER_STATUSES = {400, 409, 413, 415, 422}
BACKOFF_BASE_S = 5.0
MAX_BACKOFF_S = 300.0
MAX_SEEN_KEYS = 10000
# The boot heartbeat is written this often, whatever the availability rate is, so the end of an
# unclean boot is known to within this many seconds.
HEARTBEAT_S = 15.0
# Watched sources (RAID, ZFS, UPS) are read this often for state changes that are events.
WATCH_S = 15.0

# How long the loop waits for collector workers it has just started, so a fast collector's reading is
# handled in the same pass. A collector that takes longer is not waited for: its worker keeps running and
# the loop looks at it again on its next pass, so a slow or hung collector never holds up events.
EVENT_GRACE_S = 0.25
TIER_GRACE_S = 0.25
# How long a freshly started detection round or agent-config request is waited for. Whatever has not
# answered by then keeps running on its worker and is picked up by a later pass.
DETECT_GRACE_S = 0.25
CONFIG_GRACE_S = 0.25
# An agent-config request that has not answered after this long is given up on and counted as a failure.
CONFIG_HANG_S = 3 * tiers.CONFIG_TIMEOUT_S
# A collector that failed after it was detected is tried again after this long, doubling with every
# further failure up to redetect_s, instead of waiting for the next full detection.
COLLECT_RETRY_BASE_S = 5.0
# While the journal has more batches waiting, the event read repeats this often instead of every EVENT_POLL_S.
DRAIN_POLL_S = 0.5

# A send that is slow must not hold a stop request for long.
SEND_TIMEOUT_S = 5.0
EventSource = Callable[[], tuple[SourceStatus, list[Event]]]


class _TierRun:
    """A tier whose collectors have been started and have not all answered."""

    def __init__(self, launched: list[tuple]) -> None:
        self.pending = launched
        self.samples: list[Sample] = []


class DeliveryError(Exception):
    """Observe did not accept a request and the request stays queued."""

    def __init__(self, message: str, status: int | None = None, retry_after: float = 0.0) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def _is_truenas(procfs: Path | None, truenas_url: str) -> bool:
    """TrueNAS shows in the host kernel version string, which the container reads through the
    procfs mount. A TrueNAS API on this machine (a loopback URL) counts as well."""
    if procfs is not None:
        try:
            if "truenas" in (procfs / "version").read_text(errors="replace").lower():
                return True
        except OSError:
            pass
    host = (urlsplit(truenas_url).hostname or "") if truenas_url else ""
    return host in ("localhost", "127.0.0.1", "::1")


def detect_platform(sysfs: Path | None = None, procfs: Path | None = None, truenas_url: str = "") -> str:
    # Checked first so a Windows host never touches sysfs or procfs paths.
    if sys.platform == "win32":
        return "windows"
    model = Path("/proc/device-tree/model")
    try:
        if model.read_text().startswith("Raspberry Pi"):
            return "rpi"
    except OSError:
        pass
    if _is_truenas(procfs, truenas_url):
        return "truenas"
    return "x86" if _platform.machine() == "x86_64" else _platform.machine()


def observe_tls_verify(cfg: Config) -> ssl.SSLContext | bool:
    """Default verification, so an Observe behind a public certificate needs no setting."""
    return True


class Agent:
    def __init__(self, cfg: Config, seam: WindowsSeam | None = None, platform: str | None = None,
                 clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time) -> None:
        self.cfg = cfg
        self.seam = seam
        self._clock = clock
        self._wall = wall
        self._warn_if_name_differs()
        # The platform is a parameter so the Windows agent can be built and tested on Linux.
        self.platform = platform or detect_platform(cfg.sysfs, cfg.procfs, cfg.truenas_url)
        self.collectors = build_collectors(cfg, seam, platform=self.platform)
        self.status: dict[str, SourceStatus] = {}
        self.outbox = Outbox(cfg.data_dir / OUTBOX_FILE)
        # Problems with the outbox itself, waiting to be sent as observe.source.change logs. The
        # outbox adds its own recoveries here; a first rejection of each signal is added by flush.
        self._outbox_incidents: list[str] = []
        self._rejection_reported: set[str] = set()
        self.resource = otel_map.resource_attributes(cfg.host_name, self.platform, __version__,
                                                     arch=_platform.machine())
        self.map_context = MapContext(ups_name=cfg.nut_ups or "ups")
        self.started_at = self._wall()
        self.schedule = tiers.TierSchedule()
        self._config_next = 0.0
        self._config_ok: bool | None = None
        # None means detection has never run. A numeric zero would compare against a monotonic
        # clock, which counts from host boot on Linux, so a host up for less than redetect_s would
        # never detect its sources.
        self._last_detect: float | None = None
        # Collectors whose detection is in flight: (collector, job, runner key).
        self._detect_round: list[tuple] = []
        # Collectors that failed after they were detected: id -> (failures in a row, retry not before).
        self._retry: dict[str, tuple[int, float]] = {}
        self._stop = threading.Event()
        self.heartbeat: boot.Heartbeat | None = None
        self._next_beat = 0.0
        self.thresholds = ThresholdEngine()
        self.thresholds.load(self.outbox.get(THRESHOLD_MARKER))
        self.journal_watcher = JournalWatcher(cfg.journal, cfg.data_dir, markers=self.outbox,
                                              volatile=cfg.journal_volatile)
        journal = self.journal = BackgroundJournal(self.journal_watcher)
        rasdaemon = RasdaemonReader(cfg.rasdaemon_db, markers=self.outbox)
        self.event_sources: dict[str, EventSource] = {
            "pstore": self._read_pstore,
            "rasdaemon": rasdaemon.read,
            "journal": journal.read,
        }
        # TrueNAS alerts come from the same API reads as the truenas collector. Registered only when
        # TrueNAS is configured.
        for c in self.collectors:
            if c.id == "truenas" and not c.is_absent():
                self.event_sources["truenas_alerts"] = c.read_events
        # Pstore and rasdaemon re-read whole records, so keys already handed to a request are
        # remembered and not sent again by this process.
        self._seen_keys: dict[str, None] = {}
        # Pstore records by name with their size and mtime, so unchanged files are not re-read.
        self._pstore_cache: dict = {}
        self._cycle_keys: list[str] = []
        self._next_events = 0.0
        self._next_watch = 0.0
        self._failsafe_open: set[tuple[str, str]] = set()
        # Availability last reported in a source change log, per source. Memory only, so a restart
        # reports a source that is still unavailable once more.
        self._reported: dict[str, bool] = {}
        self._flush_failures = 0
        self._next_flush = 0.0
        # Requests acknowledged by the delivery pass in progress, so a pass that failed after making
        # progress does not climb the back-off.
        self._pass_acked = 0
        # Monotonic time of the first failed delivery of the current stall.
        self._stall_since: float | None = None
        self._stopped = threading.Event()
        # Collectors run on worker threads, one at a time each, bounded by their time limit.
        self.runner = CollectorRunner()
        # Tier runs that have started and not yet been queued: tier -> run in flight.
        self._tier_runs: dict[str, _TierRun] = {}

    @property
    def pending_events(self) -> list[Event]:
        """Events waiting for the next event read, held in the outbox so a restart
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
        value = json.dumps([e.model_dump() for e in events]) if events else None
        if value != self.outbox.get(PENDING_BOOT_MARKER):  # a write per pass would cost an fsync every few seconds
            self.outbox.stage(PENDING_BOOT_MARKER, value)

    def _read_pstore(self) -> tuple[SourceStatus, list[Event]]:
        """Pstore records are re-read whole, so the keys already queued are
        kept as a marker and committed with the requests that carry the rest."""
        status, found = pstore.read_pstore(self.cfg.pstore, self._pstore_cache)
        try:
            sent = json.loads(self.outbox.get(PSTORE_SENT_MARKER) or "[]")
        except ValueError:
            sent = []
        new = [e for e in found if e.dedup_key not in sent]
        if new:
            self.outbox.stage(PSTORE_SENT_MARKER,
                              json.dumps((sent + [e.dedup_key for e in new])[-MAX_SEEN_KEYS:]))
        return status, new

    # -- rates from Observe ------------------------------------------------------------------

    def _request_config(self, client: httpx.Client) -> tuple[str, Any]:
        """The network half of a config fetch, run on a worker thread. Returns ("ok", body) or
        ("fail", reason). It touches no agent state."""
        url = self.cfg.observe_url + tiers.AGENT_CONFIG_PATH
        try:
            r = client.get(url, headers={"Authorization": f"Bearer {self.cfg.ingest_key}"},
                           timeout=tiers.CONFIG_TIMEOUT_S)
            if r.status_code in (401, 403):
                return "fail", f"Observe refused the ingest key ({r.status_code}); check HOSTWATCH_INGEST_KEY"
            r.raise_for_status()
            return "ok", r.json()
        except httpx.HTTPStatusError as exc:
            return "fail", f"Observe answered {exc.response.status_code} for agent-config"
        except Exception as exc:  # unreachable, a bad answer or invalid JSON: all keep the current rates
            return "fail", f"Observe could not be reached for agent-config: {type(exc).__name__}: {exc}"

    def fetch_config(self, client: httpx.Client) -> bool:
        """Ask Observe for this host's tier rates and apply them, waiting for the answer. Returns True
        when the rates changed. A failure of any kind keeps the rates in force and is logged once per
        change of outcome, so an Observe that is down does not fill the log. The loop does not call
        this: it uses `_poll_config`, which never waits for an unreachable Observe."""
        return self._apply_config(self._request_config(client))

    def _poll_config(self, client: httpx.Client, now: float) -> None:
        """Start a config fetch when one is due and apply the answer of a finished one. The request
        runs on a worker thread and is waited for only CONFIG_GRACE_S, so an unreachable Observe never
        holds up event collection."""
        job = self.runner.current("config")
        if job is not None and job.done and job.abandoned:
            self.runner.finish("config")  # its answer came after it was given up on
            job = None
        started = False
        if job is None:
            if now < self._config_next:
                return
            job = self.runner.start("config", lambda: self._request_config(client))
            started = True
        if started:
            job.wait(CONFIG_GRACE_S)
        if job.done:
            self.runner.finish("config")
            try:
                outcome = job.value()
            except Exception as exc:
                outcome = ("fail", f"agent-config could not be read: {type(exc).__name__}: {exc}")
            self._apply_config(outcome)
        elif job.age() > CONFIG_HANG_S and not job.abandoned:
            job.abandoned = True
            self._config_failed(f"Observe gave no answer for agent-config within {CONFIG_HANG_S:g}s")

    def _apply_config(self, outcome: tuple[str, Any]) -> bool:
        kind, body = outcome
        if kind != "ok":
            self._config_failed(body)
            return False
        rates = tiers.parse_agent_config(body)
        if rates is None:
            self._config_failed("the agent-config answer has no usable intervals")
            return False
        if isinstance(body, dict) and isinstance(body.get("host"), str) \
                and body["host"].strip().lower() != self.cfg.host_name.strip().lower():
            log.warning("Observe's agent-config names host %r but HOSTWATCH_HOST_NAME is %r",
                        body["host"], self.cfg.host_name)
        before = self.schedule.rates()
        self.schedule.apply(rates)
        self.schedule.reschedule(self._clock())
        self._config_next = self._clock() + tiers.CONFIG_REFRESH_S
        changed = self.schedule.rates() != before
        if self._config_ok is not True or changed:
            log.info("polling rates from Observe: %s", self._rates_text())
        self._config_ok = True
        return changed

    def _rates_text(self) -> str:
        return ", ".join(f"{t}={v:g}s" for t, v in self.schedule.rates().items())

    def _config_failed(self, reason: str) -> None:
        self._config_next = self._clock() + tiers.CONFIG_RETRY_S
        if self._config_ok is not False:
            log.warning("%s; using the polling rates in force (%s)", reason, self._rates_text())
        self._config_ok = False

    # -- events ------------------------------------------------------------------------------

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
        The event is queued for the next event read; Observe deduplicates by boot_id.
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

    def _probe_source(self, c) -> tuple[bool, str, bool]:
        """Detection of one collector, run on its worker thread: whether the source is there, why not,
        and whether the host positively has no such source."""
        try:
            ok, reason = c.detect()
        except Exception as exc:
            ok, reason = False, f"detect error: {type(exc).__name__}: {exc}"
        absent = False
        if not ok:
            try:
                absent = c.is_absent()
            except Exception as exc:
                log.warning("source %s: could not establish absence: %s", c.id, exc)
        return ok, reason, absent

    def _apply_detect(self, c, ok: bool, reason: str, absent: bool) -> None:
        prev = self.status.get(c.id)
        if prev is None or prev.pending or prev.available != ok:
            log.info("source %s: %s %s", c.id, "available" if ok else "unavailable", reason)
        self._retry.pop(c.id, None)  # detection is the authority on whether the source is there
        self.status[c.id] = SourceStatus(source=c.id, available=ok, reason=reason, present=not absent)

    def _start_detect(self) -> None:
        """Begin a detection round: one worker per collector, so a source that cannot answer (an
        unreachable TrueNAS, NUT or Scrutiny) holds up nobody else. Until a collector has answered
        once its status is a pending placeholder, and the collector is not read."""
        self._last_detect = self._clock()
        for c in self.collectors:
            if self.platform == "windows" and c.linux_only:
                # Nothing was probed: these sources read sysfs, procfs or /run, which a Windows host
                # does not have, so they are not present rather than present but unavailable.
                self._apply_detect(c, False, f"{c.id} reads Linux-only locations and is not present on Windows",
                                   True)
                continue
            if c.id not in self.status:
                self.status[c.id] = SourceStatus(source=c.id, available=False, reason="detection in progress",
                                                 pending=True)
            key = f"{c.id}:detect"
            self._detect_round.append((c, self.runner.start(key, lambda c=c: self._probe_source(c), c.id), key))

    def _settle_detect(self, wait_s: float | None) -> None:
        """Take the answers of the detection round. A worker past its collector's time limit is given
        up on: a source that never answered is reported unavailable with that reason, and a source that
        already had an answer keeps it. With `wait_s` None this waits for every worker up to its limit;
        otherwise for at most `wait_s` in total."""
        deadline = None if wait_s is None else time.monotonic() + wait_s
        remaining: list[tuple] = []
        for c, job, key in self._detect_round:
            limit = c.time_limit_s
            room = limit - job.age() if deadline is None else min(limit - job.age(), deadline - time.monotonic())
            job.wait(max(0.0, room))
            if job.done:
                self.runner.finish(key)
                try:
                    ok, reason, absent = job.value()
                except Exception as exc:
                    ok, reason, absent = False, f"detect error: {type(exc).__name__}: {exc}", False
                self._apply_detect(c, ok, reason, absent)
            elif job.age() >= limit:
                if not job.abandoned:
                    job.abandoned = True
                    why = f"detect error: CollectorTimeout: no answer within {limit:g}s"
                    log.warning("source %s: %s", c.id, why)
                    prev = self.status.get(c.id)
                    if prev is None or prev.pending:
                        self._apply_detect(c, False, why, False)
            else:
                remaining.append((c, job, key))
        self._detect_round = remaining

    def _service_detect(self, grace_s: float | None, block: bool = False) -> None:
        """Keep detection moving without waiting for it. A round is started when none is running and
        the last one is older than redetect_s, then given `grace_s` once so a quick source is known
        in the same pass. After that a round is only looked at, never waited for. `block` waits for
        the whole round, for a caller that has to read the sources straight away."""
        started = False
        if not self._detect_round and (self._last_detect is None
                                       or self._clock() - self._last_detect > self.cfg.redetect_s):
            self._start_detect()
            started = True
        if self._detect_round:
            self._settle_detect(None if block else (grace_s if started else 0.0))

    def detect(self) -> None:
        """Detect every source and wait for the answers, each within its time limit. The loop does
        not call this: it uses `_service_detect`, which never waits for a slow source."""
        if not self._detect_round:
            self._start_detect()
        self._settle_detect(None)

    def _retry_now(self, c) -> bool:
        """Whether an unavailable source is read again now. A source that failed after it was
        detected is tried again once its back-off has passed. A configured polled source is tried
        again every cycle."""
        failed = self._retry.get(c.id)
        if failed is not None:
            return self._clock() >= failed[1]
        if not c.retry_each_cycle:
            return False
        try:
            return not c.is_absent()
        except Exception:
            return False

    # -- collection --------------------------------------------------------------------------

    def _ensure_detected(self) -> None:
        self._service_detect(DETECT_GRACE_S, block=True)

    def _launch(self, tier: str | None, watched: bool) -> list[tuple]:
        """Start a worker for each collector of the tier (or each watched or probed collector when
        `watched`), skipping a source that is unavailable until the next detection, except a
        configured network source, which is tried every time. A collector whose earlier call is
        still running gets no second one: the same worker is handed back."""
        launched = []
        for c in self.collectors:
            if watched:
                if not (c.event_watch or c.event_probe):
                    continue
            elif tier is not None and c.tier != tier:
                continue
            if not self.status[c.id].available and not self._retry_now(c):
                continue
            probe = watched and c.event_probe
            key = f"{c.id}:{'watch' if watched else 'tier'}"
            # A probe that shares nothing with the tier read does not queue behind it.
            share = None if probe and c.probe_independent else c.id
            launched.append((c, self.runner.start(key, c.probe if probe else c.collect, share), key))
        return launched

    def _settle(self, launched: list[tuple], wait_s: float | None) -> tuple[list[Sample], list[tuple]]:
        """Take the answers of started workers. Returns the samples of those that finished and the
        workers still inside their time limit. A worker past its limit is given up on: the source is
        reported unavailable with the reason and the worker's late answer is discarded. With `wait_s`
        None this waits for every worker up to its limit; otherwise for at most `wait_s` in total."""
        deadline = None if wait_s is None else time.monotonic() + wait_s
        samples: list[Sample] = []
        pending: list[tuple] = []
        for c, job, key in launched:
            limit = c.time_limit_s
            room = limit - job.age() if deadline is None else min(limit - job.age(), deadline - time.monotonic())
            job.wait(max(0.0, room))
            if job.done:
                self.runner.finish(key)
                try:
                    samples.extend(self._record(c, job.value()))
                except Exception as exc:
                    self._record_failure(c, exc)
            elif job.age() >= limit:
                if not job.abandoned:  # report a hang once, not on every pass until it returns
                    job.abandoned = True
                    self._record_failure(c, CollectorTimeout(f"no answer within {limit:g}s"))
            else:
                pending.append((c, job, key))
        return samples, pending

    def _record(self, c, samples: list[Sample]) -> list[Sample]:
        self._retry.pop(c.id, None)
        if not self.status[c.id].available:
            log.info("source %s: available again", c.id)
            self.status[c.id] = SourceStatus(source=c.id, available=True, reason="")
        return samples

    def _record_failure(self, c, exc: BaseException) -> None:
        log.warning("collector %s failed: %s", c.id, exc)
        if not c.retry_each_cycle:
            # One transient error must not blind the source until the next full detection: read it
            # again after a short back-off that doubles with each failure in a row.
            failures = self._retry.get(c.id, (0, 0.0))[0] + 1
            wait = min(COLLECT_RETRY_BASE_S * 2 ** (failures - 1), max(COLLECT_RETRY_BASE_S, self.cfg.redetect_s))
            self._retry[c.id] = (failures, self._clock() + wait)
        self.status[c.id] = SourceStatus(source=c.id, available=False,
                                         reason=f"collect error: {type(exc).__name__}: {exc}")

    def collect_samples(self, tier: str | None = None, watched: bool = False) -> list[Sample]:
        """Samples from the collectors of one tier (or all when `tier` is None), or from the
        watched and probed collectors. Every collector runs on a worker thread within its time
        limit. The watched read waits only EVENT_GRACE_S and leaves a slow collector to finish for a
        later read, so it is safe on the event path; a tier read waits for each collector up to its
        limit."""
        if watched:
            self._service_detect(DETECT_GRACE_S)  # the event path never waits for a slow source
        else:
            self._ensure_detected()
        samples, _ = self._settle(self._launch(tier, watched), EVENT_GRACE_S if watched else None)
        return samples

    def _outbox_status(self) -> None:
        dropped = self.outbox.dropped_since_drain()
        dead = self.outbox.dead_letter_count()
        notes = []
        if dropped:
            notes.append(f"outbox over a limit: {self.outbox.dropped_points_total()} data point(s) and "
                         f"{self.outbox.dropped_records_total()} log record(s) dropped in total; events are dropped last")
        if dead:
            notes.append(f"{dead} request(s) refused by Observe are in the dead-letter table")
        rejected = self.outbox.rejected_points_total() + self.outbox.rejected_records_total()
        if rejected:
            notes.append(f"Observe accepted but rejected {rejected} item(s) in total")
        quarantined = self.outbox.quarantined_total()
        if quarantined:
            notes.append(f"{quarantined} item(s) could not be encoded and were quarantined in total")
        if self._stall_since is not None:
            notes.append(f"delivery to Observe has stalled for {self._clock() - self._stall_since:.0f}s; "
                         f"{self.outbox.depth()} request(s) are queued and kept")
        if self.outbox.recovered_from is not None:
            notes.append(f"the outbox file was corrupt and was moved to {self.outbox.recovered_from.name}; "
                         "requests and progress markers in it were lost")
        self.status["outbox"] = SourceStatus(source="outbox", available=not dropped, reason="; ".join(notes))

    def _source_change_logs(self, now: float) -> list[LogRecord]:
        """One observe.source.change log for each source whose availability differs from the last
        one reported. A source first seen available is not news, so it is recorded silently. This
        runs on every tier, so a failure on a slow tier is logged when it happens and not at the
        next availability report."""
        out: list[LogRecord] = []
        for st in self.status.values():
            # A source that is positively not on this host is not a failure, so it counts as fine.
            if st.pending:
                continue  # a first read that is still running says nothing yet
            fine = st.available or not st.present
            before = self._reported.get(st.source)
            if before is None and fine:
                self._reported[st.source] = True
            elif before != fine:
                self._reported[st.source] = fine
                out.append(otel_map.map_source_change(st.source, fine, st.reason, now))
        return out

    def _new_failsafe_logs(self, samples: list[Sample]) -> list[LogRecord]:
        """A failsafe is logged when a reason first appears, not on every poll while it lasts."""
        current = {(r.scope, r.attributes["observe.thermal.reason"]): r for r in otel_map.failsafe_logs(samples)}
        scopes = {otel_map.scope_name(s.source) for s in samples if s.metric == "failsafe"}
        fresh = [r for key, r in current.items() if key not in self._failsafe_open]
        self._failsafe_open = {k for k in self._failsafe_open if k[0] not in scopes} | set(current)
        return fresh

    def run_tier(self, tier: str) -> None:
        """Collect one tier, wait for it and queue the result."""
        self._complete_tier(tier, self.collect_samples(tier))

    def _begin_tier(self, tier: str) -> None:
        self._service_detect(DETECT_GRACE_S)
        self._tier_runs[tier] = _TierRun(self._launch(tier, False))

    def _harvest_tier(self, tier: str) -> None:
        """Take what the tier's collectors have finished and queue the tier once all are done or
        given up on. Until then the run stays in flight and the loop does other work."""
        run = self._tier_runs[tier]
        got, run.pending = self._settle(run.pending, TIER_GRACE_S)
        run.samples.extend(got)
        if run.pending:
            return
        del self._tier_runs[tier]
        self._complete_tier(tier, run.samples)

    def _complete_tier(self, tier: str, samples: list[Sample]) -> None:
        """Queue the result of one tier. The availability tier carries the heartbeat, the source
        status report and the rates in force instead of collector readings."""
        now = self._wall()
        points: list[Point] = otel_map.map_samples(samples, self.map_context)
        logs = self._new_failsafe_logs(samples)
        logs += self._source_change_logs(now)
        events = self._threshold_events(samples)
        if tier == tiers.AVAILABILITY:
            self._outbox_status()
            points += [otel_map.heartbeat_point(now), *otel_map.map_source_status(self.status.values(), now),
                       *otel_map.rejected_points(self.outbox.rejected_points_total(),
                                                 self.outbox.rejected_records_total(), now),
                       *otel_map.tier_interval_points(self.schedule.rates(), now)]
        logs += [otel_map.map_event(e) for e in events]
        self._enqueue(points, logs)

    def _threshold_events(self, samples: list[Sample]) -> list[Event]:
        events = self.thresholds.evaluate(samples, self.status.values())
        state = self.thresholds.dump()
        if state != self.outbox.get(THRESHOLD_MARKER):
            self.outbox.stage(THRESHOLD_MARKER, state)
        return events

    def _incident_logs(self) -> list[LogRecord]:
        """One observe.source.change log for each outbox problem not yet reported (a file that
        was found corrupt, or the first items Observe rejected). The outbox source is marked as
        reported unavailable, so the next source change pass reports it available again."""
        self._outbox_incidents.extend(self.outbox.take_incidents())
        if not self._outbox_incidents:
            return []
        now = self._wall()
        out = [otel_map.map_source_change("outbox", False, text, now) for text in self._outbox_incidents]
        self._outbox_incidents = []
        self._reported["outbox"] = False
        return out

    def _enqueue(self, points: list[Point], logs: list[LogRecord]) -> None:
        """Queue points and logs, then queue any outbox incident the write itself caused, so a
        recovery during this write is reported on this pass."""
        self._enqueue_entry(points, [*logs, *self._incident_logs()])
        late = self._incident_logs()
        if late:
            self._enqueue_entry([], late)

    def _enqueue_entry(self, points: list[Point], logs: list[LogRecord]) -> None:
        """Encode points and logs as OTLP requests and write them, with the staged markers, to the
        outbox in one transaction. Nothing is queued for an empty list."""
        entry_id = uuid.uuid4().hex
        opts = {"fmt": self.cfg.otlp_format, "compress": self.cfg.otlp_gzip}
        built = [otlp.build_metrics_requests(entry_id, self.resource, points, start_ts=self.started_at, **opts),
                 otlp.build_logs_requests(entry_id, self.resource, logs, **opts)]
        for b in built:
            if b.skipped:
                log.warning("%d item(s) were left out of a request because Observe would refuse them", b.skipped)
        self.outbox.note_quarantined("metrics", built[0].quarantined)
        self.outbox.note_quarantined("logs", built[1].quarantined)
        for b in built:
            if b.quarantined:
                log.warning("%d item(s) could not be encoded and were quarantined, not queued", b.quarantined)
        self.outbox.enqueue([r for b in built for r in b.requests], entry_id)

    def event_cycle(self, watch: bool) -> None:
        """Read the event sources, and the watched sources when `watch` is set, and queue everything
        found as logs, so it leaves for Observe on this pass."""
        events = self.pending_events
        self._stage_pending([])
        events.extend(self._collect_events())
        if watch:
            events.extend(self._threshold_events(self.collect_samples(watched=True)))
        self._enqueue([], [otel_map.map_event(e) for e in events])

    def _guard(self, what: str, run: Callable[[], None]) -> bool:
        """Run one unit of work without letting an exception end the loop. On failure the staged
        markers and the in-process dedup keys of the failed unit are discarded so nothing is
        skipped, the failure is logged, and the agent source is reported unavailable with the
        reason until a unit succeeds."""
        self._cycle_keys = []
        threshold_state = dict(self.thresholds.state)
        try:
            run()
        except Exception as exc:
            log.exception("agent %s failed; the loop continues", what)
            self.outbox.discard_staged()
            # Conditions opened by the failed unit were never queued, so forget them and let the
            # next unit emit them again.
            self.thresholds.state = threshold_state
            self.journal.rewind()
            for key in self._cycle_keys:
                self._seen_keys.pop(key, None)
            self.status["agent"] = SourceStatus(source="agent", available=False,
                                                reason=f"{what} error: {type(exc).__name__}: {exc}")
            return False
        self.status["agent"] = SourceStatus(source="agent", available=True, reason="")
        return True

    def tick(self, client: httpx.Client) -> None:
        """One pass of the loop: refresh the rates when due, run every tier that is due, read the
        events when due, then try to deliver. Nothing here may raise."""
        now = self._clock()
        self._poll_config(client, now)
        self._beat_if_due(now)
        # Events come first, so the first availability report already names the event sources.
        if now >= self._next_events:
            watch = now >= self._next_watch
            self._guard("event read", lambda: self.event_cycle(watch))
            # A journal backlog that is being worked off in batches is read again at once.
            self._next_events = now + (DRAIN_POLL_S if self.journal.draining else tiers.EVENT_POLL_S)
            if watch:
                self._next_watch = now + WATCH_S
            # Send the events before a slow tier can hold them back.
            self._try_flush(client)
        # Collectors run on worker threads, so a tier is started here and queued when its collectors
        # have answered or run out of time. Events are read at the top of every pass either way.
        for tier in self.schedule.due(self._clock()):
            if tier not in self._tier_runs:  # still running from an earlier beat: skip this one
                self._guard(f"{tier} poll", lambda tier=tier: self._begin_tier(tier))
            self.schedule.done(tier, self._clock())
        for tier in list(self._tier_runs):
            self._guard(f"{tier} poll", lambda tier=tier: self._harvest_tier(tier))
        self._try_flush(client)

    def sleep_s(self) -> float:
        """How long the loop may wait before the next thing is due."""
        now = self._clock()
        wait = min(tiers.EVENT_POLL_S, self.schedule.seconds_until_next(now), self._next_events - now)
        if self._tier_runs:
            wait = min(wait, TIER_GRACE_S)  # a tier is waiting on its collectors
        if self._next_flush > now:
            wait = min(wait, self._next_flush - now)  # a delayed delivery is due again then
        return max(0.1, wait)

    # -- delivery ----------------------------------------------------------------------------

    def flush(self, client: httpx.Client, deadline: float | None = None, honour_stop: bool = True) -> None:
        """Send queued requests oldest first. A request leaves the outbox only after a 2xx answer.
        A 200 that reports rejected items is acknowledged all the same, because the rejected items
        would be rejected again, and the count is kept. A status in DEAD_LETTER_STATUSES can never
        succeed and is dead-lettered so the head is not blocked. Any other failure raises
        DeliveryError and the request stays queued: those describe Observe, the key or the network.

        Each send times out after SEND_TIMEOUT_S seconds. A stop request ends the loop between sends
        (unless honour_stop is False, as in the final flush), and a monotonic deadline caps the total
        time. Unsent requests stay in the outbox either way.

        Acknowledgements are committed once at the end of the pass, also when the pass ends in an
        error, so a pass costs one fsync for them and not one per request. A crash before that commit
        only repeats requests, which carry the same Idempotency-Key."""
        self.outbox.prune()
        try:
            self._send_queued(client, deadline, honour_stop)
        except BaseException:
            # The delivery error (and its Retry-After) must reach the caller, so a failed commit here
            # is logged and the acknowledgements are sent again next pass under the same key.
            try:
                self.outbox.commit_acks()
            except Exception:
                log.warning("could not commit acknowledgements after a failed delivery pass", exc_info=True)
            raise
        self.outbox.commit_acks()

    def _send_queued(self, client: httpx.Client, deadline: float | None, honour_stop: bool) -> None:
        unflushed = 0
        self._pass_acked = 0
        # A backlog of readings goes out as a few large requests instead of one per cycle. The join
        # is skipped when a stop was requested and in the final flush (honour_stop False), whose time
        # budget the decompress, merge and compress work would otherwise not count against. The
        # outbox itself never joins a request that has been sent (see Outbox.note_attempt).
        try:
            if honour_stop and not self._stop.is_set():
                self.outbox.coalesce_metrics()
        except Exception:
            log.warning("could not join queued metrics requests; sending them as they are", exc_info=True)
        while (req := self.outbox.peek()) is not None:
            if honour_stop and self._stop.is_set():
                return
            timeout = SEND_TIMEOUT_S
            if deadline is not None:
                remaining = deadline - self._clock()
                if remaining <= 0:
                    raise TimeoutError("delivery time budget used up")
                timeout = min(timeout, remaining)
            headers = {**req.headers, "Authorization": f"Bearer {self.cfg.ingest_key}",
                       "User-Agent": f"hostwatch/{__version__}"}
            self.outbox.note_attempt(req.seq)
            r = client.post(self.cfg.observe_url + req.path, content=req.body, headers=headers, timeout=timeout)
            if r.status_code in DEAD_LETTER_STATUSES:
                self.outbox.dead_letter(req.seq, r.status_code, _problem_text(r))
                continue
            if r.is_success:
                if r.status_code == 200:
                    rejected, message = otlp.parse_partial_success(
                        r.content, r.headers.get("content-type", ""), req.signal)
                    if rejected or message:
                        self.outbox.note_rejected(req.signal, rejected)
                        if req.signal not in self._rejection_reported:
                            self._rejection_reported.add(req.signal)
                            self._outbox_incidents.append(
                                f"Observe accepted a {req.signal} request but rejected {rejected} item(s): "
                                f"{message or 'no reason given'}; further rejections are counted in "
                                "observe.agent.rejected.items")
                        log.warning("Observe accepted %s request %s but rejected %d item(s): %s",
                                    req.signal, req.entry_id, rejected, message or "no reason given")
                self.outbox.ack(req.seq, commit=False)
                self._pass_acked += 1
                unflushed += 1
                if unflushed >= ACK_COMMIT_EVERY:
                    self.outbox.commit_acks()
                    unflushed = 0
                continue
            if r.status_code in (401, 403):
                log.error("Observe answered %d. Check that HOSTWATCH_INGEST_KEY is valid and is bound to "
                          "the host name %r. Requests stay queued.", r.status_code, self.cfg.host_name)
            raise DeliveryError(f"Observe answered {r.status_code}", r.status_code, _retry_after(r))

    def _try_flush(self, client: httpx.Client) -> None:
        if self._clock() < self._next_flush:
            return
        try:
            self.flush(client)
        except Exception as exc:
            if self._pass_acked:
                # Observe took requests in this pass, so it is up and this is a limit, not an outage:
                # start the back-off again instead of climbing it across a drain.
                self._flush_failures = 0
            self._flush_failures += 1
            if self._stall_since is None:
                self._stall_since = self._clock()
            wait = self._backoff(self._flush_failures)
            if isinstance(exc, DeliveryError) and exc.retry_after > 0:
                # Observe named the wait, so wait that long and no longer.
                wait = min(exc.retry_after, MAX_BACKOFF_S)
            self._next_flush = self._clock() + wait
            log.warning("delivery failed (%s); %d request(s) queued, next attempt in %.0fs", exc,
                        self.outbox.depth(), wait)
        else:
            self._flush_failures, self._next_flush = 0, 0.0
            self._stall_since = None

    @staticmethod
    def _backoff(failures: int) -> float:
        return min(BACKOFF_BASE_S * 2 ** max(0, failures - 1), MAX_BACKOFF_S)

    def _warn_if_name_differs(self) -> None:
        """One warning, never a stop: a container often reports a name other than its host's."""
        own = socket.gethostname()
        wanted = self.cfg.host_name.strip().lower()
        if wanted and wanted not in {own.lower(), own.lower().split(".")[0]}:
            log.warning("HOSTWATCH_HOST_NAME is %r but this machine is named %r; data is reported under "
                        "%r. Check that this is the host you meant, unless this is a container.",
                        self.cfg.host_name, own, self.cfg.host_name)

    def run(self) -> None:
        """The loop. It writes the clean-shutdown flag itself when it exits, so a
        signal handler only has to call stop()."""
        try:
            self._service_detect(DETECT_GRACE_S)
            self._guarded_boot_check()
            with httpx.Client(verify=observe_tls_verify(self.cfg)) as client:
                while not self._stop.is_set():
                    try:
                        self.tick(client)
                    except Exception:  # last resort: nothing may end the loop
                        log.exception("unexpected error in the agent loop; continuing")
                    self._stop.wait(self.sleep_s())
        finally:
            self.finish()

    def _beat_if_due(self, now: float) -> None:
        if now >= self._next_beat:
            self._next_beat = now + HEARTBEAT_S
            self._beat()
            self._touch_alive()

    def _touch_alive(self) -> None:
        """Record that the loop is running, for the container health check. This says the agent
        loop turns; whether Observe receives the data is what the outbox status reports."""
        try:
            tmp = self.cfg.data_dir / (ALIVE_FILE + ".tmp")
            write_private(tmp, str(self._wall()))
            tmp.replace(self.cfg.data_dir / ALIVE_FILE)
        except OSError as exc:
            log.warning("cannot write %s: %s", ALIVE_FILE, exc)

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


def _retry_after(r: httpx.Response) -> float:
    """Retry-After in seconds. A date form or anything else unusable counts as no hint."""
    try:
        value = float(r.headers.get("retry-after", ""))
    except ValueError:
        return 0.0
    return value if math.isfinite(value) and value > 0 else 0.0


def _problem_text(r: httpx.Response) -> str:
    try:
        body = r.json()
        return str(body.get("detail") or body.get("title") or "") if isinstance(body, dict) else ""
    except ValueError:
        return ""
