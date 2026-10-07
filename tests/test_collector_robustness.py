"""Collectors and the journal recover on their own: a transient collector error is retried with a
short back-off, a large journal backlog is worked off in bounded batches, and detection and the
agent-config request run on worker threads so an unreachable source never stalls event collection."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import tracemalloc

import httpx
from agent_helpers import FakeObserve, body_json, event, log_records
from test_tiers import Clock, Counting, make_agent

from hostwatch import agent as agent_mod
from hostwatch import tiers
from hostwatch.agent import COLLECT_RETRY_BASE_S, DRAIN_POLL_S
from hostwatch.collectors.base import Collector
from hostwatch.events import journal
from hostwatch.events.journal import BackgroundJournal, JournalWatcher, LineList
from hostwatch.model import Sample, SourceStatus

# -- a transient collector error does not blind the source until the next detection -------------


class Flaky(Counting):
    """A collector whose first `failures` reads raise `error`."""

    def __init__(self, failures=1, error=None, **kw):
        super().__init__("flaky", tiers.DEVICE_METRICS, source="mdraid", **kw)
        self.failures = failures
        self.error = error or OSError("device busy")

    def collect(self):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error
        return [Sample(source="mdraid", metric="array_state", value=1.0, ts=1.0,
                       labels={"array": "md0", "state": "clean"})]


def test_one_oserror_then_success_gives_data_on_the_next_ticks(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    flaky = Flaky()
    agent.collectors = [flaky]
    assert agent.cfg.redetect_s >= 600  # the old behaviour waited this long
    queued: list[list[Sample]] = []
    real = agent._complete_tier
    agent._complete_tier = lambda tier, samples: (queued.append(list(samples)), real(tier, samples))[1]
    observe = FakeObserve(config={"intervals": {"device_metrics": 10, "availability": 10}})
    start = clock.t
    recovered = None
    with observe.client() as client:
        while clock.t < start + 120:
            agent.tick(client)
            if recovered is None and any(any(s.source == "mdraid" for s in q) for q in queued):
                recovered = clock.t - start
                break
            clock.t += 1
    assert flaky.calls >= 2
    assert recovered is not None and recovered <= COLLECT_RETRY_BASE_S + 10 + 2
    assert agent.status["flaky"].available is True and agent.status["flaky"].reason == ""


def test_a_failed_read_is_retried_with_a_doubling_back_off(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    flaky = Flaky(failures=2)
    agent.collectors = [flaky]
    agent.detect()
    assert agent.collect_samples(tiers.DEVICE_METRICS) == [] and flaky.calls == 1
    assert not agent.status["flaky"].available and "OSError" in agent.status["flaky"].reason
    clock.t += COLLECT_RETRY_BASE_S - 1
    agent.collect_samples(tiers.DEVICE_METRICS)
    assert flaky.calls == 1  # still backing off
    clock.t += 1
    assert agent.collect_samples(tiers.DEVICE_METRICS) == [] and flaky.calls == 2  # the second failure
    clock.t += 2 * COLLECT_RETRY_BASE_S - 1
    agent.collect_samples(tiers.DEVICE_METRICS)
    assert flaky.calls == 2  # the wait doubled
    clock.t += 1
    assert len(agent.collect_samples(tiers.DEVICE_METRICS)) == 1 and flaky.calls == 3
    assert agent.status["flaky"].available
    assert agent.collect_samples(tiers.DEVICE_METRICS) and flaky.calls == 4  # healthy again, read every time


def test_the_back_off_never_exceeds_the_redetect_interval(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock, redetect_s=30.0)
    flaky = Flaky(failures=100)
    agent.collectors = [flaky]
    agent.detect()
    for _ in range(8):
        agent.collect_samples(tiers.DEVICE_METRICS)
        clock.t += 31
        agent._last_detect = clock.t  # keep detection out of this test
    assert flaky.calls == 8  # one read per pass once the wait is capped at 30 s


class HangsOnce(Counting):
    def __init__(self):
        super().__init__("hangs", tiers.DEVICE_METRICS, source="mdraid")
        self.time_limit_s = 0.05
        self.release = threading.Event()

    def collect(self):
        self.calls += 1
        if self.calls == 1:
            self.release.wait(30)
        return [Sample(source="mdraid", metric="array_state", value=1.0, ts=1.0,
                       labels={"array": "md0", "state": "clean"})]


def test_a_timed_out_read_is_retried_after_the_back_off(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    slow = HangsOnce()
    agent.collectors = [slow]
    agent.detect()
    try:
        assert agent.collect_samples(tiers.DEVICE_METRICS) == []
        assert "CollectorTimeout" in agent.status["hangs"].reason
    finally:
        slow.release.set()
    assert agent.runner.current("hangs:tier").wait(5)
    clock.t += COLLECT_RETRY_BASE_S
    assert len(agent.collect_samples(tiers.DEVICE_METRICS)) == 1
    assert agent.status["hangs"].available


# -- a large journal backlog is worked off in bounded batches ------------------------------------

FAKE_JOURNALCTL = '''
import json, sys, time
TOTAL, PAD, HANG = %d, "x" * %d, %s
args = sys.argv[1:]
start = 0
if "--after-cursor" in args:
    start = int(args[args.index("--after-cursor") + 1].split("=")[1], 16) + 1
out = sys.stdout.buffer
try:
    for i in range(start, TOTAL):
        msg = "I/O error, dev sda, sector %%d" %% i if i and i %% 50000 == 0 else "kernel: " + PAD
        out.write((json.dumps({"__CURSOR": "s=%%08x" %% i, "MESSAGE": msg,
                               "__REALTIME_TIMESTAMP": "1790000000000000", "PRIORITY": "6"}) + "\\n").encode())
    out.flush()
    if HANG:
        time.sleep(600)
except OSError:
    pass
'''


def fake_journalctl(monkeypatch, tmp_path, total, pad=200, hang=False):
    """Run the journal reader against a real child process that prints `total` entries after the
    cursor and then, when `hang`, never exits."""
    script = tmp_path / "fake_journalctl.py"
    script.write_text(FAKE_JOURNALCTL % (total, pad, hang), encoding="utf-8")
    real_popen = subprocess.Popen
    monkeypatch.setattr(journal.shutil, "which", lambda name: "journalctl")
    monkeypatch.setattr(journal.subprocess, "Popen",
                        lambda cmd, **kw: real_popen([sys.executable, str(script), *cmd[1:]], **kw))
    jdir = tmp_path / "journal"
    jdir.mkdir(exist_ok=True)
    (jdir / "system.journal").write_bytes(b"x")
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return jdir, data


def test_a_100_mb_backlog_after_a_cursor_drains_in_batches_with_bounded_memory(monkeypatch, tmp_path):
    line_len = len(json.dumps({"__CURSOR": "s=00000000", "MESSAGE": "kernel: " + "x" * 200,
                               "__REALTIME_TIMESTAMP": "1790000000000000", "PRIORITY": "6"})) + 1
    total = 100 * 1024 * 1024 // line_len
    jdir, data = fake_journalctl(monkeypatch, tmp_path, total)
    (data / journal.CURSOR_FILE).write_text("s=00000000")
    batch_sizes = []
    real_process = JournalWatcher.process

    def counting_process(self, cursor, lines):
        batch_sizes.append(len(lines))
        return real_process(self, cursor, lines)

    monkeypatch.setattr(JournalWatcher, "process", counting_process)
    watcher = JournalWatcher(jdir, data)
    cursors, events = [watcher.load_cursor()], []
    tracemalloc.start()
    try:
        while True:
            status, found = watcher.read()
            assert status.available, status.reason
            events.extend(found)
            cursor = watcher.load_cursor()
            if cursor == cursors[-1]:
                break
            cursors.append(cursor)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert cursors[-1] == "s=%08x" % (total - 1)  # the whole backlog was read
    assert len(cursors) - 1 >= 100 * 1024 * 1024 // journal.BATCH_MAX_BYTES  # in batches, each moving the cursor
    assert cursors == sorted(set(cursors))  # strictly forward
    assert max(batch_sizes) <= journal.BATCH_MAX_LINES
    assert sum(batch_sizes) == total - 1
    assert len([e for e in events if e.kind == "disk.io_error"]) == (total - 1) // 50000
    assert peak < 96 * 1024 * 1024  # a batch is held, never the 100 MB backlog


def test_a_read_that_hits_the_time_limit_keeps_what_it_got_and_moves_the_cursor(monkeypatch, tmp_path):
    jdir, data = fake_journalctl(monkeypatch, tmp_path, total=300, hang=True)
    monkeypatch.setattr(journal, "JOURNALCTL_TIMEOUT_S", 1)
    (data / journal.CURSOR_FILE).write_text("s=00000000")
    watcher = JournalWatcher(jdir, data)
    status, _ = watcher.read()
    assert status.available
    assert watcher.load_cursor() == "s=%08x" % 299  # the livelock never advanced; this does


def test_a_full_batch_is_followed_by_the_next_read_at_once(tmp_path):
    batches = [LineList(json.dumps({"__CURSOR": "c1", "MESSAGE": "x"}) for _ in range(2)),
               LineList([json.dumps({"__CURSOR": "c2", "MESSAGE": "x"})])]
    batches[0].more = True

    def reader(directory, cursor):
        return batches.pop(0) if batches else LineList()

    jdir = tmp_path / "j"
    jdir.mkdir()
    (jdir / "system.journal").write_bytes(b"x")
    bg = BackgroundJournal(JournalWatcher(jdir, tmp_path, reader))
    bg.read()
    bg._thread.join(5)
    bg.read()
    assert bg.draining is True
    bg._thread.join(5)
    bg.read()
    assert bg.draining is False


def test_the_agent_reads_the_journal_again_soon_while_a_backlog_remains(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    agent.collectors = []
    agent.event_sources = {"journal": lambda: (SourceStatus(source="journal", available=True), [])}
    agent.journal.draining = True
    with FakeObserve().client() as client:
        agent.tick(client)
    assert agent._next_events == clock.t + DRAIN_POLL_S
    agent.journal.draining = False
    clock.t += 10
    with FakeObserve().client() as client:
        agent.tick(client)
    assert agent._next_events == clock.t + tiers.EVENT_POLL_S


# -- detection and the agent-config request never stall event collection ------------------------


class HangsDetect(Counting):
    def __init__(self):
        super().__init__("hungdetect", tiers.DEVICE_METRICS, source="mdraid")
        self.time_limit_s = 30.0
        self.release = threading.Event()

    def detect(self):
        self.release.wait(30)
        return True, ""


def sent_dedup_keys(observe):
    return [r["dedup_key"] for req in observe.posts if req.url.path == "/v1/logs"
            for r in log_records(body_json(req))]


def test_a_hung_detect_does_not_delay_a_journal_event(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    hung, good = HangsDetect(), Counting("good", tiers.DEVICE_METRICS)
    agent.collectors = [hung, good]
    agent.event_sources = {"journal": lambda: (SourceStatus(source="journal", available=True),
                                               [event(kind="md.degraded", key="journal:now", ts=clock.t)])}
    observe = FakeObserve()
    try:
        with observe.client() as client:
            began = time.monotonic()
            agent.tick(client)
            took = time.monotonic() - began
            assert "journal:now" in sent_dedup_keys(observe)  # left on the first pass
            assert took < 5.0  # nowhere near the detect's 30 s
            assert agent.status["hungdetect"].pending and not agent.status["hungdetect"].available
            clock.t += 1
            agent.tick(client)
            clock.t += 1
            agent.tick(client)
        assert agent.status["good"].available  # one source's hang does not hold up the others
        assert good.calls >= 1
        assert hung.calls == 0
    finally:
        hung.release.set()


def test_a_detect_that_never_answers_is_reported_unavailable_at_its_limit(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    hung = HangsDetect()
    hung.time_limit_s = 0.05
    agent.collectors = [hung]
    try:
        agent.detect()
        assert not agent.status["hungdetect"].available and not agent.status["hungdetect"].pending
        assert "no answer within" in agent.status["hungdetect"].reason
    finally:
        hung.release.set()
    assert agent.runner.current("hungdetect:detect").wait(5)
    clock.t += agent.cfg.redetect_s + 1
    agent._service_detect(None, block=True)  # the late answer is discarded and detection asks again
    assert agent.status["hungdetect"].available


def config_calls(observe):
    return [r for r in observe.calls if r.url.path == "/internal/v1/agent-config"]


class SlowConfig(FakeObserve):
    """An Observe whose agent-config request does not answer until released."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.release = threading.Event()

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/internal/v1/agent-config":
            self.calls.append(request)
            self.release.wait(30)
            return httpx.Response(200, json=self.config)
        return super().handler(request)


def test_an_unreachable_agent_config_does_not_stall_the_loop(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    agent.collectors = []
    agent.event_sources = {"journal": lambda: (SourceStatus(source="journal", available=True),
                                               [event(kind="md.degraded", key="journal:now", ts=clock.t)])}
    observe = SlowConfig(config={"host": "h1", "intervals": {"availability": 30}})
    try:
        with observe.client() as client:
            began = time.monotonic()
            agent.tick(client)
            assert time.monotonic() - began < 5.0
            assert "journal:now" in sent_dedup_keys(observe)
            assert len(config_calls(observe)) == 1
            agent.tick(client)  # still waiting: no second request is started
            assert len(config_calls(observe)) == 1
            observe.release.set()
            assert agent.runner.current("config").wait(5)
            clock.t += 1
            agent.tick(client)
        assert agent._config_ok is True and agent.schedule.rates()[tiers.AVAILABILITY] == 30.0
    finally:
        observe.release.set()


def test_a_config_request_that_never_returns_is_a_failure_not_a_stall(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_mod, "CONFIG_HANG_S", 0.0)
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    agent.collectors = []
    agent.event_sources = {}
    observe = SlowConfig(config={"intervals": {}})
    try:
        with observe.client() as client:
            agent.tick(client)
        assert agent._config_ok is False
    finally:
        observe.release.set()


class Needs(Collector):
    """Detection depends on a file, to see that a re-detect still works off the loop."""

    id = "needs"

    def __init__(self, path):
        super().__init__()
        self.path = path

    def detect(self):
        return self.path.exists(), "missing"

    def collect(self):
        return []


def test_redetection_runs_on_a_worker_and_picks_up_a_source_that_appeared(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    flag = tmp_path / "flag"
    agent.collectors = [Needs(flag)]
    agent.event_sources = {}
    with FakeObserve().client() as client:
        agent.tick(client)
        assert not agent.status["needs"].available
        flag.write_text("x")
        clock.t += agent.cfg.redetect_s + 1
        agent.tick(client)
    assert agent.status["needs"].available
