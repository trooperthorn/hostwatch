"""Failures and events are never delayed: a storage failure is raised from a probe while its tier is
slow, a collector that hangs is cut off at its time limit without holding up events, and after an outage
the logs leave before the older metrics."""

from __future__ import annotations

import threading
import time

from agent_helpers import FakeObserve, body_json, event, log_records
from test_tiers import Clock, Counting, make_agent
from test_win_storage import SMART, ok, seam_for

from hostwatch import tiers
from hostwatch.agent import EVENT_GRACE_S, WATCH_S
from hostwatch.collectors.base import Collector
from hostwatch.collectors.scrutiny import ScrutinyCollector
from hostwatch.collectors.win_storage import WinSmartctlCollector
from hostwatch.model import Sample, SourceStatus


def sent_event_names(observe) -> list[str]:
    return [r["event"] for req in observe.posts if req.url.path == "/v1/logs"
            for r in log_records(body_json(req))]


class FakeScrutiny(ScrutinyCollector):
    """Scrutiny with a disk whose status the test can change, and no network."""

    def __init__(self) -> None:
        super().__init__(None, None, "http://scrutiny.test")
        self.status = 0
        self.fetches = 0

    def _fetch(self) -> dict:
        self.fetches += 1
        return {"data": {"summary": {"w1": {"device": {"device_name": "sda", "device_status": self.status},
                                            "smart": {}}}}}


def test_a_scrutiny_failure_is_raised_within_one_event_cycle_while_the_tier_is_slow(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    scrutiny = FakeScrutiny()
    agent.collectors = [scrutiny]
    observe = FakeObserve(config={"intervals": {"storage_health": 86400}})
    start = clock.t
    failed = None
    with observe.client() as client:
        while clock.t <= start + 600:
            if failed is None and clock.t >= start + 101:
                scrutiny.status = 2
                failed = clock.t
            agent.tick(client)
            if "hostwatch.scrutiny.status_raised" in sent_event_names(observe):
                break
            clock.t += 1
    assert failed is not None and "hostwatch.scrutiny.status_raised" in sent_event_names(observe)
    # The tier ran once, at the start. The event came from the probe, one watch interval and one event
    # poll after the disk failed at the latest.
    assert clock.t - failed <= WATCH_S + tiers.EVENT_POLL_S
    assert clock.t - start < 86400


def test_the_smartctl_probe_reads_only_the_health_verdict(tmp_path):
    c = WinSmartctlCollector(seam=seam_for(results=[ok(SMART["scan"]), ok(SMART["sata_ok"]),
                                                    ok(SMART["nvme_failing"])]))
    assert c.event_probe
    got = c.probe()
    assert got and {s.metric for s in got} == {"smart_passed"}
    assert c.time_limit_s > 60.0  # a full read of many drives needs a longer limit than the default


class Hangs(Collector):
    """A collector whose read never returns until the test lets it."""

    id = "hung"
    tier = tiers.STORAGE_HEALTH

    def __init__(self, limit: float) -> None:
        super().__init__()
        self.time_limit_s = limit
        self.release = threading.Event()
        self.calls = 0

    def detect(self):
        return True, ""

    def collect(self):
        self.calls += 1
        self.release.wait(30)
        return [Sample(source="hung", metric="array_state", value=1.0, ts=1.0, labels={})]


def test_a_collector_that_hangs_does_not_delay_events_and_is_cut_off_at_its_limit(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    hung = Hangs(limit=0.05)
    agent.collectors = [hung]
    emitted: list = []
    agent.event_sources = {"journal": lambda: (SourceStatus(source="journal", available=True), list(emitted))}
    observe = FakeObserve()
    slowest = 0.0
    try:
        with observe.client() as client:
            for i in range(40):
                if i == 3:
                    emitted.append(event(kind="md.degraded", key="journal:late", ts=clock.t))
                began = time.monotonic()
                agent.tick(client)
                slowest = max(slowest, time.monotonic() - began)
                if i >= 3 and any(r["dedup_key"] == "journal:late" for req in observe.posts
                                  if req.url.path == "/v1/logs" for r in log_records(body_json(req))):
                    if not agent.status["hung"].available:
                        break
                clock.t += 1
    finally:
        hung.release.set()
    sent = [r["dedup_key"] for req in observe.posts if req.url.path == "/v1/logs"
            for r in log_records(body_json(req))]
    assert "journal:late" in sent  # the event left on the pass that found it
    assert not agent.status["hung"].available
    assert "CollectorTimeout" in agent.status["hung"].reason
    assert hung.calls == 1  # one worker, never a pile of them
    # No pass waited for the hang: each took about the grace period, nowhere near the worker's 30 s.
    assert slowest < 10 * (EVENT_GRACE_S + tiers.EVENT_POLL_S)


def test_a_probe_that_hangs_leaves_other_probes_and_events_alone(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    hung = Hangs(limit=0.05)
    hung.event_probe = True
    quick = FakeScrutiny()
    agent.collectors = [hung, quick]
    observe = FakeObserve(config={"intervals": {"storage_health": 86400}})
    try:
        with observe.client() as client:
            for i in range(60):
                if i == 5:
                    quick.status = 1
                agent.tick(client)
                if "hostwatch.scrutiny.status_raised" in sent_event_names(observe):
                    break
                clock.t += 1
    finally:
        hung.release.set()
    assert "hostwatch.scrutiny.status_raised" in sent_event_names(observe)


def test_logs_leave_before_older_metrics_after_an_outage(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    agent.collectors = [Counting("md", tiers.DEVICE_METRICS)]
    emitted: list = []
    agent.event_sources = {"journal": lambda: (SourceStatus(source="journal", available=True), list(emitted))}
    down = FakeObserve(answers=[503])
    with down.client() as client:
        for i in range(3):  # metrics pile up while Observe is down
            agent.tick(client)
            clock.t += 61
        emitted.append(event(kind="md.degraded", key="journal:during-outage", ts=clock.t))
        agent.tick(client)
    queued = [(r.signal, r.seq) for r in _queue(agent)]
    assert any(sig == "metrics" for sig, _ in queued) and any(sig == "logs" for sig, _ in queued)
    up = FakeObserve()
    agent._next_flush = 0.0
    with up.client() as client:
        agent.flush(client)
    paths = up.signals()
    assert "/v1/logs" in paths and "/v1/metrics" in paths
    assert paths.index("/v1/logs") < paths.index("/v1/metrics")
    first_logs = [r["dedup_key"] for r in log_records(body_json(next(p for p in up.posts
                                                                     if p.url.path == "/v1/logs")))]
    assert "journal:during-outage" in first_logs


def _queue(agent):
    """The queued requests, oldest first, as (seq, signal) rows."""
    rows = agent.outbox._db.execute("SELECT seq, signal FROM requests ORDER BY seq").fetchall()
    return [type("Row", (), {"seq": seq, "signal": signal}) for seq, signal in rows]


def test_an_event_with_an_unpaired_surrogate_does_not_block_the_others(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    agent.collectors = []
    bad = event(kind="md.degraded", key="journal:bad", ts=clock.t)
    bad = bad.model_copy(update={"title": "disk \ud800 failed"})
    good = event(kind="md.degraded", key="journal:good", ts=clock.t)
    agent.event_sources = {"journal": lambda: (SourceStatus(source="journal", available=True), [bad, good])}
    observe = FakeObserve()
    with observe.client() as client:
        agent.tick(client)
    sent = [r["dedup_key"] for req in observe.posts if req.url.path == "/v1/logs"
            for r in log_records(body_json(req))]
    assert "journal:good" in sent
