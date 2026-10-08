"""Fast backlog drain, and no PowerShell on the agent's main loop.

The drain tests play a rate-limited Observe on a fake clock, so they take no real time. The Windows
test uses a PowerShell fake that blocks until the test lets it go, which is how a slow spawn looks to
the loop. Nothing here touches the network, a process or pywin32.
"""

from __future__ import annotations

import logging
import math
import threading

import httpx
import pytest
from agent_helpers import FakeObserve, body_json, event_cycle, request_json
from fakes_windows import FakeCimQuery, FakeCommandRunner, FakePipeStatusReader
from test_outbox import make_cfg, pt, requests_for

import hostwatch.agent as agent_mod
from hostwatch import otlp
from hostwatch.agent import Agent
from hostwatch.outbox import Outbox
from hostwatch.windows import CommandResult, PowerShellEventLogReader, WindowsSeam
from hostwatch.windows import service as svc

RES = {"host.name": "h"}
LIMIT_PER_MIN = 120
QUEUED = 552


class RateLimited:
    """Observe's ingest limit: a token bucket per key that holds LIMIT_PER_MIN tokens and refills at
    that rate per minute. A request without a token gets a 429 with Retry-After set to the whole
    seconds until a token is back."""

    def __init__(self, clock: dict) -> None:
        self.clock, self.tokens, self.last, self.answers = clock, float(LIMIT_PER_MIN), clock["t"], []

    def take(self) -> int | None:
        """None when a request is accepted, else the Retry-After seconds."""
        now = self.clock["t"]
        self.tokens = min(float(LIMIT_PER_MIN), self.tokens + (now - self.last) * LIMIT_PER_MIN / 60.0)
        self.last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            self.answers.append(200)
            return None
        self.answers.append(429)
        return max(1, math.ceil((1.0 - self.tokens) * 60.0 / LIMIT_PER_MIN))

    def handler(self, request: httpx.Request) -> httpx.Response:
        wait = self.take()
        if wait is None:
            return httpx.Response(200)
        return httpx.Response(429, headers={"Retry-After": str(wait)})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def old_drain_seconds(total: int) -> float:
    """The time the delivery loop before this change needs under the same limit. It restarted its
    back-off only after a pass that sent everything, so under a sustained limit every refused pass
    climbed 5, 10, 20 ... up to the 300 s cap; a Retry-After longer than that step won, a shorter one
    changed nothing."""
    clock = {"t": 0.0}
    server = RateLimited(clock)
    sent = failures = 0
    while sent < total:
        while sent < total and (retry_after := server.take()) is None:
            sent += 1
        if sent >= total:
            break
        failures += 1
        clock["t"] += min(max(min(5.0 * 2 ** (failures - 1), 300.0), retry_after), 300.0)
    return clock["t"]


def new_drain_seconds(tmp_path, entries: int, make_requests) -> tuple[float, int, int]:
    clock = {"t": 1000.0}
    agent = Agent(make_cfg(tmp_path), clock=lambda: clock["t"])
    for i in range(entries):
        agent.outbox.enqueue(make_requests(i), f"e{i}")
    queued = agent.outbox.depth()
    server = RateLimited(clock)
    started, passes = clock["t"], 0
    with server.client() as client:
        while agent.outbox.depth() and passes < 10_000:
            agent._try_flush(client)
            passes += 1
            clock["t"] = max(clock["t"], agent._next_flush)
    assert agent.outbox.depth() == 0 and agent.outbox.dead_letter_count() == 0
    return clock["t"] - started, queued, server.answers.count(200)


def test_552_queued_requests_drain_within_one_and_a_half_times_the_ideal_time(tmp_path):
    ideal = QUEUED / LIMIT_PER_MIN * 60.0
    elapsed, queued, delivered = new_drain_seconds(tmp_path, QUEUED, lambda i: requests_for(f"e{i}", n_records=1))
    assert queued == QUEUED and delivered == QUEUED
    assert elapsed <= 1.5 * ideal, f"{elapsed:.0f}s against an ideal {ideal:.0f}s"
    # The model of the old loop shows why this needed a change: it climbs to the cap.
    assert old_drain_seconds(QUEUED) > 1.5 * ideal


def test_a_pass_that_made_progress_restarts_the_back_off(tmp_path):
    clock = {"t": 1000.0}
    agent = Agent(make_cfg(tmp_path), clock=lambda: clock["t"])
    agent._flush_failures = 6  # a long outage had climbed the back-off
    for i in range(3):
        agent.outbox.enqueue(requests_for(f"e{i}", n_records=1), f"e{i}")
    with FakeObserve(answers=[200, 200, 503]).client() as client:
        agent._try_flush(client)
    assert agent._flush_failures == 1
    assert agent._next_flush == 1000.0 + agent_mod.BACKOFF_BASE_S


def test_a_retry_after_is_honoured_without_climbing(tmp_path):
    clock = {"t": 1000.0}
    agent = Agent(make_cfg(tmp_path), clock=lambda: clock["t"])
    agent.outbox.enqueue(requests_for("e", n_records=1), "e")
    with FakeObserve(answers=[(429, {"Retry-After": "2"}, b"")]).client() as client:
        for _ in range(5):
            agent._next_flush = 0.0
            agent._try_flush(client)
            assert agent._next_flush == 1000.0 + 2
    assert agent._flush_failures == 5


def test_the_loop_wakes_when_a_delayed_delivery_is_due(tmp_path):
    clock = {"t": 1000.0}
    agent = Agent(make_cfg(tmp_path), clock=lambda: clock["t"])
    agent._next_events = 1000.0 + 100
    agent.schedule.seconds_until_next = lambda now: 100.0
    agent._next_flush = 1000.0 + 0.7
    assert agent.sleep_s() == pytest.approx(0.7)


# -- coalescing --------------------------------------------------------------------------------

def points_of(tree: dict) -> list[tuple]:
    out = []
    for rm in tree["resourceMetrics"]:
        for sm in rm["scopeMetrics"]:
            for m in sm["metrics"]:
                for dp in (m.get("gauge") or m["sum"])["dataPoints"]:
                    attrs = tuple(sorted((a["key"], str(a["value"])) for a in dp.get("attributes", [])))
                    out.append((sm["scope"]["name"], m["name"], str(dp["timeUnixNano"]), dp["asDouble"], attrs))
    return sorted(out)


def backlog_requests(i: int, **kw):
    from hostwatch.otel_map import GAUGE, Point
    base = 1_700_000_000.0 + i * 30.0
    pts = [Point(f"hostwatch.collector.c{j % 4}", f"hw.metric.{j}", "1", GAUGE, i + j / 7, base + j * 0.001,
                 {"disk": f"d{j % 3}"}) for j in range(40)]
    return otlp.build_metrics_requests(f"e{i}", RES, pts, **kw).requests


@pytest.mark.parametrize("fmt,compress", [("json", True), ("protobuf", False)])
def test_a_six_hour_backlog_goes_out_in_far_fewer_requests_with_the_same_content(tmp_path, fmt, compress):
    entries = 6 * 3600 // 30  # one reading every 30 seconds for 6 hours
    agent = Agent(make_cfg(tmp_path))
    built = [backlog_requests(i, fmt=fmt, compress=compress) for i in range(entries)]
    expected = sorted(p for requests in built for r in requests for p in points_of(request_json(r)))
    assert len(expected) == entries * 40
    for i, requests in enumerate(built):
        agent.outbox.enqueue(requests, f"e{i}")
    assert agent.outbox.depth() == entries
    observe = FakeObserve()
    with observe.client() as client:
        agent.flush(client)
    sent = [p for r in observe.posts for p in points_of(body_json(r))]
    assert sorted(sent) == expected  # identical decoded content
    assert len(observe.posts) <= entries // 20
    for r in observe.posts:
        assert len(r.content) <= otlp.MAX_BODY_BYTES
        assert len(points_of(body_json(r))) <= otlp.MAX_POINTS
    assert agent.outbox.depth() == 0


@pytest.mark.parametrize("fmt,compress", [("json", True), ("json", False), ("protobuf", True), ("protobuf", False)])
def test_merging_requests_keeps_every_point_in_each_encoding(fmt, compress):
    parts = [backlog_requests(i, fmt=fmt, compress=compress)[0] for i in range(7)]
    merged = otlp.merge_metrics([(r.headers, r.body, r.count) for r in parts])
    assert merged.count == 7 * 40 and merged.headers["Content-Type"] == parts[0].headers["Content-Type"]
    assert points_of(request_json(merged)) == sorted(p for r in parts for p in points_of(request_json(r)))
    assert merged.headers["Idempotency-Key"] == otlp.merge_metrics(
        [(r.headers, r.body, r.count) for r in parts]).headers["Idempotency-Key"]


def test_joined_requests_are_stable_across_a_failed_send(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    for i in range(50):
        agent.outbox.enqueue(backlog_requests(i), f"e{i}")
    first = FakeObserve(answers=[503])
    with first.client() as client, pytest.raises(agent_mod.DeliveryError):
        agent.flush(client)
    again = FakeObserve()
    with again.client() as client:
        agent.flush(client)
    assert again.posts[0].content == first.posts[0].content
    assert again.posts[0].headers["idempotency-key"] == first.posts[0].headers["idempotency-key"]
    assert first.posts[0].headers["idempotency-key"].startswith(otlp.MERGED_KEY_PREFIX)


def test_a_request_with_no_clear_answer_is_never_joined_into_another(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    for i in range(3):
        agent.outbox.enqueue(backlog_requests(i), f"e{i}")
    head = agent.outbox.peek()
    assert agent.outbox.coalesce_metrics(frozenset({head.seq})) == 1  # e1 and e2 joined, e0 left alone
    assert agent.outbox.depth() == 2
    assert agent.outbox.peek().headers["Idempotency-Key"] == "hw-e0-m0"


def test_requests_of_different_encodings_and_signals_are_not_joined(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    box.enqueue(backlog_requests(0, fmt="json"), "a")
    box.enqueue(backlog_requests(1, fmt="protobuf"), "b")
    box.enqueue(requests_for("c", n_records=2), "c")
    box.enqueue(backlog_requests(2, fmt="protobuf"), "d")
    assert box.coalesce_metrics() == 1
    assert box.depth() == 3


def test_joining_respects_the_point_limit(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    for i in range(3):
        box.enqueue(otlp.build_metrics_requests(f"e{i}", RES, [pt(j) for j in range(3000)]).requests, f"e{i}")
    assert box.coalesce_metrics() == 0  # 3000 + 3000 exceeds 5000, so nothing joins
    assert box.depth() == 3


# -- Windows event log off the main loop -------------------------------------------------------

class GatedRunner:
    """A PowerShell fake that takes as long as the test says: it blocks until released."""

    def __init__(self) -> None:
        self.entered, self.release, self.finished = threading.Event(), threading.Event(), threading.Event()
        self.calls = 0

    def run(self, args, timeout_s):
        self.calls += 1
        self.entered.set()
        assert self.release.wait(30), "the test never released the fake PowerShell"
        self.finished.set()
        return CommandResult(0, "[]")


def test_the_windows_event_cycle_is_not_delayed_by_a_slow_powershell(tmp_path):
    runner = GatedRunner()
    seam = WindowsSeam(events=PowerShellEventLogReader(runner), cim=FakeCimQuery({}),
                       pipe=FakePipeStatusReader({}), runner=FakeCommandRunner())
    cfg = make_cfg(tmp_path, host_name="win-host")
    agent = svc.build_agent(cfg, seam)
    assert event_cycle(agent) is True  # returns while the fake is still inside its spawn
    assert runner.entered.wait(5) and not runner.finished.is_set()
    assert agent.status["winevent"].pending is True
    for _ in range(3):  # later cycles do not wait for it either, and do not start a second spawn
        assert event_cycle(agent) is True
    assert not runner.finished.is_set() and runner.calls == 1
    runner.release.set()
    agent.event_sources["winevent"].__self__._thread.join(5)
    assert event_cycle(agent) is True
    assert agent.status["winevent"].available is True and agent.status["winevent"].pending is False


def test_a_failed_windows_read_is_reported_and_tried_again(tmp_path):
    class Failing:
        def run(self, args, timeout_s):
            return CommandResult(1, "", "access denied")

    seam = WindowsSeam(events=PowerShellEventLogReader(Failing()), cim=FakeCimQuery({}),
                       pipe=FakePipeStatusReader({}), runner=FakeCommandRunner())
    agent = svc.build_agent(make_cfg(tmp_path, host_name="win-host"), seam)
    event_cycle(agent)
    reader = agent.event_sources["winevent"].__self__
    reader._thread.join(5)
    event_cycle(agent)
    assert agent.status["winevent"].available is False and "access denied" in agent.status["winevent"].reason


# -- logging -----------------------------------------------------------------------------------

def test_httpx_does_not_log_each_request_at_info(caplog):
    with caplog.at_level(logging.INFO):
        with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as client:
            client.post("http://observe.test/v1/logs", content=b"x")
    assert [r for r in caplog.records if r.name.startswith(("httpx", "httpcore"))] == []
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
