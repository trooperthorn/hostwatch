"""Polling tiers: rates from Observe are applied and floored, defaults hold when Observe cannot be
reached, every tier runs at its own rate, and an event does not wait for a slow tier."""

from __future__ import annotations

import httpx
import pytest
from agent_helpers import FakeObserve, event, log_records, request_json

from hostwatch import tiers
from hostwatch.agent import WATCH_S, Agent
from hostwatch.collectors.base import Collector
from hostwatch.config import Config
from hostwatch.model import Sample, SourceStatus


def make_agent(tmp_path, clock, **over) -> Agent:
    for d in ("proc", "sys", "data"):
        (tmp_path / d).mkdir(exist_ok=True)
    cfg = Config(procfs=tmp_path / "proc", sysfs=tmp_path / "sys", data_dir=tmp_path / "data",
                 host_name="h1", observe_url="http://observe.test", ingest_key="k" * 24,
                 pstore=tmp_path / "none", journal=tmp_path / "none", rasdaemon_db=tmp_path / "none.db", **over)
    agent = Agent(cfg, clock=clock)
    agent.event_sources = {}
    return agent


class Clock:
    def __init__(self, start=100_000.0):
        self.t = start

    def __call__(self):
        return self.t


class Counting(Collector):
    """A collector that counts how often it was read and returns one reading."""

    def __init__(self, cid, tier, watch=False, value=1.0, source=None):
        super().__init__()
        self.id = cid
        self.tier = tier
        self.event_watch = watch
        self.value = value
        self.source = source or cid
        self.calls = 0

    def detect(self):
        return True, ""

    def collect(self):
        self.calls += 1
        return [Sample(source=self.source, metric="array_state", value=self.value, ts=1.0,
                       labels={"array": "md0", "state": "clean"})]


# -- parsing and flooring ----------------------------------------------------------------------

@pytest.mark.parametrize("tier,asked,expected", [
    ("availability", 1, 5.0), ("availability", 15, 15.0), ("availability", 10**9, 3600.0),
    ("device_metrics", 0, 10.0), ("device_metrics", -5, 10.0), ("device_metrics", 120.5, 120.5),
    ("storage_health", 59, 60.0), ("storage_health", 900, 900.0), ("storage_health", 10**9, 86400.0),
    ("smart", 299, 300.0), ("inventory", 1, 600.0),
])
def test_a_rate_is_clamped_to_the_limits_observe_enforces(tier, asked, expected):
    assert tiers.clamp_rate(tier, asked) == expected


@pytest.mark.parametrize("bad", [True, False, None, "30", "fast", float("nan"), float("inf"), [], {}])
def test_an_unusable_rate_is_not_a_rate(bad):
    assert tiers.clamp_rate("availability", bad) is None


def test_the_limits_are_the_ones_observe_defines():
    assert {t: v[0] for t, v in tiers.LIMITS.items()} == {
        "availability": 30.0, "device_metrics": 60.0, "storage_health": 900.0, "smart": 3600.0,
        "inventory": 3600.0}
    assert {t: v[1] for t, v in tiers.LIMITS.items()} == {
        "availability": 5.0, "device_metrics": 10.0, "storage_health": 60.0, "smart": 300.0,
        "inventory": 600.0}


@pytest.mark.parametrize("body", [None, [], "x", 5, {}, {"intervals": []}, {"intervals": "x"}, {"host": "h"}])
def test_an_answer_without_intervals_is_refused(body):
    assert tiers.parse_agent_config(body) is None


def test_parse_keeps_good_tiers_and_drops_bad_and_unknown_ones():
    got = tiers.parse_agent_config({"host": "h1", "intervals": {
        "availability": 2, "device_metrics": "soon", "storage_health": 1800, "smart": None,
        "mystery": 5, "inventory": True}})
    assert got == {"availability": 5.0, "storage_health": 1800.0}


# -- applying rates ----------------------------------------------------------------------------

def test_rates_from_observe_are_applied_and_floored(tmp_path):
    agent = make_agent(tmp_path, Clock())
    assert agent.schedule.rates() == tiers.DEFAULTS
    observe = FakeObserve(config={"host": "h1", "intervals": {
        "availability": 1, "device_metrics": 45, "storage_health": 7200, "smart": 10, "inventory": 99999}})
    with observe.client() as client:
        assert agent.fetch_config(client) is True
    assert agent.schedule.rates() == {"availability": 5.0, "device_metrics": 45.0, "storage_health": 7200.0,
                                      "smart": 300.0, "inventory": 86400.0}
    [call] = observe.calls
    assert call.url.path == "/internal/v1/agent-config" and call.headers["authorization"] == "Bearer " + "k" * 24


def test_a_tier_missing_from_the_answer_keeps_its_current_rate(tmp_path):
    agent = make_agent(tmp_path, Clock())
    with FakeObserve(config={"intervals": {"availability": 20, "smart": 600}}).client() as client:
        agent.fetch_config(client)
    with FakeObserve(config={"intervals": {"availability": 40}}).client() as client:
        agent.fetch_config(client)
    assert agent.schedule.rates()["availability"] == 40.0 and agent.schedule.rates()["smart"] == 600.0


@pytest.mark.parametrize("config", [
    httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), 500, 503, 404, 401, 403,
    ["not", "an", "object"], {"intervals": "x"},
], ids=lambda c: type(c).__name__ + str(c)[:12])
def test_observe_unreachable_or_refusing_leaves_the_defaults_in_force(tmp_path, config):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    with FakeObserve(config=config).client() as client:
        assert agent.fetch_config(client) is False
    assert agent.schedule.rates() == tiers.DEFAULTS
    assert agent._config_next == clock.t + tiers.CONFIG_RETRY_S  # asked again soon, not in a tight loop


def test_an_undecodable_answer_leaves_the_defaults_in_force(tmp_path):
    agent = make_agent(tmp_path, Clock())
    broken = FakeObserve()
    broken.handler = lambda request: httpx.Response(200, content=b"<html>not json</html>")
    with httpx.Client(transport=httpx.MockTransport(broken.handler)) as client:
        assert agent.fetch_config(client) is False
    assert agent.schedule.rates() == tiers.DEFAULTS


def test_an_outage_keeps_the_last_good_rates_and_recovery_applies_new_ones(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    with FakeObserve(config={"intervals": {"availability": 10}}).client() as client:
        agent.fetch_config(client)
    with FakeObserve(config=httpx.ConnectError("down")).client() as client:
        agent.fetch_config(client)
    assert agent.schedule.rates()["availability"] == 10.0
    with FakeObserve(config={"intervals": {"availability": 20}}).client() as client:
        agent.fetch_config(client)
    assert agent.schedule.rates()["availability"] == 20.0


def test_rates_are_refreshed_periodically_without_a_restart(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    agent.collectors = []
    observe = FakeObserve(config={"intervals": {"availability": 30}})
    with observe.client() as client:
        agent.tick(client)
        fetches = [c for c in observe.calls if c.url.path.endswith("agent-config")]
        assert len(fetches) == 1
        clock.t += tiers.CONFIG_REFRESH_S - 1
        agent.tick(client)
        assert len([c for c in observe.calls if c.url.path.endswith("agent-config")]) == 1
        observe.config = {"intervals": {"availability": 5}}
        clock.t += 1
        agent.tick(client)
        assert len([c for c in observe.calls if c.url.path.endswith("agent-config")]) == 2
    assert agent.schedule.rates()["availability"] == 5.0


def test_a_lowered_rate_applies_at_once_instead_of_after_the_old_wait(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    agent.collectors = []
    storage = Counting("md", tiers.STORAGE_HEALTH)
    agent.collectors = [storage]
    observe = FakeObserve(config={"intervals": {"storage_health": 3600}})
    with observe.client() as client:
        agent.tick(client)
        assert storage.calls >= 1
        observe.config = {"intervals": {"storage_health": 60}}
        clock.t += tiers.CONFIG_REFRESH_S
        before = storage.calls
        agent.tick(client)  # the new rate arrives and the tier is due within one new interval
        clock.t += 61
        agent.tick(client)
    assert storage.calls > before


# -- each tier at its own rate -----------------------------------------------------------------

def test_every_tier_runs_at_its_own_rate(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    by_tier = {t: Counting(f"c_{t}", t) for t in (tiers.DEVICE_METRICS, tiers.STORAGE_HEALTH, tiers.SMART)}
    agent.collectors = list(by_tier.values())
    observe = FakeObserve()
    start = clock.t
    with observe.client() as client:
        while clock.t <= start + 3600:
            agent.tick(client)
            clock.t += 5
    assert by_tier[tiers.DEVICE_METRICS].calls == 61
    assert by_tier[tiers.STORAGE_HEALTH].calls == 5
    assert by_tier[tiers.SMART].calls == 2
    metrics = [r for r in observe.posts if r.url.path == "/v1/metrics"]
    heartbeats = [r for r in metrics if b"observe.agent.heartbeat" in _inflate(r)]
    assert len(heartbeats) == 121  # the availability tier, every 30 seconds


def _inflate(request):
    import gzip
    return gzip.decompress(request.content) if request.headers.get("content-encoding") == "gzip" else request.content


def test_availability_carries_the_heartbeat_the_source_status_and_the_rates_in_force(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    agent.collectors = []
    observe = FakeObserve(config={"intervals": {"availability": 20, "storage_health": 1200}})
    with observe.client() as client:
        agent.tick(client)
    names = {}
    for req in observe.posts:
        if req.url.path != "/v1/metrics":
            continue
        for rm in request_json_of(req)["resourceMetrics"]:
            for sm in rm["scopeMetrics"]:
                for m in sm["metrics"]:
                    for dp in (m.get("gauge") or m["sum"])["dataPoints"]:
                        attrs = {a["key"]: list(a["value"].values())[0] for a in dp.get("attributes", [])}
                        names.setdefault(m["name"], []).append((attrs, dp["asDouble"]))
    assert "observe.agent.heartbeat" in names and "observe.source.available" in names
    rates = {a["observe.tier"]: v for a, v in names["observe.agent.poll.interval"]}
    assert rates["availability"] == 20.0 and rates["storage_health"] == 1200.0


def request_json_of(req):
    from agent_helpers import body_json
    return body_json(req)


# -- events do not wait for a slow tier --------------------------------------------------------

def logs_with(observe, key):
    out = []
    for req in observe.posts:
        if req.url.path == "/v1/logs":
            out += [r for r in log_records(request_json_of(req)) if r["dedup_key"] == key]
    return out


def test_an_event_is_sent_within_seconds_while_the_storage_tier_is_slow(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    storage = Counting("md", tiers.STORAGE_HEALTH)
    agent.collectors = [storage]
    emitted: list = []
    agent.event_sources = {"journal": lambda: (SourceStatus(source="journal", available=True), list(emitted))}
    observe = FakeObserve(config={"intervals": {"storage_health": 3600}})
    start = clock.t
    appeared = None
    with observe.client() as client:
        while clock.t <= start + 600:
            if appeared is None and clock.t >= start + 101:
                emitted.append(event(kind="md.degraded", key="journal:disk-failure", ts=clock.t))
                appeared = clock.t
            agent.tick(client)
            if appeared is not None and logs_with(observe, "journal:disk-failure"):
                break
            clock.t += 1
    assert appeared is not None and logs_with(observe, "journal:disk-failure")
    assert clock.t - appeared <= tiers.EVENT_POLL_S  # within one event poll
    assert storage.calls <= 1 + int((clock.t - start) // WATCH_S) + 1  # watched reads only, no tier run
    storage_tier_runs = [r for r in observe.posts if r.url.path == "/v1/metrics"
                         and b"md0" in _inflate(r)]
    assert len(storage_tier_runs) == 1  # the tier itself ran once, at the start


def test_a_watched_source_raises_its_threshold_event_without_waiting_for_the_tier(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    degraded = Counting("mdraid", tiers.STORAGE_HEALTH, watch=True, value=0.0)
    degraded.metric = "degraded"

    def collect():
        degraded.calls += 1
        return [Sample(source="mdraid", metric="degraded", value=degraded.value, ts=1.0, labels={"array": "md0"})]

    degraded.collect = collect
    agent.collectors = [degraded]
    observe = FakeObserve(config={"intervals": {"storage_health": 3600}})
    start = clock.t
    flipped = None
    with observe.client() as client:
        while clock.t <= start + 300:
            if flipped is None and clock.t >= start + 120:
                degraded.value = 1.0
                flipped = clock.t
            agent.tick(client)
            names = [r["event"] for req in observe.posts if req.url.path == "/v1/logs"
                     for r in log_records(request_json_of(req))]
            if "hostwatch.md.degraded" in names:
                break
            clock.t += 1
    assert "hostwatch.md.degraded" in names
    assert clock.t - flipped <= WATCH_S + tiers.EVENT_POLL_S


def test_events_are_read_every_poll_even_when_every_tier_is_slow(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    agent.collectors = []
    reads = []
    agent.event_sources = {"journal": lambda: (reads.append(clock.t) or SourceStatus(source="journal", available=True), [])}
    with FakeObserve(config={"intervals": {t: 86400 for t in tiers.TIERS}}).client() as client:
        start = clock.t
        while clock.t < start + 60:
            agent.tick(client)
            clock.t += 1
    gaps = [b - a for a, b in zip(reads, reads[1:])]
    assert reads and max(gaps) <= tiers.EVENT_POLL_S


def test_the_loop_never_sleeps_longer_than_an_event_poll(tmp_path):
    clock = Clock()
    agent = make_agent(tmp_path, clock)
    agent.collectors = []
    with FakeObserve(config={"intervals": {t: 86400 for t in tiers.TIERS}}).client() as client:
        agent.tick(client)
    assert 0.1 <= agent.sleep_s() <= tiers.EVENT_POLL_S


def test_the_schedule_reschedules_from_the_due_time_so_a_slow_run_does_not_stretch_the_cadence():
    s = tiers.TierSchedule()
    assert set(s.due(0.0)) == set(tiers.TIERS)
    s.done("availability", 1.5)
    assert s.tiers["availability"].next_due == 30.0
    s.done("availability", 100.0)  # the agent fell far behind: schedule from now, do not burst
    assert s.tiers["availability"].next_due == 130.0
