"""Threshold rules and their wiring into the agent batch."""

from __future__ import annotations

from hostwatch.agent import Agent
from hostwatch.config import Config
from hostwatch.events.thresholds import ThresholdEngine
from hostwatch.schema import Event, Sample, SourceStatus


def md(metric, value, **labels):
    return Sample(source="mdraid", metric=metric, value=value, labels={"array": "md0", **labels}, ts=1.0)


def kinds(events):
    return [e.kind for e in events]


def test_degraded_transition_raises_then_clears():
    eng = ThresholdEngine()
    assert eng.evaluate([md("degraded", 0)], [], now=1) == []
    assert kinds(eng.evaluate([md("degraded", 1)], [], now=2)) == ["md.degraded"]
    assert kinds(eng.evaluate([md("degraded", 0)], [], now=3)) == ["md.degraded_cleared"]


def test_steady_state_gives_no_repeats():
    eng = ThresholdEngine()
    assert kinds(eng.evaluate([md("degraded", 1)], [], now=1)) == ["md.degraded"]
    for t in (2, 3, 4):
        assert eng.evaluate([md("degraded", 1)], [], now=t) == []
    eng2 = ThresholdEngine()
    for t in (1, 2):
        assert eng2.evaluate([md("degraded", 0), md("sync_action", 1, action="idle")], [], now=t) == []


def test_none_value_never_triggers_or_recovers():
    eng = ThresholdEngine()
    assert eng.evaluate([md("degraded", None)], [], now=1) == []
    eng.evaluate([md("degraded", 1)], [], now=2)
    assert eng.evaluate([md("degraded", None)], [], now=3) == []
    assert eng.evaluate([md("degraded", 1)], [], now=4) == []
    assert kinds(eng.evaluate([md("degraded", 0)], [], now=5)) == ["md.degraded_cleared"]


def test_source_flip_gives_unavailable_then_available_event():
    eng = ThresholdEngine()
    up, down = SourceStatus(source="mdraid", available=True), SourceStatus(source="mdraid", available=False, reason="gone")
    assert eng.evaluate([], [down], now=1) == []  # never seen up
    assert eng.evaluate([], [up], now=2) == []
    ev = eng.evaluate([], [down], now=3)
    assert kinds(ev) == ["source.unavailable"] and ev[0].detail["reason"] == "gone"
    assert eng.evaluate([], [down], now=4) == []
    assert kinds(eng.evaluate([], [up], now=5)) == ["source.available"]


def test_sync_change_and_scrutiny_growth():
    eng = ThresholdEngine()
    eng.evaluate([md("sync_action", 1, action="idle")], [], now=1)
    assert kinds(eng.evaluate([md("sync_action", 1, action="resync")], [], now=2)) == ["md.sync_changed"]
    sc = lambda v: Sample(source="scrutiny", metric="device_status", value=v, labels={"wwn": "w1"}, ts=1.0)
    assert eng.evaluate([sc(0)], [], now=3) == []
    assert kinds(eng.evaluate([sc(1)], [], now=4)) == ["scrutiny.status_raised"]
    assert eng.evaluate([sc(1)], [], now=5) == []
    assert kinds(eng.evaluate([sc(0)], [], now=6)) == ["scrutiny.status_cleared"]


def test_seed_from_store_prevents_repeat_on_restart():
    first = ThresholdEngine()
    ev = first.evaluate([md("degraded", 1)], [], now=10)
    stored = [{**e.model_dump(), "id": 1} for e in ev]
    second = ThresholdEngine()
    second.seed(stored)
    assert second.evaluate([md("degraded", 1)], [], now=20) == []
    assert kinds(second.evaluate([md("degraded", 0)], [], now=30)) == ["md.degraded_cleared"]


def test_agent_batch_includes_events_from_event_source_and_thresholds(tmp_path):
    sysfs, procfs, data = tmp_path / "sys", tmp_path / "proc", tmp_path / "data"
    (sysfs / "block/md0/md").mkdir(parents=True)
    procfs.mkdir()
    data.mkdir()
    (sysfs / "block/md0/md/degraded").write_text("1\n")
    cfg = Config(sysfs=sysfs, procfs=procfs, data_dir=data, ingest_token="x" * 32, host_name="h",
                 pstore=tmp_path / "none", journal=tmp_path / "none", rasdaemon_db=tmp_path / "none.db")
    agent = Agent(cfg)
    fake = Event(kind="fake.thing", severity="info", source="fake", ts=1.0, title="t", dedup_key="fake:1")
    agent.event_sources = {"fake": lambda: (SourceStatus(source="fake", available=True), [fake])}
    agent.detect()
    batch = agent.collect_once()
    got = kinds(batch.events)
    assert "fake.thing" in got and "md.degraded" in got
    assert any(s.source == "fake" and s.available for s in batch.sources)
    assert "fake.thing" not in kinds(agent.collect_once().events)  # not resent
