"""Golden tests for the OTEL mapping. The fixtures under tests/fixtures/otel are shared inputs and
expected outputs for each collector, taken from section 3 of the Observe data API design."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from hostwatch import otel_map as m
from hostwatch.model import Event, Sample, SourceStatus

FIXTURES = Path(__file__).parent / "fixtures" / "otel"
COLLECTORS = sorted(p.stem for p in FIXTURES.glob("*.json") if p.stem != "events")


def _point_dict(p: m.Point) -> dict:
    return {"scope": p.scope, "name": p.name, "unit": p.unit, "kind": p.kind, "monotonic": p.monotonic,
            "value": p.value, "ts": p.ts, "attributes": p.attributes}


@pytest.fixture(autouse=True)
def _fresh_warnings():
    m.reset_unmapped_warnings()


def test_every_collector_has_a_fixture():
    assert {"cpu", "win_cpu", "memory", "win_memory", "hwmon", "rapl", "rpi", "mdraid", "zfs", "truenas",
            "scrutiny", "win_storage", "win_smartctl", "nut", "thermalctl", "win_thermalsuite"} <= set(COLLECTORS)


@pytest.mark.parametrize("name", COLLECTORS)
def test_golden_collector_mapping(name):
    doc = json.loads((FIXTURES / f"{name}.json").read_text())
    points = m.map_samples([Sample(**s) for s in doc["samples"]])
    assert [_point_dict(p) for p in points] == doc["points"]


@pytest.mark.parametrize("name", COLLECTORS)
def test_scope_is_the_collector_source(name):
    doc = json.loads((FIXTURES / f"{name}.json").read_text())
    for raw in doc["samples"]:
        for p in m.map_sample(Sample(**raw)):
            assert p.scope == f"hostwatch.collector.{raw['source']}"


def test_unavailable_value_is_dropped_not_zero():
    assert m.map_samples([Sample(source="cpu", metric="utilization_pct", value=None, unit="%", ts=1.0)]) == []
    assert m.map_samples([Sample(source="memory", metric="mem_available", value=None, unit="B", ts=1.0)]) == []


def test_percent_becomes_ratio():
    p, = m.map_sample(Sample(source="cpu", metric="utilization_pct", value=50.0, unit="%", ts=1.0))
    assert (p.name, p.unit, p.value) == ("system.cpu.utilization", "1", 0.5)


def test_used_memory_needs_the_total():
    pts = m.map_samples([Sample(source="memory", metric="mem_available", value=30.0, unit="B", ts=1.0)])
    assert [(p.name, p.attributes["system.memory.state"]) for p in pts] == [("system.memory.usage", "free")]


def test_unknown_metric_uses_the_fallback_prefix_with_converted_unit():
    pts = m.map_samples([Sample(source="newsrc", metric="fan_load", value=25.0, unit="%", labels={"a": "b"}, ts=1.0),
                         Sample(source="newsrc", metric="clock", value=2.0, unit="MHz", ts=1.0),
                         Sample(source="newsrc", metric="odd", value=3.0, unit="furlong", ts=1.0)])
    assert [(p.name, p.unit, p.value) for p in pts] == [
        ("observe.legacy.newsrc.fan_load", "1", 0.25), ("observe.legacy.newsrc.clock", "Hz", 2e6),
        ("observe.legacy.newsrc.odd", "furlong", 3.0)]
    assert pts[0].attributes == {"a": "b"} and pts[0].scope == "hostwatch.collector.newsrc"


def test_unmapped_pair_is_logged_once(caplog):
    s = Sample(source="newsrc", metric="x", value=1.0, ts=1.0)
    with caplog.at_level(logging.WARNING, logger="hostwatch.otel_map"):
        m.map_samples([s, s])
        m.map_samples([s])
    assert len([r for r in caplog.records if "newsrc/x" in r.getMessage()]) == 1


def test_ups_name_comes_from_the_context():
    s = Sample(source="nut", metric="battery_runtime_s", value=60.0, unit="s", ts=1.0)
    p, = m.map_sample(s, m.MapContext(ups_name="rack"))
    assert p.attributes["hw.id"] == "ups:rack"


def test_source_status_points():
    pts = m.map_source_status([SourceStatus(source="zfs", available=False, reason="x", present=True),
                               SourceStatus(source="mdraid", available=False, present=False)], 5.0)
    got = {(p.name, p.attributes["observe.source"]): p.value for p in pts}
    assert got == {("observe.source.available", "zfs"): 0.0, ("observe.source.present", "zfs"): 1.0,
                   ("observe.source.available", "mdraid"): 0.0, ("observe.source.present", "mdraid"): 0.0}
    assert all(p.scope == "hostwatch.collector." + p.attributes["observe.source"] for p in pts)


def test_heartbeat_point():
    p = m.heartbeat_point(1700000000.0)
    assert (p.name, p.unit, p.kind, p.value) == ("observe.agent.heartbeat", "s", m.GAUGE, 1700000000.0)


def test_resource_attributes():
    full = m.resource_attributes("h1", "x86", "0.1.0", machine_id="abc", arch="amd64", os_description="Debian",
                                 os_version="12", instance_id="i-1")
    assert full == {"host.name": "h1", "os.type": "linux", "service.name": "hostwatch", "service.version": "0.1.0",
                    "observe.platform": "linux", "host.id": "abc", "host.arch": "amd64",
                    "os.description": "Debian", "os.version": "12", "service.instance.id": "i-1"}
    bare = m.resource_attributes("w1", "windows", "0.1.0")
    assert bare["os.type"] == "windows" and bare["observe.platform"] == "windows" and "host.id" not in bare
    assert m.resource_attributes("p", "rpi", "1")["observe.platform"] == "rpi"
    assert m.resource_attributes("t", "truenas", "1")["observe.platform"] == "truenas"
    assert m.resource_attributes("a", "aarch64", "1")["observe.platform"] == "linux"


def test_golden_event_mapping():
    doc = json.loads((FIXTURES / "events.json").read_text())
    assert len(doc["events"]) == len(doc["logs"]) > 0
    for raw, expected in zip(doc["events"], doc["logs"]):
        r = m.map_event(Event(**raw))
        assert {"scope": r.scope, "ts": r.ts, "event_name": r.event_name, "severity_number": r.severity_number,
                "severity_text": r.severity_text, "body": r.body, "attributes": r.attributes} == expected


def test_event_severities():
    def sev(kind, severity, source="journal"):
        return m.map_event(Event(kind=kind, severity=severity, source=source, ts=1.0, title="t", dedup_key="k"))
    assert (sev("a.b", "info").severity_number, sev("a.b", "info").severity_text) == (9, "INFO")
    assert (sev("a.b", "warning").severity_number, sev("a.b", "warning").severity_text) == (13, "WARN")
    assert (sev("a.b", "critical").severity_number, sev("a.b", "critical").severity_text) == (17, "ERROR")
    assert sev("boot.power_loss", "critical", "boot").severity_number == 13
    assert sev("a.b", "critical").attributes["observe.severity"] == "critical"


def test_detail_is_flattened_and_capped():
    detail = {f"k{i:02d}": i for i in range(30)}
    flat = m.flatten_detail(detail)
    assert len(flat) == m.MAX_DETAIL_KEYS
    assert all(k.startswith("observe.detail.") for k in flat)
    assert len(m.flatten_detail({"a": "y" * 2000})["observe.detail.a"]) == m.MAX_DETAIL_VALUE
    assert "observe.detail.bad_key_" in m.flatten_detail({"bad key!": 1})


def test_source_change_log():
    r = m.map_source_change("zfs", False, "permission denied", 9.0)
    assert (r.event_name, r.severity_number, r.body) == ("observe.source.change", 13,
                                                         "zfs unavailable: permission denied")
    assert r.attributes == {"observe.source": "zfs", "observe.source.reason": "permission denied"}
    assert m.map_source_change("zfs", True, "", 9.0).body == "zfs available"


def test_failsafe_reasons_become_logs():
    s = Sample(source="win_thermalsuite", metric="failsafe", value=2.0, unit="count",
               labels={"reasons": "fan:CPU:stalled,control:lost"}, ts=3.0)
    logs = m.failsafe_logs([s])
    assert [(r.event_name, r.severity_number, r.attributes["observe.thermal.reason"]) for r in logs] == [
        ("observe.thermal.failsafe", 13, "fan:CPU:stalled"), ("observe.thermal.failsafe", 13, "control:lost")]
    assert m.failsafe_logs([Sample(source="win_thermalsuite", metric="failsafe", value=0.0, ts=1.0,
                                   labels={"reasons": ""})]) == []
