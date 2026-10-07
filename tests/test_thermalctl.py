"""thermalctl collector: status file decoding, unavailable and absent cases, and the Fans group."""

from __future__ import annotations

from agent_helpers import collect_once
import json
import time

import pytest
from hostwatch.agent import Agent
from hostwatch.config import Config

H = "h1"

from hostwatch.collectors import build_collectors
from hostwatch.collectors.thermalctl import FUTURE_SKEW_S, STALE_AFTER_S, ThermalctlCollector, ThermalctlError

NOW = 1_000_000.0


def doc(ts=NOW, state="active", reasons=(), rpm=1200.0, duty=40.0):
    return {"version": "1", "timestamp": ts, "mode": "enforce", "config_valid": True,
            "zones": {"cpu": {"temperature": 51.5, "load": 22.0},
                      "disk": {"temperature": None, "load": None}},
            "headers": {"fan1": {"state": state, "mapped": True, "duty": duty, "rpm": rpm,
                                 "reasons": list(reasons), "notes": [], "zones": ["cpu"]}}}


def write(tmp_path, document):
    f = tmp_path / "run" / "thermalctl" / "status.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(document if isinstance(document, str) else json.dumps(document))
    return f


def make(f, now=NOW):
    return ThermalctlCollector(f.parent, f.parent, str(f), clock=lambda: now)


def by_metric(samples):
    out = {}
    for s in samples:
        out.setdefault(s.metric, []).append(s)
    return out


def test_normal_status_emits_zones_and_headers(tmp_path):
    c = make(write(tmp_path, doc()))
    assert c.detect()[0] is True
    m = by_metric(c.collect())
    temps = {s.labels["zone"]: s.value for s in m["zone_temp"]}
    assert temps == {"cpu": 51.5, "disk": None}
    assert {s.labels["zone"]: s.value for s in m["zone_load"]}["cpu"] == 22.0
    fan, duty = m["fan"][0], m["fan_duty"][0]
    assert (fan.value, fan.unit) == (1200.0, "RPM") and (duty.value, duty.unit) == (40.0, "%")
    assert fan.labels == {"chip": "thermalctl", "sensor": "fan1", "state": "active",
                          "mode": "enforce", "reasons": ""}


def test_failsafe_reasons_become_labels(tmp_path):
    c = make(write(tmp_path, doc(state="failsafe", reasons=("sensor_missing", "stall"), rpm=None)))
    fan = by_metric(c.collect())["fan"][0]
    assert fan.value is None and fan.labels["state"] == "failsafe"
    assert fan.labels["reasons"] == "sensor_missing,stall"


def test_missing_file_in_readable_directory_is_absent(tmp_path):
    f = write(tmp_path, doc())
    f.unlink()
    c = make(f)
    assert c.detect()[0] is False and c.is_absent() is True


def test_missing_directory_in_readable_parent_is_absent(tmp_path):
    c = make(tmp_path / "run" / "thermalctl" / "status.json")
    (tmp_path / "run").mkdir()
    assert c.is_absent() is True


def test_unreadable_parent_is_not_absent(tmp_path):
    c = make(tmp_path / "nothing" / "deeper" / "status.json")
    assert c.is_absent() is False


@pytest.mark.parametrize("text", ["{not json", "[1, 2]", json.dumps({"zones": {}})])
def test_malformed_is_unavailable_not_absent(tmp_path, text):
    c = make(write(tmp_path, text))
    ok, reason = c.detect()
    assert ok is False and reason and c.is_absent() is False
    with pytest.raises(ThermalctlError):
        c.collect()


def test_stale_timestamp_is_unavailable(tmp_path):
    f = write(tmp_path, doc(ts=NOW - STALE_AFTER_S - 5))
    ok, reason = make(f).detect()
    assert ok is False and "stale" in reason
    assert make(f, now=NOW - STALE_AFTER_S - 5 + 10).detect()[0] is True


def test_thermalctl_is_registered_with_configured_path(tmp_path):
    cfg = Config( data_dir=tmp_path, thermalctl_status=str(tmp_path / "s.json"))
    found = [c for c in build_collectors(cfg) if c.id == "thermalctl"]
    assert len(found) == 1 and str(found[0].path) == str(tmp_path / "s.json")


def run(tmp_path, document):
    f = write(tmp_path, document)
    data = tmp_path / "data"
    data.mkdir()
    agent = Agent(Config(procfs=tmp_path / "proc", sysfs=tmp_path / "sys", data_dir=data,
                         host_name=H, journal=tmp_path / "j", journal_volatile=tmp_path / "jv",
                         pstore=tmp_path / "p", scrutiny_url="", thermalctl_status=str(f)))
    return collect_once(agent)


def thermal(cycle, metric):
    return [x for x in cycle.samples if x.source == "thermalctl" and x.metric == metric]


def test_headers_are_reported_as_fans_with_their_failsafe_reasons(tmp_path):
    cycle = run(tmp_path, doc(ts=time.time(), state="failsafe", reasons=("stall",)))
    [fan] = thermal(cycle, "fan")
    assert fan.value == 1200.0 and fan.labels.get("state") == "failsafe" and "stall" in fan.labels.get("reasons", "")


def test_normal_header_has_no_failsafe_reason(tmp_path):
    cycle = run(tmp_path, doc(ts=time.time()))
    [fan] = thermal(cycle, "fan")
    assert fan.labels.get("state") == "active" and not fan.labels.get("reasons")


def test_host_without_controller_reports_present_false(tmp_path):
    (tmp_path / "sys").mkdir()
    (tmp_path / "proc").mkdir()
    data = tmp_path / "data"
    data.mkdir()
    agent = Agent(Config(procfs=tmp_path / "proc", sysfs=tmp_path / "sys", data_dir=data,
                         host_name=H, journal=tmp_path / "j", journal_volatile=tmp_path / "jv",
                         pstore=tmp_path / "p", scrutiny_url="",
                         thermalctl_status=str(tmp_path / "run" / "thermalctl" / "status.json")))
    (tmp_path / "run").mkdir()
    st = {x.source: x for x in collect_once(agent).sources}["thermalctl"]
    assert st.available is False and st.present is False


def test_future_timestamp_beyond_skew_is_stale_with_a_reason(tmp_path):
    f = write(tmp_path, doc(ts=NOW + FUTURE_SKEW_S + 30))
    ok, reason = make(f).detect()
    assert ok is False and "stale" in reason and "future" in reason
    assert make(write(tmp_path, doc(ts=NOW + FUTURE_SKEW_S - 1))).detect()[0] is True


def test_source_that_goes_stale_after_detect_is_unavailable_with_a_reason(tmp_path):
    f = write(tmp_path, doc())
    now = [NOW]
    c = ThermalctlCollector(f.parent, f.parent, str(f), clock=lambda: now[0])
    assert c.detect()[0] is True
    now[0] = NOW + STALE_AFTER_S + 10
    with pytest.raises(ThermalctlError, match="stale"):
        c.collect()


def test_agent_marks_a_collector_that_went_stale_unavailable_with_its_reason(tmp_path):
    f = write(tmp_path, doc(ts=time.time()))
    (tmp_path / "sys").mkdir()
    (tmp_path / "proc").mkdir()
    data = tmp_path / "data"
    data.mkdir()
    agent = Agent(Config(procfs=tmp_path / "proc", sysfs=tmp_path / "sys", data_dir=data,
                         host_name=H, journal=tmp_path / "j", journal_volatile=tmp_path / "jv",
                         pstore=tmp_path / "p", scrutiny_url="", thermalctl_status=str(f)))
    agent.detect()
    f.write_text(json.dumps(doc(ts=time.time() - STALE_AFTER_S - 30)))
    st = {x.source: x for x in collect_once(agent).sources}["thermalctl"]
    assert st.available is False and "stale" in st.reason and st.present is True


# -- failsafe state reaches Observe like the Windows controller's -------------------------------

def test_a_failsafe_header_produces_the_failsafe_gauge_and_one_log_per_reason(tmp_path):
    from agent_helpers import drain_logs
    from hostwatch import otel_map, tiers
    f = write(tmp_path, doc(ts=time.time(), state="failsafe", reasons=("sensor_lost", "rpm_zero"), rpm=0.0))
    (tmp_path / "sys").mkdir()
    (tmp_path / "proc").mkdir()
    data = tmp_path / "data"
    data.mkdir()
    agent = Agent(Config(procfs=tmp_path / "proc", sysfs=tmp_path / "sys", data_dir=data,
                         host_name=H, journal=tmp_path / "j", journal_volatile=tmp_path / "jv",
                         pstore=tmp_path / "p", scrutiny_url="", thermalctl_status=str(f)))
    agent.collectors = [c for c in agent.collectors if c.id == "thermalctl"]
    agent.event_sources = {}
    agent.detect()
    [fs] = thermal(collect_once(agent), "failsafe")
    assert fs.value == 2.0 and fs.labels["reasons"] == "fan1:sensor_lost,fan1:rpm_zero"
    [gauge] = [p for p in otel_map.map_samples([fs], agent.map_context) if p.name == "observe.thermal.failsafe"]
    assert gauge.value == 2.0 and gauge.unit == "{reason}"
    agent.run_tier(tiers.DEVICE_METRICS)
    failsafe = [r for r in drain_logs(agent) if r["event"] == "observe.thermal.failsafe"]
    assert sorted(r["attrs"]["observe.thermal.reason"] for r in failsafe) == [
        "fan1:rpm_zero", "fan1:sensor_lost"]
    agent.run_tier(tiers.DEVICE_METRICS)  # a steady failsafe is logged once, not on every poll
    assert [r for r in drain_logs(agent) if r["event"] == "observe.thermal.failsafe"] == []


def test_a_healthy_controller_reports_a_zero_failsafe_gauge_and_no_log(tmp_path):
    cycle = run(tmp_path, doc(ts=time.time()))
    [fs] = thermal(cycle, "failsafe")
    assert fs.value == 0.0 and fs.labels["reasons"] == ""
    from hostwatch import otel_map
    assert otel_map.failsafe_logs([fs]) == []


def test_a_failsafe_header_that_names_no_reason_still_counts(tmp_path):
    c = make(write(tmp_path, doc(state="failsafe", reasons=())))
    [fs] = by_metric(c.collect())["failsafe"]
    assert fs.value == 1.0 and fs.labels["reasons"] == "fan1:failsafe"
