"""thermalctl collector: status file decoding, unavailable and absent cases, and the Fans group."""

from __future__ import annotations

import json
import time

import pytest
from test_zfs import H, Agent, Config, Store, build_host_summary

from hostwatch.collectors import build_collectors
from hostwatch.collectors.thermalctl import STALE_AFTER_S, ThermalctlCollector
from hostwatch.integrations.summary import group_documents

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
    assert c.collect() == []


def test_stale_timestamp_is_unavailable(tmp_path):
    f = write(tmp_path, doc(ts=NOW - STALE_AFTER_S - 5))
    ok, reason = make(f).detect()
    assert ok is False and "stale" in reason
    assert make(f, now=NOW - STALE_AFTER_S - 5 + 10).detect()[0] is True


def test_thermalctl_is_registered_with_configured_path(tmp_path):
    cfg = Config(ingest_token="x" * 32, data_dir=tmp_path, thermalctl_status=str(tmp_path / "s.json"))
    found = [c for c in build_collectors(cfg) if c.id == "thermalctl"]
    assert len(found) == 1 and str(found[0].path) == str(tmp_path / "s.json")


def run(tmp_path, document):
    f = write(tmp_path, document)
    data = tmp_path / "data"
    data.mkdir()
    agent = Agent(Config(procfs=tmp_path / "proc", sysfs=tmp_path / "sys", data_dir=data, ingest_token="x" * 32,
                         host_name=H, journal=tmp_path / "j", journal_volatile=tmp_path / "jv",
                         pstore=tmp_path / "p", scrutiny_url="", thermalctl_status=str(f)))
    batch = agent.collect_once()
    store = Store(tmp_path / "db.sqlite")
    store.ingest_batch(batch.model_copy(update={"host": H, "sent_at": time.time()}))
    return batch, build_host_summary(store, H, time.time())


def test_headers_appear_under_fans(tmp_path):
    _, s = run(tmp_path, doc(ts=time.time(), state="failsafe", reasons=("stall",)))
    fan = next(c for c in s.fans if c.labels.get("chip") == "thermalctl")
    assert fan.value == 1200.0 and fan.state == "warning" and "stall" in fan.reason
    fans = next(g for g in group_documents(s) if g["id"] == "fans")
    assert fans["status"] == "warning" and any("thermalctl" in m["name"] for m in fans["members"])


def test_normal_header_is_ok_in_fans(tmp_path):
    _, s = run(tmp_path, doc(ts=time.time()))
    fan = next(c for c in s.fans if c.labels.get("chip") == "thermalctl")
    assert fan.state == "ok"


def test_host_without_controller_reports_present_false(tmp_path):
    (tmp_path / "sys").mkdir()
    (tmp_path / "proc").mkdir()
    data = tmp_path / "data"
    data.mkdir()
    agent = Agent(Config(procfs=tmp_path / "proc", sysfs=tmp_path / "sys", data_dir=data, ingest_token="x" * 32,
                         host_name=H, journal=tmp_path / "j", journal_volatile=tmp_path / "jv",
                         pstore=tmp_path / "p", scrutiny_url="",
                         thermalctl_status=str(tmp_path / "run" / "thermalctl" / "status.json")))
    (tmp_path / "run").mkdir()
    st = {x.source: x for x in agent.collect_once().sources}["thermalctl"]
    assert st.available is False and st.present is False
