"""Raspberry Pi throttling collector: decoding, unavailable reasons, absence and the summary."""

from __future__ import annotations

import sys
import time

import pytest
from test_zfs import H, Agent, Config, Store, build_host_summary

from hostwatch.collectors.rpi import RpiCollector


def pi_tree(tmp_path, throttled=None, model="Raspberry Pi 5 Model B Rev 1.0\x00", temp="52300"):
    sysfs, procfs = tmp_path / "sys", tmp_path / "proc"
    (procfs / "device-tree").mkdir(parents=True)
    (sysfs / "class").mkdir(parents=True)
    if model is not None:
        (procfs / "device-tree" / "model").write_text(model)
    if throttled is not None:
        f = sysfs / "devices" / "platform" / "soc" / "soc_firmware" / "get_throttled"
        f.parent.mkdir(parents=True)
        f.write_text(throttled + "\n")
    if temp is not None:
        z = sysfs / "class" / "thermal" / "thermal_zone0"
        z.mkdir(parents=True)
        (z / "type").write_text("cpu-thermal\n")
        (z / "temp").write_text(temp + "\n")
    return sysfs, procfs, sysfs / "devices" / "platform" / "soc" / "soc_firmware" / "get_throttled"


def collector(tmp_path, **kw):
    sysfs, procfs, f = pi_tree(tmp_path, **kw)
    return RpiCollector(sysfs, procfs, str(f))


def flags(c):
    return {s.labels["flag"]: s.value for s in c.collect() if s.metric == "throttle_flag"}


def test_clean_pi_has_no_flags_and_a_temperature(tmp_path):
    c = collector(tmp_path, throttled="0x0")
    assert c.detect()[0] is True
    assert set(flags(c).values()) == {0}
    assert {s.metric: s.value for s in c.collect()}["soc_temp"] == 52.3


def test_0x50005_sets_current_and_occurred_bits(tmp_path):
    f = flags(collector(tmp_path, throttled="0x50005"))
    assert {k for k, v in f.items() if v} == {"under_voltage_now", "throttled_now",
                                              "under_voltage_occurred", "throttled_occurred"}


def test_0x50000_sets_only_occurred_bits(tmp_path):
    f = flags(collector(tmp_path, throttled="0x50000"))
    assert {k for k, v in f.items() if v} == {"under_voltage_occurred", "throttled_occurred"}


def test_pi_without_file_is_unavailable_with_reason(tmp_path):
    c = collector(tmp_path, throttled=None)
    ok, reason = c.detect()
    assert ok is False and "vcgencmd" in reason
    assert c.is_absent() is False
    assert all(s.value is None for s in c.collect() if s.metric == "throttle_flag")


def test_garbage_bitmask_is_unavailable(tmp_path):
    ok, reason = collector(tmp_path, throttled="banana").detect()
    assert ok is False and "not a number" in reason


def test_non_pi_is_not_present(tmp_path):
    c = collector(tmp_path, throttled=None, model="Some Other Board")
    assert c.detect()[0] is False and c.is_absent() is True
    sysfs, procfs, _ = pi_tree(tmp_path / "x", throttled=None, model=None)
    assert RpiCollector(sysfs, procfs).is_absent() is True


def test_missing_trees_are_not_absent(tmp_path):
    assert RpiCollector(tmp_path / "nosys", tmp_path / "noproc").is_absent() is False


def run(tmp_path, throttled):
    sysfs, procfs, f = pi_tree(tmp_path, throttled=throttled)
    data = tmp_path / "data"
    data.mkdir()
    agent = Agent(Config(procfs=procfs, sysfs=sysfs, data_dir=data, ingest_token="x" * 32, host_name=H,
                         journal=tmp_path / "j", journal_volatile=tmp_path / "jv", pstore=tmp_path / "p",
                         scrutiny_url="", rpi_throttled_path=str(f)))
    batch = agent.collect_once()
    store = Store(tmp_path / "db.sqlite")
    store.ingest_batch(batch.model_copy(update={"host": H, "sent_at": time.time()}))
    return batch, build_host_summary(store, H, time.time())


@pytest.mark.parametrize("raw,state,status", [("0x0", "ok", 0), ("0x50000", "warning", 1),
                                              ("0x4", "warning", 1), ("0x50005", "critical", 2)])
def test_summary_statuses(tmp_path, raw, state, status):
    _, s = run(tmp_path, raw)
    assert s.pi.state == state and s.pi.status == status
    assert "pi" not in s.not_present and "pi" not in s.unmeasured
    assert any(t.name == "temp.soc" and t.value == 52.3 for t in s.temperatures)


def test_summary_pi_missing_file_is_unmeasured(tmp_path):
    _, s = run(tmp_path, None)
    assert s.pi.status is None and "pi" in s.unmeasured


def test_non_pi_host_reports_present_false(tmp_path):
    sysfs, procfs = tmp_path / "sys", tmp_path / "proc"
    sysfs.mkdir()
    procfs.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    agent = Agent(Config(procfs=procfs, sysfs=sysfs, data_dir=data, ingest_token="x" * 32, host_name=H,
                         journal=tmp_path / "j", journal_volatile=tmp_path / "jv", pstore=tmp_path / "p",
                         scrutiny_url=""))
    st = {x.source: x for x in agent.collect_once().sources}["rpi"]
    assert st.available is False and st.present is False


@pytest.mark.skipif(sys.platform == "win32", reason="the default firmware path contains a colon")
def test_default_path_is_the_firmware_attribute(tmp_path):
    sysfs, procfs, _ = pi_tree(tmp_path, throttled=None)
    f = sysfs / "devices" / "platform" / "soc" / "soc:firmware" / "get_throttled"
    f.parent.mkdir(parents=True)
    f.write_text("0x50000\n")
    assert RpiCollector(sysfs, procfs).detect()[0] is True


def test_unreadable_model_with_throttled_file_is_present(tmp_path):
    sysfs, procfs, f = pi_tree(tmp_path, throttled="0x50000", model=None)
    (procfs / "device-tree" / "model").mkdir()
    c2 = RpiCollector(sysfs, procfs, str(f))
    assert c2.is_absent() is False
    assert c2.detect()[0] is True
    c3 = RpiCollector(sysfs, procfs, str(tmp_path / "missing"))
    assert c3.is_absent() is False
    ok, reason = c3.detect()
    assert ok is False and "vcgencmd" in reason


def test_readable_non_pi_model_is_absent_even_with_throttled_file(tmp_path):
    c = collector(tmp_path, throttled="0x0", model="Some Other Board")
    assert c.is_absent() is True


@pytest.mark.skipif(sys.platform == "win32", reason="the default firmware path contains a colon")
def test_default_path_is_read_from_a_fake_tree_without_a_model(tmp_path):
    sysfs, procfs, _ = pi_tree(tmp_path, throttled=None, model=None)
    f = sysfs / "devices" / "platform" / "soc" / "soc:firmware" / "get_throttled"
    f.parent.mkdir(parents=True)
    f.write_text("0x50005\n")
    c = RpiCollector(sysfs, procfs)
    assert c.is_absent() is False
    assert c.detect()[0] is True
    assert flags(c)["under_voltage_now"] == 1
