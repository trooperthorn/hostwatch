"""The TrueNAS collector against fixtures that follow the shapes in docs/hosts/truenas-svr.md."""

from __future__ import annotations

import copy
import dataclasses

import pytest

from hostwatch.agent import Agent
from hostwatch.collectors.truenas import TruenasCollector, TruenasError, alert_severity
from hostwatch.config import Config
from hostwatch.truenas.client import Result, convert_dates

SDM_SERIAL = "PNY253825091701039CA"


def leaf(disk, name, **stats):
    base = {"read_errors": 0, "write_errors": 0, "checksum_errors": 0, "self_healed": 0}
    return {"name": name, "type": "DISK", "status": "ONLINE", "path": f"/dev/{disk}1", "device": f"{disk}1",
            "disk": disk, "stats": {**base, **stats}, "children": []}


def apps_pool():
    """The Apps pool as measured: a mirror whose member sdm has one corrected checksum error."""
    return {"id": 1, "name": "Apps", "status": "ONLINE", "healthy": True, "warning": True,
            "status_code": "FAILING_DEV", "status_detail": "resilvered",
            "scan": {"function": "RESILVER", "state": "FINISHED", "errors": 0,
                     "start_time": {"$date": 1_790_000_000_000}, "end_time": {"$date": 1_790_000_100_000}},
            "topology": {"data": [{"name": "mirror-0", "type": "MIRROR", "status": "ONLINE", "children": [
                leaf("sdl", "aaaa-sdl"),
                leaf("sdm", "5e882717-6a5c-41d5-a8df-6d9a72e4af51", checksum_errors=1, self_healed=4096)]}],
                "log": [], "cache": [], "spare": [], "special": [], "dedup": []}}


def vault_pool():
    return {"id": 2, "name": "Vault", "status": "ONLINE", "healthy": True, "warning": False,
            "status_code": "OK", "scan": {"function": "SCRUB", "state": "FINISHED", "errors": 0},
            "topology": {"data": [{"name": "mirror-0", "type": "MIRROR", "status": "ONLINE", "children": [
                leaf("sda", "v1"), leaf("sdb", "v2")]}]}}


DISKS = [{"name": "sdl", "serial": "PNY253825091701039CB", "model": "PNY CS900 1TB SSD", "pool": "Apps"},
         {"name": "sdm", "serial": SDM_SERIAL, "model": "PNY CS900 1TB SSD", "pool": "Apps"},
         {"name": "sda", "serial": "WD-A", "model": "WDC WD181KFGX", "pool": "Vault"},
         {"name": "sdb", "serial": "WD-B", "model": "WDC WD181KFGX", "pool": "Vault"},
         {"name": "nvme0n1", "serial": "NV1", "model": "NVMe", "pool": None}]
TEMPS = {"sdl": 30.0, "sdm": 37.0, "sda": 41.0, "sdb": 42.0, "nvme0n1": 34.85}
APPS_ALERT = {"id": 7, "uuid": "u-apps-1", "source": "VolumeStatus", "klass": "VolumeStatus",
              "args": {"volume": "Apps"}, "node": "Controller A", "key": "{}",
              "datetime": {"$date": 1_790_000_000_000}, "last_occurrence": {"$date": 1_790_000_050_000},
              "dismissed": True, "level": "CRITICAL",
              "formatted": "Pool Apps state is ONLINE: one device has errors.", "one_shot": False}


class FakeClient:
    def __init__(self, **answers):
        self.answers = {"pool.query": [apps_pool(), vault_pool()], "disk.query": DISKS,
                        "disk.temperatures": TEMPS, "alert.list": [APPS_ALERT], **answers}
        self.closed = False

    async def call(self, method, params=None):
        value = self.answers[method]
        if isinstance(value, Result):
            return value
        return Result(True, convert_dates(copy.deepcopy(value)))

    async def close(self):
        self.closed = True


def collector(tmp_path, **answers):
    return TruenasCollector(tmp_path / "sys", tmp_path / "proc", FakeClient(**answers))


def health(samples, pool):
    return next(s for s in samples if s.metric == "pool_health" and s.labels["pool"] == pool)


def test_corrected_checksum_error_is_a_warning_naming_the_disk_and_serial(tmp_path):
    samples = collector(tmp_path).collect()
    apps = health(samples, "Apps")
    assert apps.value == 1.0
    assert "sdm" in apps.labels["reason"] and SDM_SERIAL in apps.labels["reason"]
    assert health(samples, "Vault").value == 0.0
    healthy = {s.labels["pool"]: s.value for s in samples if s.metric == "pool_healthy"}
    warning = {s.labels["pool"]: s.value for s in samples if s.metric == "pool_warning"}
    assert healthy["Apps"] == 1.0 and warning["Apps"] == 1.0
    assert apps.labels["status_code"] == "FAILING_DEV" and apps.labels["scan_state"] == "FINISHED"


def test_device_samples_carry_pool_vdev_disk_and_serial_labels(tmp_path):
    samples = collector(tmp_path).collect()
    cksum = [s for s in samples if s.metric == "vdev_checksum_errors" and s.labels["pool"] == "Apps"]
    by_disk = {s.labels["disk"]: s for s in cksum}
    assert by_disk["sdm"].value == 1.0 and by_disk["sdm"].labels["serial"] == SDM_SERIAL
    assert by_disk["sdm"].labels["vdev"] == "5e882717-6a5c-41d5-a8df-6d9a72e4af51"
    assert by_disk["sdm"].labels["group"] == "mirror-0"
    assert by_disk["sdl"].value == 0.0
    healed = next(s for s in samples if s.metric == "vdev_self_healed_bytes" and s.labels["disk"] == "sdm")
    assert healed.value == 4096.0
    assert not any(s.labels.get("vdev") == "mirror-0" for s in samples if s.metric.startswith("vdev_"))


def test_clean_pool_is_ok(tmp_path):
    c = collector(tmp_path, **{"pool.query": [vault_pool()]})
    assert health(c.collect(), "Vault").value == 0.0


def test_degraded_pool_is_critical(tmp_path):
    pool = vault_pool()
    pool["status"], pool["healthy"] = "DEGRADED", False
    pool["topology"]["data"][0]["status"] = "DEGRADED"
    pool["topology"]["data"][0]["children"][1]["status"] = "FAULTED"
    h = health(collector(tmp_path, **{"pool.query": [pool]}).collect(), "Vault")
    assert h.value == 2.0 and "DEGRADED" in h.labels["reason"] and "sdb" in h.labels["reason"]


@pytest.mark.parametrize("key", ["read_errors", "write_errors", "checksum_errors"])
def test_any_nonzero_device_count_is_at_least_a_warning(tmp_path, key):
    pool = vault_pool()
    pool["topology"]["data"][0]["children"][0]["stats"][key] = 3
    h = health(collector(tmp_path, **{"pool.query": [pool]}).collect(), "Vault")
    assert h.value == 1.0 and "sda" in h.labels["reason"]


def test_missing_stats_stay_unavailable_not_zero(tmp_path):
    pool = vault_pool()
    del pool["topology"]["data"][0]["children"][0]["stats"]
    samples = collector(tmp_path, **{"pool.query": [pool]}).collect()
    sda = [s for s in samples if s.metric.startswith("vdev_") and s.labels["disk"] == "sda"]
    assert sda and all(s.value is None for s in sda)
    assert health(samples, "Vault").value == 0.0


def test_scan_errors_are_reported_and_warn(tmp_path):
    pool = vault_pool()
    pool["scan"]["errors"] = 2
    samples = collector(tmp_path, **{"pool.query": [pool]}).collect()
    assert next(s for s in samples if s.metric == "pool_scan_errors").value == 2.0
    assert health(samples, "Vault").value == 1.0


def test_temperatures_map_to_disks(tmp_path):
    samples = collector(tmp_path).collect()
    temps = {s.labels["disk"]: s for s in samples if s.metric == "disk_temp_c"}
    assert temps["sdm"].value == 37.0 and temps["sdm"].labels["serial"] == SDM_SERIAL
    assert temps["sdm"].labels["pool"] == "Apps" and temps["sdm"].unit == "C"
    assert temps["nvme0n1"].value == 34.85


def test_known_disk_without_a_temperature_is_unavailable_not_zero(tmp_path):
    temps = {k: v for k, v in TEMPS.items() if k != "sda"}
    samples = collector(tmp_path, **{"disk.temperatures": temps}).collect()
    assert next(s for s in samples if s.metric == "disk_temp_c" and s.labels["disk"] == "sda").value is None


def test_dismissed_critical_alert_is_one_event_with_critical_severity(tmp_path):
    c = collector(tmp_path)
    c.collect()
    status, events = c.read_events()
    assert status.available
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "truenas.alert" and ev.severity == "critical" and ev.source == "truenas"
    assert ev.detail["dismissed"] is True and ev.detail["uuid"] == "u-apps-1"
    assert ev.ts == 1_790_000_050.0
    assert ev.dedup_key == "truenas.alert:u-apps-1:1790000050000"


def test_alert_levels_map_to_severity():
    levels = ("INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY", "odd")
    assert [alert_severity(x) for x in levels] == \
        ["info", "info", "warning", "critical", "critical", "critical", "critical", "warning"]


def test_new_last_occurrence_of_the_same_alert_is_a_new_key(tmp_path):
    c = collector(tmp_path)
    c.collect()
    first = c.read_events()[1][0].dedup_key
    c.client.answers["alert.list"] = [dict(APPS_ALERT, last_occurrence={"$date": 1_790_000_099_000})]
    c.collect()
    assert c.read_events()[1][0].dedup_key != first


def agent_with(tmp_path, client):
    cfg = dataclasses.replace(Config(), data_dir=tmp_path / "data", sysfs=tmp_path / "sys",
                              procfs=tmp_path / "proc", host_name="nas", hub_url="http://127.0.0.1:1",
                              journal=tmp_path / "nojournal", pstore=tmp_path / "nopstore",
                              rasdaemon_db=tmp_path / "nodb", truenas_url="")
    (tmp_path / "data").mkdir(exist_ok=True)
    agent = Agent(cfg)
    found = next(c for c in agent.collectors if c.id == "truenas")
    found.client = client
    if client is not None:
        agent.event_sources["truenas_alerts"] = found.read_events
    return agent


def test_alert_is_recorded_once_and_not_repeated_next_cycle(tmp_path):
    agent = agent_with(tmp_path, FakeClient())
    first = [e for e in agent.collect_once().events if e.kind == "truenas.alert"]
    second = [e for e in agent.collect_once().events if e.kind == "truenas.alert"]
    assert len(first) == 1 and second == []
    assert agent.status["truenas"].available and agent.status["truenas_alerts"].available


def test_api_failure_is_unavailable_with_a_reason(tmp_path):
    bad = Result(False, reason="connection failed: OSError")
    agent = agent_with(tmp_path, FakeClient(**{"pool.query": bad}))
    batch = agent.collect_once()
    status = next(s for s in batch.sources if s.source == "truenas")
    assert not status.available and "pool.query failed" in status.reason and status.present
    assert not [s for s in batch.samples if s.source == "truenas"]
    assert not next(s for s in batch.sources if s.source == "truenas_alerts").available


def test_failure_of_a_later_call_makes_the_whole_source_unavailable(tmp_path):
    c = collector(tmp_path, **{"disk.temperatures": Result(False, reason="timed out")})
    with pytest.raises(TruenasError, match="disk.temperatures failed: timed out"):
        c.collect()
    status, events = c.read_events()
    assert not status.available and events == []


def test_unconfigured_truenas_is_not_present(tmp_path):
    agent = agent_with(tmp_path, None)
    assert "truenas_alerts" not in agent.event_sources
    agent.detect()
    assert agent.status["truenas"].present is False
    assert "HOSTWATCH_TRUENAS_URL" in agent.status["truenas"].reason


def test_configured_but_unreachable_is_present_and_unavailable(tmp_path):
    c = collector(tmp_path, **{"pool.query": Result(False, reason="timed out")})
    ok, reason = c.detect()
    assert not ok and "timed out" in reason and c.is_absent() is False
    c.close()
    assert c.client.closed


def test_summary_shows_the_corrected_error_pool_as_a_warning_naming_the_disk(tmp_path):
    import time

    from hostwatch.integrations.summary import build_host_summary
    from hostwatch.schema import Batch, SourceStatus
    from hostwatch.store import Store

    samples = collector(tmp_path).collect()
    store = Store(tmp_path / "db.sqlite")
    store.ingest_batch(Batch(agent_version="t", host="nas", platform="x86", sent_at=time.time(),
                             sources=[SourceStatus(source="truenas", available=True)], samples=samples))
    summary = build_host_summary(store, "nas", time.time())
    pools = {c.labels["pool"]: c for c in summary.pools}
    assert pools["Apps"].state == "warning" and pools["Apps"].status == 1
    assert SDM_SERIAL in pools["Apps"].reason and "sdm" in pools["Apps"].reason
    assert pools["Vault"].state == "ok"
    assert summary.status == 1
