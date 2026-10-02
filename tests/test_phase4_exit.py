"""Phase 4 exit criteria, asserted together with a fake in-memory broker and the hub over HTTP.

1. The Home Assistant device and its entities appear on the broker.
2. A forced warning drives the Orion status to 1 and the Home Assistant problem sensor on.
3. Both survive a hub restart (new store, app and MQTT client on the same database) and a broker
   restart, with and without retained messages.

Nothing here touches a network: the broker is a fake transport and the hub runs under TestClient.
"""

from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.integrations.homeassistant import HomeAssistantPublisher
from hostwatch.integrations.mqtt_client import MqttClient
from hostwatch.schema import Batch, Sample, SourceStatus
from hostwatch.store import Store

H = "Media-SVR"
NODE = "hostwatch_media_svr"
SOURCES = ["cpu", "memory", "rapl", "hwmon", "mdraid", "scrutiny"]
SUMMARY = f"/api/v1/orion/hosts/{H}/summary"
TEMP_PROBLEM = "hostwatch/media_svr/problem_temperature_high/state"


class FakeBroker:
    def __init__(self):
        self.retained: dict[str, str] = {}
        self.transports: list[FakeTransport] = []

    def restart(self, keep_retained: bool):
        if not keep_retained:
            self.retained.clear()
        for t in self.transports:
            t.handler()


class FakeTransport:
    def __init__(self, broker: FakeBroker):
        self.broker = broker
        broker.transports.append(self)
        self.handler = lambda: None

    def set_disconnect_handler(self, handler):
        self.handler = handler

    def set_message_handler(self, handler):
        pass

    def configure(self, **kw):
        pass

    def set_will(self, topic, payload, qos, retain):
        pass

    def connect(self, host, port, keepalive):
        pass

    def subscribe(self, topic, qos):
        pass

    def publish(self, topic, payload, qos, retain):
        if retain:
            self.broker.retained[topic] = payload

    def disconnect(self):
        pass


def config(tmp_path):
    return Config(ingest_token="t" * 64, data_dir=tmp_path, mqtt_host="broker.test", argon2_time_cost=1,
                  argon2_memory_kib=8, argon2_parallelism=1)


def sample(source, metric, value, **labels):
    return Sample(source=source, metric=metric, value=value, labels=labels, ts=time.time())


def seed(store, temp):
    samples = [
        sample("cpu", "utilization_pct", 12.5),
        sample("memory", "mem_total", 8000.0), sample("memory", "mem_available", 6000.0),
        sample("rapl", "watts", 20.0, zone="r0", domain="package-0"),
        sample("hwmon", "temp", temp, chip="k10temp", sensor="Tctl"),
        sample("mdraid", "degraded", 0, array="md0"),
        sample("mdraid", "sync_action", 1, array="md0", action="idle"),
        sample("scrutiny", "device_status", 0, wwn="w1", device="sda", model="m"),
        sample("scrutiny", "temp", 35.0, wwn="w1", device="sda", model="m"),
    ]
    store.ingest_batch(Batch(agent_version="t", host=H, platform="x86", sent_at=time.time(),
                             sources=[SourceStatus(source=n, available=True) for n in SOURCES],
                             samples=samples))


class Hub:
    """One hub process: its own store connection, HTTP app and MQTT client on a shared database."""

    def __init__(self, tmp_path, broker, key=None):
        self.cfg = config(tmp_path)
        self.store = Store(tmp_path / "db.sqlite")
        self.http = TestClient(create_app(self.cfg, self.store))
        self.key = key or "Bearer " + auth.generate_api_key(self.store, "read:metrics", "test")[0]
        client = MqttClient(self.cfg, FakeTransport(broker), clock=lambda: 0.0)
        self.publisher = HomeAssistantPublisher(self.cfg, client, self.store)

    def orion(self) -> dict:
        r = self.http.get(SUMMARY, headers={"Authorization": self.key})
        assert r.status_code == 200
        return r.json()


def entity_configs(broker):
    return {t: json.loads(p) for t, p in broker.retained.items() if t.startswith("homeassistant/")}


def assert_device_and_entities(broker):
    configs = entity_configs(broker)
    assert {tuple(c["device"]["identifiers"]) for c in configs.values()} == {(NODE,)}
    assert {c["device"]["name"] for c in configs.values()} == {H}
    for key in ("cpu_utilization", "memory_used", "package_power", "temp_k10temp_tctl"):
        assert f"homeassistant/sensor/{NODE}/{key}/config" in configs
    assert f"homeassistant/binary_sensor/{NODE}/problem_temperature_high/config" in configs
    assert broker.retained["hostwatch/availability"] == "online"
    assert broker.retained["hostwatch/media_svr/cpu_utilization/state"] == "12.5"


def test_device_and_entities_appear(tmp_path):
    broker = FakeBroker()
    hub = Hub(tmp_path, broker)
    seed(hub.store, temp=45.0)
    assert hub.publisher.tick() is True
    assert_device_and_entities(broker)
    assert broker.retained[TEMP_PROBLEM] == "OFF"


def test_forced_warning_drives_orion_status_and_ha_problem(tmp_path):
    broker = FakeBroker()
    hub = Hub(tmp_path, broker)
    seed(hub.store, temp=45.0)
    hub.publisher.tick()
    assert hub.orion()["overall_status"] == 0
    seed(hub.store, temp=85.0)
    assert hub.orion()["overall_status"] == 1
    assert hub.orion()["temp_k10temp_tctl_status"] == 1
    hub.publisher.tick()
    assert broker.retained[TEMP_PROBLEM] == "ON"


def test_both_survive_hub_restart_and_broker_restart(tmp_path):
    broker = FakeBroker()
    first = Hub(tmp_path, broker)
    seed(first.store, temp=85.0)
    first.publisher.tick()
    key = first.key
    before = first.orion()
    first.publisher.close()

    # Hub restart: a fresh store, app and MQTT client on the same database; the old key still works.
    second = Hub(tmp_path, broker, key=key)
    after = second.orion()
    for d in (before, after):
        d.pop("last_seen")
    assert after == before and after["overall_status"] == 1
    assert second.publisher.tick() is True
    assert_device_and_entities(broker)
    assert broker.retained[TEMP_PROBLEM] == "ON"

    # Broker restart that loses retained messages: the next tick restores everything.
    broker.restart(keep_retained=False)
    assert entity_configs(broker) == {}
    assert second.publisher.tick() is True
    assert_device_and_entities(broker)
    assert broker.retained[TEMP_PROBLEM] == "ON"

    # Broker restart that keeps retained messages: nothing is lost and the warning is still reported.
    broker.restart(keep_retained=True)
    assert second.publisher.tick() is True
    assert_device_and_entities(broker)
    assert second.orion()["overall_status"] == 1
