"""Home Assistant MQTT discovery and state publishing, against a fake in-memory broker."""

from __future__ import annotations

import json
import time

import pytest

from hostwatch.config import Config
from hostwatch.integrations.homeassistant import HomeAssistantPublisher, build_entities
from hostwatch.integrations.mqtt_client import MqttClient
from hostwatch.integrations.summary import build_host_summary
from hostwatch.schema import Batch, Sample, SourceStatus
from hostwatch.store import Store

H = "Media-SVR"
ALL = ["cpu", "memory", "rapl", "hwmon", "mdraid", "scrutiny"]
NODE = "hostwatch_media_svr"
CPU_CONFIG = f"homeassistant/sensor/{NODE}/cpu_utilization/config"


class FakeBroker:
    """Keeps retained messages like a broker does, and records every publish in order."""

    def __init__(self):
        self.retained: dict[str, str] = {}
        self.log: list[tuple[str, str, int, bool]] = []
        self.transports: list[FakeTransport] = []

    def restart(self, keep_retained: bool = False):
        """Broker restart: every client drops, retained messages are lost unless persisted."""
        if not keep_retained:
            self.retained.clear()
        for t in self.transports:
            t.handler()

    def birth(self, payload="online"):
        for t in self.transports:
            t.message_handler("homeassistant/status", payload)


class FakeTransport:
    def __init__(self, broker: FakeBroker):
        self.broker = broker
        broker.transports.append(self)
        self.handler = lambda: None
        self.message_handler = lambda topic, payload: None
        self.subscribed = []
        self.will = None
        self.configured = None

    def set_disconnect_handler(self, handler):
        self.handler = handler

    def set_message_handler(self, handler):
        self.message_handler = handler

    def configure(self, **kw):
        self.configured = kw

    def set_will(self, topic, payload, qos, retain):
        self.will = (topic, payload, qos, retain)

    def connect(self, host, port, keepalive):
        pass

    def subscribe(self, topic, qos):
        self.subscribed.append(topic)

    def publish(self, topic, payload, qos, retain):
        self.broker.log.append((topic, payload, qos, retain))
        if retain:
            self.broker.retained[topic] = payload

    def disconnect(self):
        pass


def make_config(tmp_path):
    return Config(data_dir=tmp_path, mqtt_host="broker.test", argon2_time_cost=1, argon2_memory_kib=8,
                  argon2_parallelism=1)


def make_publisher(cfg, store, broker):
    client = MqttClient(cfg, FakeTransport(broker), clock=lambda: 0.0)
    return HomeAssistantPublisher(cfg, client, store), client


def sample(source, metric, value, **labels):
    return Sample(source=source, metric=metric, value=value, labels=labels, ts=time.time())


def seed(store, unavailable=()):
    samples = [
        sample("cpu", "utilization_pct", 12.5),
        sample("memory", "mem_total", 8000.0), sample("memory", "mem_available", 6000.0),
        sample("rapl", "watts", 20.0, zone="r0", domain="package-0"),
        sample("hwmon", "temp", 45.0, chip="k10temp", sensor="Tctl"),
        sample("mdraid", "degraded", 0, array="md0"),
        sample("mdraid", "sync_action", 1, array="md0", action="idle"),
        sample("scrutiny", "device_status", 0, wwn="w1", device="sda", model="m"),
        sample("scrutiny", "temp", 35.0, wwn="w1", device="sda", model="m"),
    ]
    samples = [s for s in samples if s.source not in unavailable]
    sources = [SourceStatus(source=n, available=n not in unavailable,
                            reason="gone" if n in unavailable else "") for n in ALL]
    store.ingest_batch(Batch(agent_version="t", host=H, platform="x86", sent_at=time.time(),
                             sources=sources, samples=samples))


@pytest.fixture
def env(tmp_path):
    cfg = make_config(tmp_path)
    store = Store(tmp_path / "db.sqlite")
    seed(store)
    broker = FakeBroker()
    pub, client = make_publisher(cfg, store, broker)
    return cfg, store, broker, pub, client


def test_disabled_without_host(tmp_path):
    cfg = Config(data_dir=tmp_path)
    broker = FakeBroker()
    pub, client = make_publisher(cfg, Store(tmp_path / "db.sqlite"), broker)
    assert pub.tick() is False
    assert broker.log == []


def test_discovery_payload_snapshot(env):
    _, _, broker, pub, _ = env
    assert pub.tick() is True
    cpu = json.loads(broker.retained[CPU_CONFIG])
    assert cpu == {
        "name": "CPU utilization",
        "unique_id": f"{NODE}_cpu_utilization",
        "state_topic": "hostwatch/media_svr/cpu_utilization/state",
        "availability": [{"topic": "hostwatch/availability"},
                         {"topic": "hostwatch/media_svr/cpu_utilization/availability"}],
        "availability_mode": "all",
        "payload_available": "online",
        "payload_not_available": "offline",
        "has_entity_name": True,
        "device": {"identifiers": [NODE], "name": H, "manufacturer": "hostwatch", "model": "Host monitor"},
        "origin": {"name": "hostwatch"},
        "unit_of_measurement": "%",
        "state_class": "measurement",
    }
    power = json.loads(broker.retained[f"homeassistant/sensor/{NODE}/package_power/config"])
    assert (power["device_class"], power["unit_of_measurement"], power["state_class"]) == ("power", "W", "measurement")
    temp = json.loads(broker.retained[f"homeassistant/sensor/{NODE}/temp_k10temp_tctl/config"])
    assert (temp["device_class"], temp["unit_of_measurement"]) == ("temperature", "°C")
    problem = json.loads(broker.retained[f"homeassistant/binary_sensor/{NODE}/problem_md_degraded/config"])
    assert problem["device_class"] == "problem"
    assert (problem["payload_on"], problem["payload_off"]) == ("ON", "OFF")
    src = json.loads(broker.retained[f"homeassistant/binary_sensor/{NODE}/source_cpu_up/config"])
    assert src["device_class"] == "connectivity"
    assert src["availability"] == [{"topic": "hostwatch/availability"}]


def test_one_device_with_unique_ids_and_all_expected_entities(env):
    _, _, broker, pub, _ = env
    pub.tick()
    configs = {t: json.loads(p) for t, p in broker.retained.items() if t.startswith("homeassistant/")}
    ids = [c["unique_id"] for c in configs.values()]
    assert len(ids) == len(set(ids))
    assert {tuple(c["device"]["identifiers"]) for c in configs.values()} == {(NODE,)}
    for key in ("cpu_utilization", "memory_used", "package_power", "md_md0", "disk_w1", "disk_temp_w1",
                "temp_k10temp_tctl"):
        assert f"homeassistant/sensor/{NODE}/{key}/config" in configs
    for key in ("problem_md_degraded", "problem_disk_failing", "problem_source_unavailable",
                "problem_temperature_high", "problem_memory_low", "source_scrutiny_up"):
        assert f"homeassistant/binary_sensor/{NODE}/{key}/config" in configs


def test_discovery_and_state_are_retained_and_values_published(env):
    _, _, broker, pub, _ = env
    pub.tick()
    assert broker.log and all(retain for _, _, _, retain in broker.log)
    assert broker.retained["hostwatch/media_svr/cpu_utilization/state"] == "12.5"
    assert broker.retained["hostwatch/media_svr/memory_used/state"] == "25"
    assert broker.retained["hostwatch/media_svr/cpu_utilization/availability"] == "online"
    assert broker.retained["hostwatch/media_svr/problem_md_degraded/state"] == "OFF"
    assert broker.retained["hostwatch/availability"] == "online"


def test_client_subscribes_to_birth_topic_and_sets_will(env):
    _, _, _, pub, client = env
    pub.tick()
    t = client.transport
    assert t.subscribed == ["homeassistant/status"]
    assert t.will == ("hostwatch/availability", "offline", 1, True)


def test_unavailable_source_publishes_unavailable_never_zero(tmp_path):
    cfg = make_config(tmp_path)
    store = Store(tmp_path / "db.sqlite")
    seed(store, unavailable=("rapl", "mdraid"))
    broker = FakeBroker()
    pub, _ = make_publisher(cfg, store, broker)
    pub.tick()
    assert broker.retained["hostwatch/media_svr/package_power/availability"] == "offline"
    assert "hostwatch/media_svr/package_power/state" not in broker.retained
    assert "hostwatch/media_svr/md_md0/availability" not in broker.retained  # never seen, so no entity
    # The raw problem flag for an unknown input is unavailable, not OFF.
    assert broker.retained["hostwatch/media_svr/problem_md_degraded/availability"] == "offline"
    assert "hostwatch/media_svr/problem_md_degraded/state" not in broker.retained
    # A source that is down is a real answer: its connectivity sensor reads OFF and stays available.
    assert broker.retained["hostwatch/media_svr/source_rapl_up/state"] == "OFF"
    assert broker.retained["hostwatch/media_svr/problem_source_unavailable/state"] == "ON"
    zeros = [(t, p) for t, p, _, _ in broker.log if t.endswith("/state") and p in ("0", "0.0")
             and ("package_power" in t or "cpu_utilization" in t)]
    assert zeros == []


def test_state_going_unavailable_flips_entity_availability(env):
    cfg, store, broker, pub, _ = env
    pub.tick()
    assert broker.retained["hostwatch/media_svr/package_power/availability"] == "online"
    seed(store, unavailable=("rapl",))
    pub.tick()
    assert broker.retained["hostwatch/media_svr/package_power/availability"] == "offline"


def test_unchanged_discovery_is_not_republished_on_each_tick(env):
    _, _, broker, pub, _ = env
    pub.tick()
    count = sum(1 for t, *_ in broker.log if t == CPU_CONFIG)
    pub.tick()
    assert sum(1 for t, *_ in broker.log if t == CPU_CONFIG) == count == 1


def test_rediscovery_after_broker_restart(env):
    _, _, broker, pub, client = env
    pub.tick()
    first_epoch = client.epoch
    broker.restart()  # retained messages are gone and the connection dropped
    assert CPU_CONFIG not in broker.retained
    pub.tick()
    assert client.epoch == first_epoch + 1
    assert CPU_CONFIG in broker.retained
    assert broker.retained["hostwatch/availability"] == "online"
    assert broker.retained["hostwatch/media_svr/cpu_utilization/state"] == "12.5"


def test_rediscovery_on_home_assistant_birth_message(env):
    _, _, broker, pub, _ = env
    pub.tick()
    broker.retained.clear()
    broker.birth("offline")
    pub.tick()
    assert CPU_CONFIG not in broker.retained  # an offline message is not a birth
    broker.birth("online")
    pub.tick()
    assert CPU_CONFIG in broker.retained


def test_rediscovery_after_hub_restart_on_same_database(tmp_path):
    cfg = make_config(tmp_path)
    db = tmp_path / "db.sqlite"
    store = Store(db)
    seed(store)
    broker = FakeBroker()
    pub, client = make_publisher(cfg, store, broker)
    pub.tick()
    client.close()
    assert broker.retained["hostwatch/availability"] == "offline"
    before = dict(broker.retained)
    broker.retained.clear()
    # A new process: new store handle on the same file, new client, new publisher.
    pub2, _ = make_publisher(cfg, Store(db), FakeBroker.__new__(FakeBroker))  \
        if False else make_publisher(cfg, Store(db), broker)
    pub2.tick()
    for topic, payload in before.items():
        if topic.startswith("homeassistant/"):
            assert broker.retained[topic] == payload
    assert broker.retained["hostwatch/availability"] == "online"


def test_failed_publish_forces_full_republish_next_tick(env):
    _, _, broker, pub, client = env
    pub.tick()
    broker.retained.clear()
    real = client.transport.publish
    calls = {"n": 0}

    def flaky(topic, payload, qos, retain):
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("broken pipe")
        real(topic, payload, qos, retain)

    client.transport.publish = flaky
    pub._published.clear()
    assert pub.tick() is False
    client.transport.publish = real
    assert pub.tick() is True
    assert CPU_CONFIG in broker.retained


def test_unknown_host_summary_has_no_numeric_states(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    summary = build_host_summary(store, "ghost", time.time())
    states = {e.key: e.state for e in build_entities(summary)}
    assert states["cpu_utilization"] is None
    assert states["problem_md_degraded"] is None


def test_entity_that_disappears_is_marked_unavailable(env):
    _, store, broker, pub, _ = env
    pub.tick()
    assert broker.retained["hostwatch/media_svr/md_md0/availability"] == "online"
    real = build_entities

    import hostwatch.integrations.homeassistant as ha
    ha.build_entities = lambda summary: [e for e in real(summary) if e.key != "md_md0"]
    try:
        pub.tick()
    finally:
        ha.build_entities = real
    assert broker.retained["hostwatch/media_svr/md_md0/availability"] == "offline"


def test_retired_entity_gets_empty_retained_config_after_restart(tmp_path):
    cfg = make_config(tmp_path)
    db = tmp_path / "db.sqlite"
    store = Store(db)
    seed(store)
    broker = FakeBroker()
    pub, _ = make_publisher(cfg, store, broker)
    pub.tick()
    md_config = f"homeassistant/sensor/{NODE}/md_md0/config"
    assert broker.retained[md_config] != ""
    # A new process in which the array is no longer built.
    import hostwatch.integrations.homeassistant as ha
    real = ha.build_entities
    ha.build_entities = lambda summary: [e for e in real(summary) if e.key != "md_md0"]
    try:
        pub2, _ = make_publisher(cfg, Store(db), broker)
        pub2.tick()
    finally:
        ha.build_entities = real
    assert broker.retained[md_config] == ""
    assert broker.retained["hostwatch/media_svr/md_md0/availability"] == "offline"
    assert CPU_CONFIG in broker.retained and broker.retained[CPU_CONFIG] != ""


def test_colliding_host_slugs_get_distinct_identifiers_and_warning(tmp_path, caplog):
    cfg = make_config(tmp_path)
    store = Store(tmp_path / "db.sqlite")
    broker = FakeBroker()
    client = MqttClient(cfg, FakeTransport(broker), clock=lambda: 0.0)
    pub = HomeAssistantPublisher(cfg, client, store, hosts=lambda: ["Media-SVR", "media_svr"])
    with caplog.at_level("WARNING"):
        assert pub.tick() is True
    configs = {t: json.loads(p) for t, p in broker.retained.items()
               if t.startswith("homeassistant/") and t.endswith("cpu_utilization/config")}
    assert len(configs) == 2
    idents = {c["device"]["identifiers"][0] for c in configs.values()}
    uids = {c["unique_id"] for c in configs.values()}
    states = {c["state_topic"] for c in configs.values()}
    assert len(idents) == len(uids) == len(states) == 2
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("Media-SVR" in m and "media_svr" in m for m in warnings)
    pub.tick()
    assert len([r for r in caplog.records if "same Home Assistant identifier" in r.getMessage()]) == 1


def _hosted_publisher(cfg, store, broker, hosts):
    client = MqttClient(cfg, FakeTransport(broker), clock=lambda: 0.0)
    return HomeAssistantPublisher(cfg, client, store, hosts=lambda: list(hosts))


def test_collision_appearing_later_retires_the_old_unsuffixed_device(tmp_path):
    cfg = make_config(tmp_path)
    store = Store(tmp_path / "db.sqlite")
    broker = FakeBroker()
    hosts = ["Media-SVR"]
    pub = _hosted_publisher(cfg, store, broker, hosts)
    pub.tick()
    old = "homeassistant/sensor/hostwatch_media_svr/cpu_utilization/config"
    assert broker.retained[old] != ""
    hosts.append("media_svr")
    pub.tick()
    assert broker.retained[old] == ""
    assert broker.retained["hostwatch/media_svr/cpu_utilization/availability"] == "offline"
    # The retirement is persisted, so a restart does not retire it a second time or lose track.
    pub2 = _hosted_publisher(cfg, Store(tmp_path / "db.sqlite"), broker, hosts)
    assert "hostwatch_media_svr" not in pub2._known


def test_host_that_disappears_has_its_entities_retired(tmp_path):
    cfg = make_config(tmp_path)
    store = Store(tmp_path / "db.sqlite")
    broker = FakeBroker()
    hosts = ["alpha", "beta"]
    pub = _hosted_publisher(cfg, store, broker, hosts)
    pub.tick()
    topic = "homeassistant/sensor/hostwatch_beta/cpu_utilization/config"
    assert broker.retained[topic] != ""
    hosts.remove("beta")
    pub2 = _hosted_publisher(cfg, Store(tmp_path / "db.sqlite"), broker, hosts)
    pub2.tick()
    assert broker.retained[topic] == ""
    assert broker.retained["hostwatch/beta/cpu_utilization/availability"] == "offline"
    assert broker.retained["homeassistant/sensor/hostwatch_alpha/cpu_utilization/config"] != ""
