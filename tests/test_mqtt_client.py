"""MQTT settings and the reconnecting client wrapper, with an in-memory fake transport."""

from __future__ import annotations

import logging
import os

import pytest

from hostwatch.config import Config
from hostwatch.integrations.mqtt_client import MqttClient, PahoTransport, backoff_delay

SECRET = "s3cret-broker-pw"


class FakeTransport:
    def __init__(self, fail_times=0, fail_message="refused"):
        self.fail_times = fail_times
        self.fail_message = fail_message
        self.will = None
        self.published = []
        self.connects = []
        self.configured = None
        self.handler = None

    def set_disconnect_handler(self, handler):
        self.handler = handler

    def configure(self, **kw):
        self.configured = kw

    def set_will(self, topic, payload, qos, retain):
        self.will = (topic, payload, qos, retain)

    def connect(self, host, port, keepalive):
        self.connects.append((host, port))
        if self.fail_times > 0:
            self.fail_times -= 1
            raise OSError(self.fail_message)

    def publish(self, topic, payload, qos, retain):
        self.published.append((topic, payload, qos, retain))

    def disconnect(self):
        pass


class Clock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t


def cfg(monkeypatch, **env):
    for k in [k for k in os.environ if k.startswith("HOSTWATCH_MQTT_")]:
        monkeypatch.delenv(k)
    monkeypatch.setenv("HOSTWATCH_ROLE", "hub")
    monkeypatch.setenv("HOSTWATCH_HUB_BIND", "127.0.0.1")
    for k, v in env.items():
        monkeypatch.setenv("HOSTWATCH_MQTT_" + k, v)
    c = Config()
    c.validate()
    return c


def test_disabled_by_default(monkeypatch):
    c = cfg(monkeypatch)
    assert not c.mqtt_enabled
    assert c.mqtt_discovery_prefix == "homeassistant"
    t = FakeTransport()
    client = MqttClient(c, t, clock=Clock())
    assert client.ensure_connected() is False
    assert t.connects == []


def test_settings_without_host_are_rejected(monkeypatch):
    with pytest.raises(ValueError, match="HOSTWATCH_MQTT_HOST"):
        cfg(monkeypatch, USERNAME="u")


def test_half_set_credentials(monkeypatch):
    with pytest.raises(ValueError, match="set together"):
        cfg(monkeypatch, HOST="b", USERNAME="u")
    with pytest.raises(ValueError, match="set together"):
        cfg(monkeypatch, HOST="b", PASSWORD="p")


def test_password_and_file_conflict(monkeypatch, tmp_path):
    f = tmp_path / "pw"
    f.write_text("x")
    with pytest.raises(ValueError, match="only one"):
        cfg(monkeypatch, HOST="b", USERNAME="u", PASSWORD="p", PASSWORD_FILE=str(f))


def test_missing_tls_files(monkeypatch, tmp_path):
    missing = str(tmp_path / "nope.pem")
    with pytest.raises(ValueError, match="HOSTWATCH_MQTT_TLS_CA"):
        cfg(monkeypatch, HOST="b", TLS_CA=missing)
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    with pytest.raises(ValueError, match="CERT and HOSTWATCH_MQTT_TLS_KEY"):
        cfg(monkeypatch, HOST="b", TLS_CA=str(ca), TLS_CERT=str(ca))
    with pytest.raises(ValueError, match="does not point"):
        cfg(monkeypatch, HOST="b", TLS_CERT=missing, TLS_KEY=missing)


def test_insecure_requires_tls_and_topics_checked(monkeypatch):
    with pytest.raises(ValueError, match="requires TLS"):
        cfg(monkeypatch, HOST="b", TLS_INSECURE="1")
    with pytest.raises(ValueError, match="BASE_TOPIC"):
        cfg(monkeypatch, HOST="b", BASE_TOPIC="a/#")
    with pytest.raises(ValueError, match="PORT"):
        cfg(monkeypatch, HOST="b", PORT="0")


def test_password_file_is_read_and_trimmed(monkeypatch, tmp_path):
    f = tmp_path / "pw"
    f.write_text(SECRET + "\n")
    c = cfg(monkeypatch, HOST="b", USERNAME="u", PASSWORD_FILE=str(f))
    assert c.mqtt_password_value() == SECRET


def test_connect_sets_will_and_retained_online(monkeypatch):
    c = cfg(monkeypatch, HOST="broker", PORT="8883", BASE_TOPIC="hw")
    t = FakeTransport()
    client = MqttClient(c, t, clock=Clock())
    assert client.ensure_connected() is True
    assert t.will == ("hw/availability", "offline", 1, True)
    assert t.connects == [("broker", 8883)]
    assert t.published == [("hw/availability", "online", 1, True)]
    client.close()
    assert t.published[-1] == ("hw/availability", "offline", 1, True)


def test_backoff_sequence_uses_injected_clock(monkeypatch):
    c = cfg(monkeypatch, HOST="broker")
    t = FakeTransport(fail_times=8)
    clock = Clock(0.0)
    client = MqttClient(c, t, clock=clock, rng=lambda: 1.0)  # top of the jitter range
    waits = []
    for _ in range(8):
        assert client.ensure_connected() is False
        waits.append(client.next_attempt - clock.t)
        attempts = len(t.connects)
        clock.t = client.next_attempt - 0.01
        assert client.ensure_connected() is False  # not due yet
        assert len(t.connects) == attempts
        clock.t = client.next_attempt
    assert waits == [1, 2, 4, 8, 16, 32, 60, 60]
    assert client.ensure_connected() is True
    assert client.failures == 0


def test_jitter_range():
    assert backoff_delay(3, lambda: 0.0) == 4.0
    assert backoff_delay(3, lambda: 1.0) == 8.0
    assert backoff_delay(99, lambda: 1.0) == 60.0


def test_disconnect_triggers_reconnect(monkeypatch):
    c = cfg(monkeypatch, HOST="broker")
    t = FakeTransport()
    client = MqttClient(c, t, clock=Clock())
    client.ensure_connected()
    t.handler()
    assert client.connected is False
    assert client.ensure_connected() is True
    assert len(t.connects) == 2


def test_password_never_logged(monkeypatch, tmp_path, caplog):
    f = tmp_path / "pw"
    f.write_text(SECRET)
    c = cfg(monkeypatch, HOST="broker", USERNAME="u", PASSWORD_FILE=str(f))
    t = FakeTransport(fail_times=1, fail_message=f"auth failed with {SECRET}")
    client = MqttClient(c, t, clock=Clock())
    with caplog.at_level(logging.DEBUG):
        client.ensure_connected()
    assert t.configured["password"] == SECRET
    assert "auth failed" in caplog.text
    assert SECRET not in caplog.text
    assert SECRET not in repr(c)


def test_paho_transport_builds_without_network():
    t = PahoTransport("hostwatch-test")
    t.configure(username="u", password="p", tls=False, ca="", cert="", key="", insecure=False)
    t.set_will("a/b", "offline", 1, True)
