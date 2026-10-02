"""MQTT client wrapper for the Home Assistant publisher.

The wrapper owns policy only: the last will, the retained online message, and capped
exponential reconnect backoff with jitter. The wire is behind the small MqttTransport
protocol so tests inject an in-memory fake and never touch a broker. PahoTransport is the
production adapter (paho-mqtt 2.x, callback API version 2). The wrapper takes its clock and
random source as arguments and never assumes how large the clock value is, so tests do not
depend on time.monotonic() starting high.

The broker password is read from the config only when connecting, is handed straight to the
transport, and is scrubbed from any exception text before it is logged.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Callable, Protocol

from ..config import Config

log = logging.getLogger(__name__)

ONLINE = "online"
OFFLINE = "offline"
BACKOFF_BASE_S = 1.0
BACKOFF_CAP_S = 60.0


class MqttTransport(Protocol):
    """What the wrapper needs from an MQTT library."""

    def configure(self, *, username: str, password: str, tls: bool, ca: str, cert: str, key: str,
                  insecure: bool) -> None: ...

    def set_will(self, topic: str, payload: str, qos: int, retain: bool) -> None: ...

    def connect(self, host: str, port: int, keepalive: int) -> None:
        """Open the connection or raise OSError."""

    def publish(self, topic: str, payload: str, qos: int, retain: bool) -> None: ...

    def disconnect(self) -> None: ...

    def set_disconnect_handler(self, handler: Callable[[], None]) -> None: ...

    def subscribe(self, topic: str, qos: int) -> None: ...

    def set_message_handler(self, handler: Callable[[str, str], None]) -> None:
        """Register a handler called with (topic, payload text) for each received message."""


def backoff_delay(attempt: int, rng: Callable[[], float]) -> float:
    """Delay before retry number `attempt` (0 based): base * 2**attempt capped at the cap, then
    jittered into the range 50% to 100% of that value so many hubs do not retry in step."""
    raw = min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** min(attempt, 30)))
    return raw * (0.5 + 0.5 * rng())


class MqttClient:
    def __init__(self, config: Config, transport: MqttTransport, *,
                 clock: Callable[[], float] = time.monotonic,
                 rng: Callable[[], float] = random.random, keepalive: int = 60) -> None:
        self.config = config
        self.transport = transport
        self._clock = clock
        self._rng = rng
        self._keepalive = keepalive
        self._lock = threading.RLock()  # the discovery loop and the events thread share one client
        self.connected = False
        self.failures = 0
        self.next_attempt: float | None = None
        self.epoch = 0  # counts successful connects, so a publisher can tell the broker session changed
        self._listeners: list[Callable[[str, str], None]] = []
        self.availability_topic = f"{config.mqtt_base_topic}/availability"
        # Home Assistant publishes its birth message here when it (re)starts.
        self.birth_topic = f"{config.mqtt_discovery_prefix}/status"
        transport.set_disconnect_handler(self._on_disconnect)
        transport.set_message_handler(self._on_message)

    @property
    def enabled(self) -> bool:
        return self.config.mqtt_enabled

    def _on_disconnect(self) -> None:
        self.connected = False

    def add_listener(self, listener: Callable[[str, str], None]) -> None:
        """Call `listener(topic, payload)` for each message on a subscribed topic. It may run on
        the transport's network thread, so it must only set a flag."""
        self._listeners.append(listener)

    def _on_message(self, topic: str, payload: str) -> None:
        for listener in list(self._listeners):
            listener(topic, payload)

    @staticmethod
    def _scrub(text: str, password: str) -> str:
        return text.replace(password, "***") if password else text

    def ensure_connected(self) -> bool:
        with self._lock:
            return self._ensure_connected()

    def _ensure_connected(self) -> bool:
        """Connect if needed and due. Returns True when connected. Safe to call every tick: after a
        failure it does nothing until the backoff delay has passed on the injected clock."""
        if not self.enabled:
            return False
        if self.connected:
            return True
        now = self._clock()
        if self.next_attempt is not None and now < self.next_attempt:
            return False
        cfg = self.config
        password = ""
        try:
            password = cfg.mqtt_password_value()
            self.transport.configure(username=cfg.mqtt_username, password=password, tls=cfg.mqtt_tls_active,
                                     ca=cfg.mqtt_tls_ca, cert=cfg.mqtt_tls_cert, key=cfg.mqtt_tls_key,
                                     insecure=cfg.mqtt_tls_insecure)
            self.transport.set_will(self.availability_topic, OFFLINE, 1, True)
            self.transport.connect(cfg.mqtt_host, cfg.mqtt_port, self._keepalive)
            self.transport.publish(self.availability_topic, ONLINE, 1, True)
            self.transport.subscribe(self.birth_topic, 1)
        except Exception as exc:  # noqa: BLE001 - any transport failure must schedule a retry
            delay = backoff_delay(self.failures, self._rng)
            self.failures += 1
            self.next_attempt = now + delay
            self.connected = False
            log.warning("MQTT connect to %s:%s failed (%s: %s); retrying in %.1fs", cfg.mqtt_host, cfg.mqtt_port,
                        type(exc).__name__, self._scrub(str(exc), password), delay)
            return False
        self.connected = True
        self.epoch += 1
        self.failures = 0
        self.next_attempt = None
        log.info("MQTT connected to %s:%s", cfg.mqtt_host, cfg.mqtt_port)
        return True

    def publish(self, topic: str, payload: str, *, retain: bool = False, qos: int = 1) -> bool:
        """Publish if connected. Returns False and does nothing when not connected."""
        with self._lock:
            if not self.connected:
                return False
            try:
                self.transport.publish(topic, payload, qos, retain)
            except Exception as exc:  # noqa: BLE001
                self.connected = False
                log.warning("MQTT publish failed (%s); will reconnect", type(exc).__name__)
                return False
            return True

    def close(self) -> None:
        """Clean shutdown. A clean disconnect does not fire the will, so say offline explicitly."""
        with self._lock:
            if self.connected:
                try:
                    self.transport.publish(self.availability_topic, OFFLINE, 1, True)
                    self.transport.disconnect()
                except Exception as exc:  # noqa: BLE001
                    log.warning("MQTT close failed (%s)", type(exc).__name__)
            self.connected = False


class PahoTransport:
    """paho-mqtt 2.x adapter. Not exercised against a broker in tests (see UNVERIFIED.md)."""

    def __init__(self, client_id: str) -> None:
        import paho.mqtt.client as mqtt
        self._client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
        self._handler: Callable[[], None] = lambda: None
        self._started = False
        self._client.on_disconnect = lambda *args, **kwargs: self._handler()
        self._message_handler: Callable[[str, str], None] = lambda topic, payload: None
        self._client.on_message = self._on_message

    def _on_message(self, client, userdata, msg) -> None:
        self._message_handler(msg.topic, msg.payload.decode("utf-8", "replace"))

    def set_message_handler(self, handler: Callable[[str, str], None]) -> None:
        self._message_handler = handler

    def subscribe(self, topic, qos) -> None:
        self._client.subscribe(topic, qos)

    def set_disconnect_handler(self, handler: Callable[[], None]) -> None:
        self._handler = handler

    def configure(self, *, username, password, tls, ca, cert, key, insecure) -> None:
        if username:
            self._client.username_pw_set(username, password)
        if tls:
            self._client.tls_set(ca_certs=ca or None, certfile=cert or None, keyfile=key or None)
            self._client.tls_insecure_set(insecure)

    def set_will(self, topic, payload, qos, retain) -> None:
        self._client.will_set(topic, payload, qos=qos, retain=retain)

    def connect(self, host, port, keepalive) -> None:
        self._client.connect(host, port, keepalive)
        if not self._started:
            self._client.loop_start()
            self._started = True

    def publish(self, topic, payload, qos, retain) -> None:
        self._client.publish(topic, payload, qos=qos, retain=retain)

    def disconnect(self) -> None:
        self._client.disconnect()
        if self._started:
            self._client.loop_stop()
            self._started = False
