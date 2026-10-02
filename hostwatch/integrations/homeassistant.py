"""Home Assistant MQTT discovery and state publishing.

Each monitored host becomes one Home Assistant device. Entities come from the shared
`build_host_summary`, so Home Assistant, Orion and Prometheus cannot disagree.

Topic layout (prefix and base topic come from the config):
  * Discovery, retained: `<prefix>/<component>/hostwatch_<host>/<key>/config`
  * State, retained:     `<base>/<host>/<key>/state`
  * Entity availability, retained: `<base>/<host>/<key>/availability` (`online` or `offline`)
  * Hub availability, retained, with the last will: `<base>/availability`

Every entity lists both availability topics with `availability_mode: all`. A value the summary
cannot know is published as entity availability `offline`, so Home Assistant shows it as
unavailable. No state is published for it and it is never reported as zero.

Discovery is republished when the broker session changes (first connect and every reconnect,
including after a broker restart), when Home Assistant publishes its birth message on
`<prefix>/status`, and when an entity definition changes. A fresh hub process has published
nothing yet, so a hub restart on the same database republishes everything too.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..config import Config
from .mqtt_client import MqttClient
from .summary import Component, HostSummary, StoreLike, build_host_summary

log = logging.getLogger(__name__)

AVAILABLE = "online"
NOT_AVAILABLE = "offline"
ON = "ON"
OFF = "OFF"
DEGREE_C = "°C"

PROBLEM_NAMES = {
    "md_degraded": "RAID array degraded",
    "disk_failing": "Disk failing",
    "source_unavailable": "Data source unavailable",
    "temperature_high": "Temperature high",
    "memory_low": "Memory low",
}


def slug(text: str) -> str:
    """Lowercase ASCII identifier safe for topics and unique ids."""
    out = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return out or "x"


@dataclass
class Entity:
    key: str
    component: str  # "sensor" or "binary_sensor"
    name: str
    state: str | None  # None means unavailable
    extra: dict[str, Any] = field(default_factory=dict)
    always_available: bool = False  # the state itself is the answer, so the entity is never unavailable


def _num(value: float | None) -> str | None:
    if value is None:
        return None
    return str(int(value)) if float(value).is_integer() else f"{value:.2f}".rstrip("0").rstrip(".")


def _sensor(key: str, name: str, comp: Component, *, device_class: str | None = None, unit: str | None = None,
            state_class: str | None = "measurement", diagnostic: bool = False) -> Entity:
    extra: dict[str, Any] = {}
    if device_class:
        extra["device_class"] = device_class
    if unit:
        extra["unit_of_measurement"] = unit
    if state_class:
        extra["state_class"] = state_class
    if diagnostic:
        extra["entity_category"] = "diagnostic"
    return Entity(key, "sensor", name, _num(comp.value), extra)


def _flag(on: bool | None) -> str | None:
    return None if on is None else (ON if on else OFF)


def build_entities(summary: HostSummary) -> list[Entity]:
    """Every entity for one host, with its current state (None when unknown)."""
    out = [
        _sensor("cpu_utilization", "CPU utilization", summary.cpu, unit="%"),
        _sensor("memory_used", "Memory used", summary.memory, unit="%"),
        _sensor("package_power", "Package power", summary.package_power, device_class="power", unit="W"),
    ]
    for c in summary.temperatures:
        if c.name.startswith("disk_temp."):
            who = c.labels.get("device") or c.labels.get("wwn", "")
            key = "disk_temp_" + slug(c.labels.get("wwn", "") or who)
            name = f"Disk {who} temperature"
        else:
            label = f"{c.labels.get('chip', '')} {c.labels.get('sensor', '')}".strip()
            key = "temp_" + slug(label) if label else "temp"
            name = f"Temperature {label}".strip()
        out.append(_sensor(key, name, c, device_class="temperature", unit=DEGREE_C))
    for c in summary.md_arrays:
        arr = c.labels.get("array", "")
        out.append(_sensor("md_" + slug(arr), f"RAID array {arr} degraded devices", c, diagnostic=True))
    for c in summary.disks:
        who = c.labels.get("device") or c.labels.get("wwn", "")
        out.append(_sensor("disk_" + slug(c.labels.get("wwn", "") or who), f"Disk {who} health status", c,
                           diagnostic=True))
    for full, c in summary.sources.items():
        short = full.removeprefix("source.")
        # A source that is down is a real answer ("off"), so the entity stays available.
        out.append(Entity("source_" + slug(short) + "_up", "binary_sensor", f"Source {short} reporting",
                          ON if c.value is not None else OFF,
                          {"device_class": "connectivity", "entity_category": "diagnostic"}, always_available=True))
    for flag, label in PROBLEM_NAMES.items():
        out.append(Entity("problem_" + flag, "binary_sensor", label, _flag(summary.problems.get(flag)),
                          {"device_class": "problem"}))
    return out


class HomeAssistantPublisher:
    def __init__(self, config: Config, client: MqttClient, store: StoreLike, *,
                 clock: Callable[[], float] = time.time, hosts: Callable[[], list[str]] | None = None,
                 version: str = "") -> None:
        self.config = config
        self.client = client
        self.store = store
        self._clock = clock
        self._hosts = hosts or self._store_hosts
        self._version = version
        self._epoch = -1
        self._birth = threading.Event()
        self._published: dict[str, str] = {}  # discovery topic -> last payload sent
        self._known: dict[str, set[str]] = {}  # host -> entity keys published by this process
        client.add_listener(self._on_message)

    def _store_hosts(self) -> list[str]:
        names = {r["host"] for r in self.store.sources()}
        agents = getattr(self.store, "agents", None)
        if agents:
            names |= {a["host"] for a in agents()}
        return sorted(names)

    def _on_message(self, topic: str, payload: str) -> None:
        # Runs on the network thread: only set a flag, tick() does the publishing.
        if topic == self.client.birth_topic and payload.strip().lower() == "online":
            self._birth.set()

    @staticmethod
    def _node(host: str) -> str:
        return "hostwatch_" + slug(host)

    def _state_base(self, host: str) -> str:
        return f"{self.config.mqtt_base_topic}/{slug(host)}"

    def discovery_topic(self, host: str, entity: Entity) -> str:
        return f"{self.config.mqtt_discovery_prefix}/{entity.component}/{self._node(host)}/{entity.key}/config"

    def discovery_payload(self, host: str, entity: Entity) -> dict[str, Any]:
        base = f"{self._state_base(host)}/{entity.key}"
        availability = [{"topic": self.client.availability_topic}]
        if not entity.always_available:
            availability.append({"topic": f"{base}/availability"})
        payload: dict[str, Any] = {
            "name": entity.name,
            "unique_id": f"{self._node(host)}_{entity.key}",
            "state_topic": f"{base}/state",
            "availability": availability,
            "availability_mode": "all",
            "payload_available": AVAILABLE,
            "payload_not_available": NOT_AVAILABLE,
            "has_entity_name": True,
            "device": {
                "identifiers": [self._node(host)],
                "name": host,
                "manufacturer": "hostwatch",
                "model": "Host monitor",
            },
            "origin": {"name": "hostwatch"},
        }
        if self._version:
            payload["device"]["sw_version"] = self._version
        if entity.component == "binary_sensor":
            payload["payload_on"] = ON
            payload["payload_off"] = OFF
        payload.update(entity.extra)
        return payload

    def tick(self) -> bool:
        """Connect if needed, republish discovery when due, publish state. Returns False when not
        connected or a publish failed (the next tick starts over with a full republish)."""
        if not self.client.ensure_connected():
            return False
        if self._birth.is_set() or self.client.epoch != self._epoch:
            self._birth.clear()
            self._published.clear()
            self._epoch = self.client.epoch
        now = self._clock()
        for host in self._hosts():
            summary = build_host_summary(self.store, host, now)
            entities = build_entities(summary)
            for entity in entities:
                if not self._publish_entity(host, entity):
                    self._epoch = -1  # force a full republish once the connection is back
                    return False
            # An entity whose inputs vanished must not keep its last retained "online" state.
            current = {e.key for e in entities}
            for key in sorted(self._known.get(host, set()) - current):
                if not self.client.publish(f"{self._state_base(host)}/{key}/availability", NOT_AVAILABLE,
                                           retain=True):
                    self._epoch = -1
                    return False
            self._known[host] = current
        return True

    def _publish_entity(self, host: str, entity: Entity) -> bool:
        topic = self.discovery_topic(host, entity)
        payload = json.dumps(self.discovery_payload(host, entity), sort_keys=True, ensure_ascii=False)
        if self._published.get(topic) != payload:
            if not self.client.publish(topic, payload, retain=True):
                return False
            self._published[topic] = payload
        base = f"{self._state_base(host)}/{entity.key}"
        if entity.state is not None and not self.client.publish(f"{base}/state", entity.state, retain=True):
            return False
        if not entity.always_available:
            avail = AVAILABLE if entity.state is not None else NOT_AVAILABLE
            if not self.client.publish(f"{base}/availability", avail, retain=True):
                return False
        return True

    def close(self) -> None:
        self.client.close()
