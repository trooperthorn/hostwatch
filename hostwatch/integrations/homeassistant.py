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

import hashlib
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..config import Config, parse_sensor_patterns
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


def slug_hash(host: str) -> str:
    """Short stable suffix derived from the exact host name, used only when slugs collide."""
    return hashlib.sha256(host.encode("utf-8")).hexdigest()[:6]


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
    ]
    # A group that is not present by design gets no entity at all, so Home Assistant shows no
    # permanently unknown sensor for hardware the host does not have.
    if "power" not in summary.not_present:
        out.append(_sensor("package_power", "Package power", summary.package_power, device_class="power",
                           unit="W"))
    if summary.wall_power is not None:
        out.append(_sensor("wall_power", "Wall power", summary.wall_power, device_class="power", unit="W"))
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
    for c in summary.pools:
        pool = c.labels.get("pool", "")
        out.append(_sensor("pool_" + slug(pool), f"Pool {pool} health (0 ok, 1 warning, 2 critical)", c, diagnostic=True))
    for c in summary.disks:
        who = c.labels.get("device") or c.labels.get("wwn", "")
        out.append(_sensor("disk_" + slug(c.labels.get("wwn", "") or who), f"Disk {who} health status", c,
                           diagnostic=True))
    for full, c in summary.sources.items():
        if c.state == "not_present":
            continue
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
                 version: str = "", wall_power: Callable[[str, float], object] | None = None) -> None:
        self.config = config
        self.client = client
        self.store = store
        self._clock = clock
        self._hosts = hosts or self._store_hosts
        self._version = version
        self._wall_power = wall_power  # reads and stores the host's wall power before a summary build
        self._epoch = -1
        self._birth = threading.Event()
        self._published: dict[str, str] = {}  # discovery topic -> last payload sent
        # node id -> "component/key" entries published for it, persisted so a restart can retire
        # entities that are no longer built.
        self._keys_path = config.data_dir / "ha_discovery_keys.json"
        self._known: dict[str, set[str]] = self._load_known()
        self._slugs: dict[str, str] = {}  # host -> topic-safe identifier, disambiguated on collision
        self._warned: set[tuple[str, ...]] = set()
        client.add_listener(self._on_message)

    def _load_known(self) -> dict[str, set[str]]:
        try:
            raw = json.loads(self._keys_path.read_text(encoding="utf-8"))
            return {str(k): {str(x) for x in v} for k, v in raw.items()}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, AttributeError, TypeError):
            log.warning("Ignoring unreadable Home Assistant discovery key list %s", self._keys_path)
            return {}

    def _save_known(self) -> None:
        tmp = self._keys_path.with_name(self._keys_path.name + ".tmp")
        try:
            tmp.write_text(json.dumps({k: sorted(v) for k, v in sorted(self._known.items())}), encoding="utf-8")
            os.replace(tmp, self._keys_path)
        except OSError as exc:
            log.error("Could not save the Home Assistant discovery key list (%s); entities retired before a restart may keep stale retained configs", type(exc).__name__)

    def _assign_slugs(self, hosts: list[str]) -> None:
        """Hosts whose slugs collide (case or punctuation only) each get a hash suffix of the exact
        name, so they stay separate devices instead of overwriting each other's entities."""
        groups: dict[str, list[str]] = {}
        for h in hosts:
            groups.setdefault(slug(h), []).append(h)
        slugs: dict[str, str] = {}
        for base, members in groups.items():
            if len(members) == 1:
                slugs[members[0]] = base
                continue
            for h in members:
                slugs[h] = f"{base}_{slug_hash(h)}"
            names = tuple(sorted(members))
            if names not in self._warned:
                self._warned.add(names)
                log.warning("Host names %s map to the same Home Assistant identifier %r; adding a hash suffix "
                            "to each so they stay separate devices", " and ".join(repr(n) for n in names), base)
        self._slugs = slugs

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

    def _slug(self, host: str) -> str:
        return self._slugs.get(host) or slug(host)

    def _node(self, host: str) -> str:
        return "hostwatch_" + self._slug(host)

    def _state_base(self, host: str) -> str:
        return f"{self.config.mqtt_base_topic}/{self._slug(host)}"

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
        hosts = self._hosts()
        self._assign_slugs(hosts)
        for host in hosts:
            if self._wall_power is not None:
                self._wall_power(host, now)
            summary = build_host_summary(self.store, host, now, silent_after_s=self.config.silence_window_s,
                                       crash_hold_s=self.config.crash_hold_s,
                                       cpu_sensors=parse_sensor_patterns("HOSTWATCH_HWMON_CPU_SENSORS",
                                                                         self.config.hwmon_cpu_sensors))
            entities = build_entities(summary)
            for entity in entities:
                if not self._publish_entity(host, entity):
                    self._epoch = -1  # force a full republish once the connection is back
                    return False
            # An entity that is no longer built must not keep its retained discovery config or its
            # last "online" state: mark it unavailable, then clear the config.
            node = self._node(host)
            current = {f"{e.component}/{e.key}" for e in entities}
            if not self._retire(node, self._known.get(node, set()) - current):
                return False
            if self._known.get(node) != current:
                self._known[node] = current
                self._save_known()
        # Nodes that are no longer any current host's node (a host that disappeared, or one whose
        # identifier changed when a slug collision appeared or went away) retire every entry.
        live = {self._node(h) for h in hosts}
        for node in sorted(set(self._known) - live):
            if not self._retire(node, self._known[node]):
                return False
            del self._known[node]
            self._save_known()
        return True

    def _retire(self, node: str, entries: set[str]) -> bool:
        """Mark each entry unavailable and clear its retained discovery config."""
        slug_part = node.removeprefix("hostwatch_")
        for entry in sorted(entries):
            component, key = entry.split("/", 1)
            topic = f"{self.config.mqtt_discovery_prefix}/{component}/{node}/{key}/config"
            avail = f"{self.config.mqtt_base_topic}/{slug_part}/{key}/availability"
            marked = self.client.publish(avail, NOT_AVAILABLE, retain=True)
            cleared = marked and self.client.publish(topic, "", retain=True)
            if not cleared:
                self._epoch = -1
                return False
            self._published.pop(topic, None)
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
