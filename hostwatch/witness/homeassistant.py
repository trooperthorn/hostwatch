"""Home Assistant smart plug witness.

A smart plug on the same circuit as a host drops off the network when the power fails, so its
state history can confirm an outage the host itself cannot see. The hub reads the history of one
configured entity per host over the Home Assistant REST API, using a long-lived access token that
the operator supplies in a file. TLS verification is on; there is no switch to turn it off here.

Rules this module keeps:

* Only a successful, non-empty answer is evidence. An unreachable server, a rejected token, a
  missing entity or an unreadable answer returns `available=False` with a reason. An empty outage
  list is only ever returned together with `available=True`, meaning the plug was seen and was on.
* The token is read from its file at call time, is sent only in the `Authorization` header, and
  never appears in a log line, a reason or an exception message.
* A host may have several entities, written `host=entity1|entity2`. Each has a role: `switch`
  (outage states `unavailable`, `unknown`, `off`), `node_status` (a Z-Wave node status entity;
  outage states `dead`, `unavailable`, `unknown`, while `alive`, `awake` and `asleep` are not
  outages) or `power` (a watt reading, not history; see `read_power`). The role is written as a
  prefix (`node_status:sensor.plug_node_status`) or, without a prefix, inferred from the entity id:
  an id ending in `_node_status` is a node status, an id in the `sensor` domain whose name ends in
  `_power` is a power reading, anything else is a switch. Evidence from several entities is
  combined: an outage on any of them counts.
* Intervals are clipped to the requested window and carry epoch seconds in UTC.

The endpoint path, header and response shape are recorded in `UNVERIFIED.md` until confirmed.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx

log = logging.getLogger(__name__)

OUTAGE_STATES = frozenset({"unavailable", "unknown", "off"})
NODE_STATUS_OUTAGE_STATES = frozenset({"dead", "unavailable", "unknown"})
ROLE_SWITCH, ROLE_NODE_STATUS, ROLE_POWER = "switch", "node_status", "power"
ROLES = (ROLE_SWITCH, ROLE_NODE_STATUS, ROLE_POWER)
OUTAGE_STATES_BY_ROLE = {ROLE_SWITCH: OUTAGE_STATES, ROLE_NODE_STATUS: NODE_STATUS_OUTAGE_STATES}
REQUEST_TIMEOUT_S = 10.0
# A wall power reading younger than this is reused, so several summary builds in a row (the UI,
# Orion, Prometheus and Home Assistant) ask Home Assistant once.
POWER_MIN_INTERVAL_S = 10.0


@dataclass(frozen=True)
class OutageInterval:
    """A period in which the plug reported an outage state. `end` is the window end when the
    state had not yet changed (`open_ended`)."""
    start: float
    end: float
    state: str
    open_ended: bool = False
    entity_id: str = ""


@dataclass(frozen=True)
class PowerReading:
    """One wall power reading. `watts` is None, with a reason, when it could not be read."""
    entity_id: str
    watts: float | None
    reason: str = ""


@dataclass
class WitnessResult:
    available: bool
    reason: str = ""
    intervals: list[OutageInterval] = field(default_factory=list)
    entity_id: str = ""


def parse_power_witness(raw: str) -> dict[str, str]:
    """Parse `host=entity_id` pairs separated by commas, semicolons or newlines. Malformed
    pairs are skipped with a warning that names no secret."""
    mapping: dict[str, str] = {}
    for part in raw.replace(";", ",").replace("\n", ",").split(","):
        part = part.strip()
        if not part:
            continue
        host, sep, entity = part.partition("=")
        host, entity = host.strip(), entity.strip()
        if not sep or not host or not entity:
            log.warning("ignoring malformed HOSTWATCH_POWER_WITNESS entry")
            continue
        mapping[host] = entity
    return mapping


@dataclass(frozen=True)
class WitnessEntity:
    role: str
    entity_id: str


def role_for(entity_id: str) -> str:
    """Infer a role from an entity id that was written without a prefix."""
    domain, _, name = entity_id.partition(".")
    if name.endswith("_node_status"):
        return ROLE_NODE_STATUS
    if domain == "sensor" and name.endswith("_power"):
        return ROLE_POWER
    return ROLE_SWITCH


def parse_entities(spec: str) -> list[WitnessEntity]:
    """Split `entity1|entity2` into entities with roles. Unknown role prefixes are skipped."""
    out: list[WitnessEntity] = []
    for item in spec.split("|"):
        item = item.strip()
        if not item:
            continue
        prefix, sep, rest = item.partition(":")
        if sep:
            if prefix.strip().lower() not in ROLES or not rest.strip():
                log.warning("ignoring a HOSTWATCH_POWER_WITNESS entity with an unknown role")
                continue
            out.append(WitnessEntity(prefix.strip().lower(), rest.strip()))
        else:
            out.append(WitnessEntity(role_for(item), item))
    return out


def _to_epoch(value: str) -> float:
    """Convert an ISO 8601 timestamp to epoch seconds. A value without an offset is read as UTC."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def intervals_from_history(states: list[dict], start: float, end: float,
                           outage_states: frozenset[str] = OUTAGE_STATES) -> list[OutageInterval]:
    """Turn one entity's state list into outage intervals clipped to [start, end]. A change
    between two outage states (unavailable to off) starts a new interval so the evidence of
    each state stays exact. `outage_states` depends on the entity role."""
    changes = sorted(((_to_epoch(item["last_changed"]), str(item["state"]).lower()) for item in states),
                     key=lambda c: c[0])
    out: list[OutageInterval] = []
    for i, (ts, state) in enumerate(changes):
        if state not in outage_states:
            continue
        nxt = changes[i + 1][0] if i + 1 < len(changes) else None
        if ts >= end:
            continue
        lo = max(ts, start)
        hi = end if nxt is None else min(nxt, end)
        if nxt is not None and hi <= lo:
            continue
        out.append(OutageInterval(lo, max(hi, lo), state, open_ended=nxt is None or nxt >= end))
    return out


class HomeAssistantWitness:
    """Reads plug history for hosts. `transport` lets tests supply an httpx mock transport."""

    def __init__(self, url: str, token_file: str, mapping: dict[str, str],
                 transport: httpx.BaseTransport | None = None, clock=time.monotonic):
        self.url = url.rstrip("/")
        self.token_file = token_file
        self.mapping = dict(mapping)
        self._transport = transport
        self._clock = clock
        self._power_cache: dict[str, tuple[float, PowerReading]] = {}

    @classmethod
    def from_config(cls, cfg, transport: httpx.BaseTransport | None = None):
        return cls(cfg.ha_url, cfg.ha_token_file, parse_power_witness(cfg.power_witness), transport)

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token_file and self.mapping)

    def entities(self, host: str, *roles: str) -> list[WitnessEntity]:
        found = parse_entities(self.mapping.get(host, ""))
        return [e for e in found if not roles or e.role in roles]

    def _read_token(self) -> str:
        return Path(self.token_file).read_text(encoding="utf-8").strip()

    def outages(self, host: str, start: float, end: float) -> WitnessResult:
        """Outage intervals for the host's plug entities between two epoch times. Switch and node
        status entities are asked one by one and their evidence is combined: the result is
        available when at least one entity gave a usable answer, and an entity that could not be
        asked is named in the reason."""
        entities = self.entities(host, ROLE_SWITCH, ROLE_NODE_STATUS)
        if not entities:
            return WitnessResult(False, "no power witness entity is configured for this host")
        names = ", ".join(e.entity_id for e in entities)
        if not (self.url and self.token_file):
            return WitnessResult(False, "Home Assistant URL or token file is not configured",
                                 entity_id=names)
        if end <= start:
            return WitnessResult(False, "the requested window is empty", entity_id=names)
        try:
            token = self._read_token()
        except OSError as exc:
            return WitnessResult(False, f"cannot read the Home Assistant token file ({type(exc).__name__})",
                                 entity_id=names)
        if not token:
            return WitnessResult(False, "the Home Assistant token file is empty", entity_id=names)

        results = [self._history(e, start, end, token) for e in entities]
        good = [r for r in results if r.available]
        if not good:
            return WitnessResult(False, "; ".join(f"{r.entity_id}: {r.reason}" for r in results)
                                 if len(results) > 1 else results[0].reason, entity_id=names)
        intervals = sorted((i for r in good for i in r.intervals), key=lambda i: (i.start, i.entity_id))
        bad = [r for r in results if not r.available]
        reason = "; ".join(f"{r.entity_id}: {r.reason}" for r in bad)
        return WitnessResult(True, reason, intervals, names)

    def _history(self, entity: WitnessEntity, start: float, end: float, token: str) -> WitnessResult:
        eid = entity.entity_id
        endpoint = f"{self.url}/api/history/period/{quote(_iso(start), safe='')}"
        params = {"filter_entity_id": eid, "end_time": _iso(end), "minimal_response": "1",
                  "no_attributes": "1"}
        headers = {"Authorization": f"Bearer {token}"}
        try:
            with httpx.Client(verify=True, timeout=REQUEST_TIMEOUT_S, transport=self._transport) as client:
                resp = client.get(endpoint, params=params, headers=headers)
        except httpx.HTTPError as exc:
            # The exception class only: its text can carry the request URL.
            return WitnessResult(False, f"Home Assistant is unreachable ({type(exc).__name__})",
                                 entity_id=eid)
        if resp.status_code in (401, 403):
            return WitnessResult(False, f"Home Assistant refused the token (HTTP {resp.status_code})",
                                 entity_id=eid)
        if resp.status_code != 200:
            return WitnessResult(False, f"Home Assistant answered HTTP {resp.status_code}", entity_id=eid)
        try:
            body = resp.json()
            series = body[0] if body else []
            if not series:
                return WitnessResult(False, "Home Assistant has no history for the entity "
                                     "(missing entity or no recorded states in the window)", entity_id=eid)
            # minimal_response omits entity_id after the first item, so only the first is checked.
            if series[0].get("entity_id", eid) != eid:
                return WitnessResult(False, "Home Assistant returned history for a different entity",
                                     entity_id=eid)
            intervals = intervals_from_history(series, start, end, OUTAGE_STATES_BY_ROLE[entity.role])
        except (ValueError, KeyError, TypeError, AttributeError, IndexError):
            return WitnessResult(False, "Home Assistant returned history in an unexpected shape",
                                 entity_id=eid)
        intervals = [replace(i, entity_id=eid) for i in intervals]
        return WitnessResult(True, "", intervals, eid)

    def read_power(self, host: str) -> PowerReading | None:
        """The host's wall power in watts from its power entity, or None when the host has none.
        An unreadable or unavailable entity gives a reading with `watts=None` and a reason, never
        zero. A reading less than `POWER_MIN_INTERVAL_S` old is reused."""
        entities = self.entities(host, ROLE_POWER)
        if not entities:
            return None
        if len(entities) > 1:
            log.warning("only the first power entity of a host is read")
        eid = entities[0].entity_id
        cached = self._power_cache.get(host)
        if cached and self._clock() - cached[0] < POWER_MIN_INTERVAL_S:
            return cached[1]
        reading = self._fetch_power(eid)
        self._power_cache[host] = (self._clock(), reading)
        return reading

    def _fetch_power(self, eid: str) -> PowerReading:
        if not (self.url and self.token_file):
            return PowerReading(eid, None, "Home Assistant URL or token file is not configured")
        try:
            token = self._read_token()
        except OSError as exc:
            return PowerReading(eid, None, f"cannot read the Home Assistant token file ({type(exc).__name__})")
        if not token:
            return PowerReading(eid, None, "the Home Assistant token file is empty")
        try:
            with httpx.Client(verify=True, timeout=REQUEST_TIMEOUT_S, transport=self._transport) as client:
                resp = client.get(f"{self.url}/api/states/{quote(eid, safe='')}",
                                  headers={"Authorization": f"Bearer {token}"})
        except httpx.HTTPError as exc:
            return PowerReading(eid, None, f"Home Assistant is unreachable ({type(exc).__name__})")
        if resp.status_code in (401, 403):
            return PowerReading(eid, None, f"Home Assistant refused the token (HTTP {resp.status_code})")
        if resp.status_code == 404:
            return PowerReading(eid, None, "Home Assistant does not know the power entity")
        if resp.status_code != 200:
            return PowerReading(eid, None, f"Home Assistant answered HTTP {resp.status_code}")
        try:
            body = resp.json()
            state = str(body["state"]).strip()
            unit = str((body.get("attributes") or {}).get("unit_of_measurement", "W")).strip()
        except (ValueError, KeyError, TypeError, AttributeError):
            return PowerReading(eid, None, "Home Assistant returned the power entity in an unexpected shape")
        if state.lower() in ("unavailable", "unknown", ""):
            return PowerReading(eid, None, f"the power entity is {state.lower() or 'empty'}")
        try:
            value = float(state)
        except ValueError:
            return PowerReading(eid, None, "the power entity state is not a number")
        factor = {"W": 1.0, "kW": 1000.0}.get(unit)
        if factor is None:
            return PowerReading(eid, None, f"the power entity unit {unit!r} is not W or kW")
        watts = value * factor
        if not math.isfinite(watts) or watts < 0:
            return PowerReading(eid, None, "the power entity value is not a usable wattage")
        return PowerReading(eid, watts, "")
