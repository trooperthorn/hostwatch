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
* Outage states are `unavailable`, `unknown` and `off`. Intervals are clipped to the requested
  window and carry epoch seconds in UTC.

The endpoint path, header and response shape are recorded in `UNVERIFIED.md` until confirmed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx

log = logging.getLogger(__name__)

OUTAGE_STATES = frozenset({"unavailable", "unknown", "off"})
REQUEST_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class OutageInterval:
    """A period in which the plug reported an outage state. `end` is the window end when the
    state had not yet changed (`open_ended`)."""
    start: float
    end: float
    state: str
    open_ended: bool = False


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


def intervals_from_history(states: list[dict], start: float, end: float) -> list[OutageInterval]:
    """Turn one entity's state list into outage intervals clipped to [start, end]. A change
    between two outage states (unavailable to off) starts a new interval so the evidence of
    each state stays exact."""
    changes = sorted(((_to_epoch(item["last_changed"]), str(item["state"]).lower()) for item in states),
                     key=lambda c: c[0])
    out: list[OutageInterval] = []
    for i, (ts, state) in enumerate(changes):
        if state not in OUTAGE_STATES:
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
                 transport: httpx.BaseTransport | None = None):
        self.url = url.rstrip("/")
        self.token_file = token_file
        self.mapping = dict(mapping)
        self._transport = transport

    @classmethod
    def from_config(cls, cfg, transport: httpx.BaseTransport | None = None):
        return cls(cfg.ha_url, cfg.ha_token_file, parse_power_witness(cfg.power_witness), transport)

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token_file and self.mapping)

    def _read_token(self) -> str:
        return Path(self.token_file).read_text(encoding="utf-8").strip()

    def outages(self, host: str, start: float, end: float) -> WitnessResult:
        """Outage intervals for the host's plug between two epoch times."""
        entity = self.mapping.get(host)
        if not entity:
            return WitnessResult(False, "no power witness entity is configured for this host")
        if not (self.url and self.token_file):
            return WitnessResult(False, "Home Assistant URL or token file is not configured",
                                 entity_id=entity)
        if end <= start:
            return WitnessResult(False, "the requested window is empty", entity_id=entity)
        try:
            token = self._read_token()
        except OSError as exc:
            return WitnessResult(False, f"cannot read the Home Assistant token file ({type(exc).__name__})",
                                 entity_id=entity)
        if not token:
            return WitnessResult(False, "the Home Assistant token file is empty", entity_id=entity)

        endpoint = f"{self.url}/api/history/period/{quote(_iso(start), safe='')}"
        params = {"filter_entity_id": entity, "end_time": _iso(end), "minimal_response": "1",
                  "no_attributes": "1"}
        headers = {"Authorization": f"Bearer {token}"}
        try:
            with httpx.Client(verify=True, timeout=REQUEST_TIMEOUT_S, transport=self._transport) as client:
                resp = client.get(endpoint, params=params, headers=headers)
        except httpx.HTTPError as exc:
            # The exception class only: its text can carry the request URL.
            return WitnessResult(False, f"Home Assistant is unreachable ({type(exc).__name__})",
                                 entity_id=entity)
        if resp.status_code in (401, 403):
            return WitnessResult(False, f"Home Assistant refused the token (HTTP {resp.status_code})",
                                 entity_id=entity)
        if resp.status_code != 200:
            return WitnessResult(False, f"Home Assistant answered HTTP {resp.status_code}", entity_id=entity)
        try:
            body = resp.json()
            series = body[0] if body else []
            if not series:
                return WitnessResult(False, "Home Assistant has no history for the entity "
                                     "(missing entity or no recorded states in the window)", entity_id=entity)
            # minimal_response omits entity_id after the first item, so only the first is checked.
            if series[0].get("entity_id", entity) != entity:
                return WitnessResult(False, "Home Assistant returned history for a different entity",
                                     entity_id=entity)
            intervals = intervals_from_history(series, start, end)
        except (ValueError, KeyError, TypeError, AttributeError, IndexError):
            return WitnessResult(False, "Home Assistant returned history in an unexpected shape",
                                 entity_id=entity)
        return WitnessResult(True, "", intervals, entity)
