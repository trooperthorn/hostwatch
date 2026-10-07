"""Polling tiers: how often each group of collectors runs, and where the rates come from.

Observe decides how hard each host is polled (design section 10.1) and tells the agent through
GET /internal/v1/agent-config. The agent never trusts that answer blindly. Each rate is a number
of seconds clamped between the lowest and highest value Observe itself accepts for the tier, so a
bad or hostile answer can neither make the host spin nor silence a tier. A tier that is missing,
not a number, not finite or a boolean falls back to its default. When Observe cannot be reached
the last good rates stay in force, and before any answer has arrived the defaults apply.

The tiers are:

* availability: the heartbeat and the source status report, which tell Observe the agent is alive.
* device_metrics: CPU, memory, load, temperatures, fans, power and UPS readings.
* storage_health: RAID and ZFS state, pool and drive usage and drive temperature.
* smart: SMART self-assessments, which are slow to read and wear nothing but time.
* inventory: firmware, versions and other facts that change rarely. No collector reads these yet.

Events are not a tier. They are checked every EVENT_POLL_S seconds whatever the tier rates are,
so a RAID failure is not held back by a storage poll that runs every fifteen minutes.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass

log = logging.getLogger("hostwatch.tiers")

AVAILABILITY = "availability"
DEVICE_METRICS = "device_metrics"
STORAGE_HEALTH = "storage_health"
SMART = "smart"
INVENTORY = "inventory"

# tier -> (default seconds, lowest, highest). These match observe/tiers.py.
LIMITS: dict[str, tuple[float, float, float]] = {
    AVAILABILITY: (30.0, 5.0, 3600.0),
    DEVICE_METRICS: (60.0, 10.0, 3600.0),
    STORAGE_HEALTH: (900.0, 60.0, 86400.0),
    SMART: (3600.0, 300.0, 86400.0),
    INVENTORY: (3600.0, 600.0, 86400.0),
}
TIERS = tuple(LIMITS)
DEFAULTS = {name: spec[0] for name, spec in LIMITS.items()}

AGENT_CONFIG_PATH = "/internal/v1/agent-config"
# How often the agent asks Observe for its rates again, so a change made in the console applies
# without a visit to the host.
CONFIG_REFRESH_S = 300.0
# After a failed fetch the agent asks again sooner than the normal refresh, but not in a tight loop.
CONFIG_RETRY_S = 60.0
CONFIG_TIMEOUT_S = 10.0
# Events and the delivery queue are looked at this often, whatever the tier rates are.
EVENT_POLL_S = 5.0


def clamp_rate(tier: str, raw: object) -> float | None:
    """The rate for a tier as a float inside its limits, or None when `raw` is not a usable number."""
    if tier not in LIMITS or isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    value = float(raw)
    if not math.isfinite(value):
        return None
    _, low, high = LIMITS[tier]
    return min(max(value, low), high)


def parse_agent_config(body: object) -> dict[str, float] | None:
    """The tier rates in an agent-config answer, each clamped to its limits. Returns None when the
    answer has no usable `intervals` object at all. A tier whose value is unusable is left out, so
    the caller keeps its current rate for that tier."""
    if not isinstance(body, dict) or not isinstance(body.get("intervals"), dict):
        return None
    rates: dict[str, float] = {}
    for tier, raw in body["intervals"].items():
        value = clamp_rate(tier, raw)
        if value is not None:
            rates[tier] = value
        elif tier in LIMITS:
            log.warning("agent-config gave an unusable rate for %s; keeping the current rate", tier)
    return rates


@dataclass
class TierState:
    interval_s: float
    next_due: float = 0.0


class TierSchedule:
    """When each tier is next due, on a clock the caller supplies (monotonic seconds).

    Every tier is due at the first call, so the first report carries a full picture. A tier that
    is due runs once and is rescheduled one interval after the time it was *due*, not after it
    finished, so a slow collector does not stretch the cadence; if the agent fell far behind the
    next run is simply scheduled from now.
    """

    def __init__(self, rates: dict[str, float] | None = None) -> None:
        self.tiers = {name: TierState(DEFAULTS[name]) for name in TIERS}
        if rates:
            self.apply(rates)

    def rates(self) -> dict[str, float]:
        return {name: st.interval_s for name, st in self.tiers.items()}

    def apply(self, rates: dict[str, float]) -> None:
        """Take new rates. A tier that is not due for longer than its new interval is pulled in,
        so a lowered rate applies at once instead of after the old, longer wait."""
        for name, value in rates.items():
            st = self.tiers.get(name)
            clean = clamp_rate(name, value)
            if st is None or clean is None:
                continue
            st.interval_s = clean

    def reschedule(self, now: float) -> None:
        """After new rates arrive, never wait longer than the new interval for any tier."""
        for st in self.tiers.values():
            if st.next_due > now + st.interval_s:
                st.next_due = now + st.interval_s

    def due(self, now: float) -> list[str]:
        return [name for name, st in self.tiers.items() if now >= st.next_due]

    def done(self, tier: str, now: float) -> None:
        st = self.tiers[tier]
        nxt = st.next_due + st.interval_s
        st.next_due = nxt if nxt > now else now + st.interval_s

    def seconds_until_next(self, now: float) -> float:
        return max(0.0, min(st.next_due for st in self.tiers.values()) - now)
