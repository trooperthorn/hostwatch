"""Witness-confirmed power loss for unclean boots.

The agent cannot tell a power cut from a hang, so it reports `boot.unknown_unclean`. The hub then
asks the outside witnesses about the window from the previous heartbeat minus a skew allowance
to the boot time plus the allowance (`HOSTWATCH_WITNESS_SKEW_S`, default 120 seconds, which
absorbs clock differences between the host, the hub and Home Assistant):

* the Home Assistant smart plug history, through `HomeAssistantWitness`, and
* the UPS events `ups.on_battery` and `ups.low_battery` stored for the same host.

An outage overlapping the window adds a `boot.power_loss` event with the same boot id and a
dedup key of `boot:<boot_id>:power_loss`, carrying every piece of evidence and the skew used.
The original event is kept and gets the same evidence under `detail.power_witness`. Without an
overlapping outage the original event stays as it was, and `detail.power_witness` records what
was asked and why there was no confirmation. A witness that is not configured or cannot be
reached is recorded as unavailable with its reason; it is never read as proof of no outage.

An outage confirms only if it began no later than the boot time plus the allowance and ended no
earlier than the last heartbeat minus the allowance. An outage found after that (the host was
already back) is kept under `non_confirming` as evidence that does not count. The witnesses are
asked a little beyond the window (`LOOKAHEAD_S`) so such an outage can be recorded.

Every unclean kind is assessed: `unknown_unclean`, an abrupt `agent_stopped` and `unknown`. When
a witness was unavailable and nothing confirmed an outage, the evidence carries
`retry_pending`, and the hub asks again with a backoff for `HOSTWATCH_WITNESS_RETRY_S` (default
24 hours) and once at every hub start. `python -m hostwatch boot reassess HOST BOOT_ID` asks
again on demand and is audited.

A Z-Wave plug cannot report its own power loss, so its node status entity (`dead`) is read as an
outage like the unavailable state of a switch. The controller needs time to notice a dead node, so an
outage shorter than that is not witnessed and stays `unknown_unclean`; see `UNVERIFIED.md`.
The host's wall power is read by `read_wall_power` below.

A fresh pstore panic (`boot.kernel_panic`) and a watchdog reset (`boot.watchdog_reset`) outrank
a power loss. For those the outage is only noted under `detail.power_witness`.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from ..events import boot

log = logging.getLogger("hostwatch.power")

UPS_KINDS = ("ups.on_battery", "ups.low_battery")
NOTE_ONLY_KINDS = ("boot." + boot.KERNEL_PANIC, "boot." + boot.WATCHDOG_RESET)
MAX_UPS_EVENTS = 50
LOOKAHEAD_S = 3600.0
RETRY_BASE_S = 60.0
RETRY_CAP_S = 3600.0


def _num(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def eligible(event: dict) -> str | None:
    """"promote", "note" or None for a boot event dict from a batch."""
    kind = event.get("kind")
    detail = event.get("detail") or {}
    if kind in ("boot." + boot.UNKNOWN_UNCLEAN, "boot." + boot.UNKNOWN):
        return "promote"
    if kind == "boot." + boot.AGENT_STOPPED and (detail.get("journal_hints") or {}).get("abrupt_end") is True:
        return "promote"
    if kind in NOTE_ONLY_KINDS:
        return "note"
    return None


def window_for(event: dict, skew_s: float) -> tuple[float, float] | None:
    """From the previous heartbeat minus the skew to the boot time plus the skew. The boot time
    is when the agent noticed the new boot (`detail.detected_at`), the closest value recorded."""
    detail = event.get("detail") or {}
    hb = _num(detail.get("heartbeat_ts"))
    if hb is None:
        hb = _num(event.get("ts"))
    if hb is None:
        return None
    boot_time = _num(detail.get("detected_at"))
    boot_time = hb if boot_time is None else max(boot_time, hb)
    return hb - skew_s, boot_time + skew_s


def confirms(start: float, end: float, lo: float, hi: float) -> bool:
    """True when an outage began no later than the window end and ended no earlier than the
    window start. The window already carries the skew allowance on both sides."""
    return start <= hi and end >= lo


def collect_evidence(store, witness, host: str, lo: float, hi: float, skew_s: float) -> dict[str, Any]:
    """Ask every witness about [lo, hi], looking `LOOKAHEAD_S` further so a later outage can be
    recorded as non-confirming. The result never raises."""
    evidence: dict[str, Any] = {"window_start": lo, "window_end": hi, "skew_s": skew_s,
                                "overlapping_outage": False}
    if witness is None or not getattr(witness, "configured", False):
        evidence["plug"] = {"available": False, "reason": "no Home Assistant power witness is configured"}
    else:
        res = None
        try:
            res = witness.outages(host, lo, hi + LOOKAHEAD_S)
        except Exception as exc:  # a witness fault must never lose the boot event
            evidence["plug"] = {"available": False, "reason": f"the witness failed ({type(exc).__name__})"}
        if res is not None:
            def row(i):
                return {"start": i.start, "end": i.end, "state": i.state, "open_ended": i.open_ended,
                        "entity_id": i.entity_id}
            hits = [i for i in res.intervals if confirms(i.start, i.end, lo, hi)]
            late = [i for i in res.intervals if not confirms(i.start, i.end, lo, hi)]
            evidence["plug"] = {
                "available": res.available, "reason": res.reason, "entity_id": res.entity_id,
                "intervals": [row(i) for i in hits], "non_confirming": [row(i) for i in late]}
            if res.available and hits:
                evidence["overlapping_outage"] = True
    try:
        rows = store.events_in_window(host, UPS_KINDS, lo, hi + LOOKAHEAD_S)
    except Exception as exc:
        evidence["ups"] = {"available": False, "reason": f"UPS events could not be read ({type(exc).__name__})"}
    else:
        hits = [r for r in rows if lo <= r["ts"] <= hi]
        late = [r for r in rows if not lo <= r["ts"] <= hi]
        evidence["ups"] = {"available": True, "total": len(hits),
                           "events": [{"id": r["id"], "kind": r["kind"], "ts": r["ts"]} for r in hits[:MAX_UPS_EVENTS]],
                           "non_confirming": [{"id": r["id"], "kind": r["kind"], "ts": r["ts"]}
                                              for r in late[:MAX_UPS_EVENTS]]}
        if len(hits) > MAX_UPS_EVENTS:
            evidence["ups"]["incomplete"] = True
            evidence["ups"]["reason"] = f"only {MAX_UPS_EVENTS} of {len(hits)} UPS events are recorded"
        if hits:
            evidence["overlapping_outage"] = True
    return evidence


def _backoff_s(attempts: int) -> float:
    return min(RETRY_BASE_S * 2 ** max(attempts - 1, 0), RETRY_CAP_S)


def assess_boot_event(store, witness, host: str, event: dict, skew_s: float, retry_s: float = 0.0,
                      now: float | None = None, force: bool = False) -> str | None:
    """Apply the witness to one stored boot event. Returns "power_loss" when a power loss event
    was added, "noted" when evidence was recorded on the existing event, or None when nothing
    applied (not an eligible kind, already assessed, or no usable window). `force` assesses
    again even when an earlier assessment is recorded (a retry or a manual reassess)."""
    mode = eligible(event)
    if mode is None:
        return None
    stored = store.event_by_key(host, event["dedup_key"])
    if stored is None:
        return None
    previous = stored["detail"].get("power_witness")
    if previous is not None and not force:
        return None
    window = window_for(event, skew_s)
    if window is None:
        return None
    now = time.time() if now is None else now
    evidence = collect_evidence(store, witness, host, window[0], window[1], skew_s)
    outage = evidence["overlapping_outage"]
    if mode == "promote" and outage:
        evidence["outcome"] = "power_loss"
        detail = {**stored["detail"], "power_witness": evidence, "supersedes": stored["kind"],
                  "evidence": "a power witness shows an outage overlapping the unclean end of the previous boot",
                  "reason": "an outside witness confirmed the outage; see power_witness for each piece of evidence"}
        store.add_events(host, [{
            "kind": "boot." + boot.POWER_LOSS, "severity": boot.SEVERITY[boot.POWER_LOSS], "source": "boot",
            "ts": stored["ts"], "title": "Previous boot ended: power loss", "detail": detail,
            "dedup_key": f"{event['dedup_key']}:power_loss", "boot_id": stored["boot_id"]}])
        store.merge_event_detail(host, event["dedup_key"], {
            "power_witness": {**evidence, "superseded_by": "boot." + boot.POWER_LOSS}})
        return "power_loss"
    if mode == "note":
        evidence["outcome"] = (f"{stored['kind']} stays because it outranks power_loss" if outage
                               else f"{stored['kind']} stays; no overlapping outage")
    elif evidence["plug"]["available"] is not True or evidence["ups"]["available"] is not True:
        evidence["outcome"] = (f"{stored['kind']} stays; a witness was unavailable, "
                               "which is not evidence of no outage")
        evidence["incomplete"] = True
        if retry_s > 0:
            old = (previous or {}).get("retry") or {}
            first = old.get("first_attempt", now)
            attempts = int(old.get("attempts", 0)) + 1
            evidence["retry_pending"] = True
            evidence["retry"] = {"first_attempt": first, "attempts": attempts, "last_attempt": now,
                                 "next_attempt": now + _backoff_s(attempts), "expires_at": first + retry_s}
    else:
        evidence["outcome"] = f"{stored['kind']} stays; no overlapping outage was found"
        if evidence["ups"].get("incomplete"):
            evidence["incomplete"] = True
    store.merge_event_detail(host, event["dedup_key"], {"power_witness": evidence})
    return "noted"


def retry_pending(store, witness, skew_s: float, retry_s: float, now: float | None = None,
                  startup: bool = False) -> int:
    """Assess again every event whose last assessment was incomplete. An event is due when its
    backoff has passed, or at hub start. One past its retry period stops being retried and is
    marked so. Returns the number of events assessed."""
    now = time.time() if now is None else now
    done = 0
    for row in store.pending_witness_events():
        pw = row["detail"]["power_witness"]
        retry = pw.get("retry") or {}
        if now > float(retry.get("expires_at", 0)):
            store.merge_event_detail(row["host"], row["dedup_key"], {"power_witness": {
                **pw, "retry_pending": False, "retry_expired": True}})
            continue
        if not startup and now < float(retry.get("next_attempt", 0)):
            continue
        try:
            assess_boot_event(store, witness, row["host"], row, skew_s, retry_s, now, force=True)
            done += 1
        except Exception as exc:
            log.warning("power witness retry failed (%s)", type(exc).__name__)
    return done


def assess_batch_events(store, witness, host: str, events: list[dict], skew_s: float,
                        retry_s: float = 0.0) -> None:
    for ev in events:
        try:
            assess_boot_event(store, witness, host, ev, skew_s, retry_s)
        except Exception as exc:
            log.warning("power witness assessment failed (%s)", type(exc).__name__)


WALL_SOURCE = "wall"
WALL_METRIC = "wall_watts"


def read_wall_power(store, witness, host: str, now: float | None = None) -> bool:
    """Read the host's power entity and store it as a `wall_watts` sample. Returns True when a
    sample was stored. A host without a power entity stores nothing. A reading that cannot be
    made is stored as an unavailable sample (value NULL) whose labels carry the reason, so the
    summary reports it unavailable and never as zero. Never raises."""
    if witness is None or not getattr(witness, "configured", False):
        return False
    try:
        reading = witness.read_power(host)
        if reading is None:
            return False
        labels = {"entity": reading.entity_id}
        if reading.watts is None:
            labels["reason"] = reading.reason[:200]
        store.add_sample(host, WALL_SOURCE, WALL_METRIC, reading.watts, "W", labels,
                         time.time() if now is None else now)
        return True
    except Exception as exc:
        log.warning("wall power read failed (%s)", type(exc).__name__)
        return False
