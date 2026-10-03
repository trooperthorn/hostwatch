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

A fresh pstore panic (`boot.kernel_panic`) and a watchdog reset (`boot.watchdog_reset`) outrank
a power loss. For those the outage is only noted under `detail.power_witness`.
"""

from __future__ import annotations

import logging
from typing import Any

from ..events import boot
from ..events.thresholds import SOURCE as THRESHOLD_SOURCE

log = logging.getLogger("hostwatch.power")

UPS_KINDS = ("ups.on_battery", "ups.low_battery")
NOTE_ONLY_KINDS = ("boot." + boot.KERNEL_PANIC, "boot." + boot.WATCHDOG_RESET)
MAX_UPS_EVENTS = 50


def _num(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def eligible(event: dict) -> str | None:
    """"promote", "note" or None for a boot event dict from a batch."""
    kind = event.get("kind")
    detail = event.get("detail") or {}
    if kind == "boot." + boot.UNKNOWN_UNCLEAN:
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


def collect_evidence(store, witness, host: str, lo: float, hi: float, skew_s: float) -> dict[str, Any]:
    """Ask every witness about [lo, hi]. The result never raises."""
    evidence: dict[str, Any] = {"window_start": lo, "window_end": hi, "skew_s": skew_s,
                                "overlapping_outage": False}
    if witness is None or not getattr(witness, "configured", False):
        evidence["plug"] = {"available": False, "reason": "no Home Assistant power witness is configured"}
    else:
        res = None
        try:
            res = witness.outages(host, lo, hi)
        except Exception as exc:  # a witness fault must never lose the boot event
            evidence["plug"] = {"available": False, "reason": f"the witness failed ({type(exc).__name__})"}
        if res is not None:
            hits = [i for i in res.intervals if i.start <= hi and i.end >= lo]
            evidence["plug"] = {
                "available": res.available, "reason": res.reason, "entity_id": res.entity_id,
                "intervals": [{"start": i.start, "end": i.end, "state": i.state, "open_ended": i.open_ended}
                              for i in hits]}
            if res.available and hits:
                evidence["overlapping_outage"] = True
    try:
        rows = store.events(host=host, since=lo, source=THRESHOLD_SOURCE, limit=1000)
    except Exception as exc:
        evidence["ups"] = {"available": False, "reason": f"UPS events could not be read ({type(exc).__name__})"}
    else:
        hits = sorted((r for r in rows if r["kind"] in UPS_KINDS and lo <= r["ts"] <= hi), key=lambda r: r["ts"])
        evidence["ups"] = {"available": True, "events": [
            {"id": r["id"], "kind": r["kind"], "ts": r["ts"]} for r in hits[:MAX_UPS_EVENTS]]}
        if hits:
            evidence["overlapping_outage"] = True
    return evidence


def assess_boot_event(store, witness, host: str, event: dict, skew_s: float) -> str | None:
    """Apply the witness to one stored boot event. Returns "power_loss" when a power loss event
    was added, "noted" when evidence was recorded on the existing event, or None when nothing
    applied (not an eligible kind, already assessed, or no usable window)."""
    mode = eligible(event)
    if mode is None:
        return None
    stored = store.event_by_key(host, event["dedup_key"])
    if stored is None or "power_witness" in stored["detail"]:
        return None
    window = window_for(event, skew_s)
    if window is None:
        return None
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
    else:
        evidence["outcome"] = f"{stored['kind']} stays; no overlapping outage was found"
    store.merge_event_detail(host, event["dedup_key"], {"power_witness": evidence})
    return "noted"


def assess_batch_events(store, witness, host: str, events: list[dict], skew_s: float) -> None:
    for ev in events:
        try:
            assess_boot_event(store, witness, host, ev, skew_s)
        except Exception as exc:
            log.warning("power witness assessment failed (%s)", type(exc).__name__)
