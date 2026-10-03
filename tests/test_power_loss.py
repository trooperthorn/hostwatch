"""Witness-confirmed power loss: the hub applies plug and UPS evidence to unclean boot events."""

from __future__ import annotations

import time

import httpx
from fastapi.testclient import TestClient

from hostwatch.config import Config
from hostwatch.events import boot
from hostwatch.hub import create_app
from hostwatch.integrations.summary import build_host_summary
from hostwatch.schema import Batch, Event
from hostwatch.store import Store
from hostwatch.witness import homeassistant as ha
from hostwatch.witness.homeassistant import HomeAssistantWitness

TOKEN = "t" * 64
ENTITY = "switch.rack_plug"
BOOT_ID = "bbbbbbbb-0000-0000-0000-000000000002"
HB = 1_700_000_000.0          # previous heartbeat
DETECTED = HB + 300.0         # the agent noticed the new boot


def make(tmp_path, handler=None, skew=120.0, configured=True):
    cfg = Config(ingest_token=TOKEN, data_dir=tmp_path, witness_skew_s=skew)
    store = Store(tmp_path / "db.sqlite")
    witness = None
    if configured:
        tok = tmp_path / "token"
        tok.write_text("SECRET\n", encoding="utf-8")
        witness = HomeAssistantWitness("https://ha.example:8123", str(tok), {"h1": ENTITY},
                                       transport=httpx.MockTransport(handler or (lambda r: httpx.Response(500))))
    return TestClient(create_app(cfg, store, power_witness=witness)), store


def plug(*states):
    """History handler: states are (epoch, state) pairs."""
    def handler(req):
        first = {"entity_id": ENTITY, "state": states[0][1], "last_changed": ha._iso(states[0][0])}
        rest = [{"state": s, "last_changed": ha._iso(t)} for t, s in states[1:]]
        return httpx.Response(200, json=[[first, *rest]])
    return handler


def boot_event(kind=boot.UNKNOWN_UNCLEAN, hints=None):
    detail = {"boot_id": BOOT_ID, "previous_boot_id": "aaaaaaaa-0000-0000-0000-000000000001",
              "heartbeat_ts": HB, "detected_at": DETECTED, "journal_hints": hints or {"abrupt_end": True}}
    return Event(kind="boot." + kind, severity=boot.SEVERITY[kind], source="boot", ts=HB, title="t",
                 detail=detail, dedup_key=f"boot:{BOOT_ID}", boot_id=BOOT_ID)


def post(client, *events):
    b = Batch(agent_version="t", host="h1", platform="x86", sent_at=DETECTED, sources=[], samples=[], events=list(events))
    r = client.post("/internal/v1/ingest", content=b.model_dump_json(),
                    headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    assert r.status_code == 200
    return r


def kinds(store):
    return sorted(e["kind"] for e in store.events(host="h1"))


def original(store):
    return store.event_by_key("h1", f"boot:{BOOT_ID}")


def test_overlapping_plug_outage_gives_power_loss_with_evidence(tmp_path):
    client, store = make(tmp_path, plug((HB - 1000, "on"), (HB + 60, "unavailable"), (DETECTED - 30, "on")))
    post(client, boot_event())
    assert kinds(store) == ["boot.power_loss", "boot.unknown_unclean"]
    pl = store.event_by_key("h1", f"boot:{BOOT_ID}:power_loss")
    assert pl["severity"] == "critical" and pl["boot_id"] == BOOT_ID and pl["ts"] == HB
    w = pl["detail"]["power_witness"]
    assert w["skew_s"] == 120.0 and w["window_start"] == HB - 120 and w["window_end"] == DETECTED + 120
    assert w["plug"]["entity_id"] == ENTITY
    assert [(i["start"], i["state"]) for i in w["plug"]["intervals"]] == [(HB + 60, "unavailable")]
    assert pl["detail"]["supersedes"] == "boot.unknown_unclean"
    assert pl["detail"]["journal_hints"] == {"abrupt_end": True}
    assert original(store)["detail"]["power_witness"]["superseded_by"] == "boot.power_loss"


def test_resent_event_adds_no_second_power_loss(tmp_path):
    client, store = make(tmp_path, plug((HB - 1000, "on"), (HB + 60, "off"), (HB + 200, "on")))
    post(client, boot_event())
    post(client, boot_event())
    assert kinds(store).count("boot.power_loss") == 1


def test_non_overlapping_outage_keeps_unknown_unclean(tmp_path):
    client, store = make(tmp_path, plug((HB - 5000, "on"), (HB - 4000, "unavailable"), (HB - 3000, "on")))
    post(client, boot_event())
    assert kinds(store) == ["boot.unknown_unclean"]
    w = original(store)["detail"]["power_witness"]
    assert w["plug"]["available"] is True and w["plug"]["intervals"] == []
    assert "no overlapping outage" in w["outcome"]


def test_witness_unavailable_keeps_unknown_unclean_with_reason(tmp_path):
    client, store = make(tmp_path, lambda r: httpx.Response(401))
    post(client, boot_event())
    assert kinds(store) == ["boot.unknown_unclean"]
    w = original(store)["detail"]["power_witness"]
    assert w["plug"]["available"] is False and "refused the token" in w["plug"]["reason"]
    assert "not evidence of no outage" in w["outcome"]


def test_witness_not_configured_is_recorded(tmp_path):
    client, store = make(tmp_path, configured=False)
    post(client, boot_event())
    assert kinds(store) == ["boot.unknown_unclean"]
    assert "no Home Assistant power witness" in original(store)["detail"]["power_witness"]["plug"]["reason"]


def test_pstore_panic_with_outage_stays_kernel_panic_and_notes_it(tmp_path):
    client, store = make(tmp_path, plug((HB - 1000, "on"), (HB + 60, "unavailable"), (DETECTED, "on")))
    post(client, boot_event(boot.KERNEL_PANIC, hints={"x": False}))
    assert kinds(store) == ["boot.kernel_panic"]
    w = original(store)["detail"]["power_witness"]
    assert w["overlapping_outage"] is True and "outranks power_loss" in w["outcome"]


def ups_event(ts):
    return {"kind": "ups.on_battery", "severity": "warning", "source": "thresholds", "ts": ts,
            "title": "UPS is running on battery", "detail": {}, "dedup_key": "ups|1", "boot_id": None}


def test_ups_on_battery_in_window_gives_power_loss(tmp_path):
    client, store = make(tmp_path, configured=False)
    store.add_events("h1", [ups_event(HB + 20)])
    post(client, boot_event())
    assert kinds(store) == ["boot.power_loss", "boot.unknown_unclean", "ups.on_battery"]
    ups = store.event_by_key("h1", f"boot:{BOOT_ID}:power_loss")["detail"]["power_witness"]["ups"]
    assert [e["kind"] for e in ups["events"]] == ["ups.on_battery"]


def test_ups_event_outside_window_does_not_count(tmp_path):
    client, store = make(tmp_path, configured=False)
    store.add_events("h1", [ups_event(HB - 5000)])
    post(client, boot_event())
    assert kinds(store) == ["boot.unknown_unclean", "ups.on_battery"]


def test_clock_skew_within_allowance_still_matches(tmp_path):
    # The plug went down 100 s after the boot was noticed (plug clock ahead): inside the 120 s allowance.
    client, store = make(tmp_path, plug((HB - 1000, "on"), (DETECTED + 100, "unavailable")))
    post(client, boot_event())
    assert "boot.power_loss" in kinds(store)


def test_outage_beyond_allowance_does_not_match(tmp_path):
    client, store = make(tmp_path, plug((HB - 1000, "on"), (DETECTED + 500, "unavailable")))
    post(client, boot_event())
    assert kinds(store) == ["boot.unknown_unclean"]


def test_power_loss_is_critical_while_held_and_replaces_unknown_unclean(tmp_path):
    client, store = make(tmp_path, plug((HB - 1000, "on"), (HB + 60, "unavailable"), (DETECTED, "on")))
    now = time.time()
    post(client, boot_event())
    with store._lock, store._db:
        store._db.execute("UPDATE events SET ts = ?", (now - 10,))
    s = build_host_summary(store, "h1", now)
    assert [c["kind"] for c in s.crashes] == ["power_loss"] and s.overall_status == 2
    pl = [r for r in store.events(host="h1") if r["kind"] == "boot.power_loss"][0]
    assert store.ack_event(pl["id"], "tester")
    assert build_host_summary(store, "h1", now).crashes == []


def test_skew_default_and_override(monkeypatch):
    assert Config(ingest_token="x" * 32).witness_skew_s == 120.0
    monkeypatch.setenv("HOSTWATCH_WITNESS_SKEW_S", "30")
    assert Config(ingest_token="x" * 32).witness_skew_s == 30.0
