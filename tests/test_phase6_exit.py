"""Phase 6 exit criteria: a simulated outage logs on-battery, and a post-outage boot with plug
witness evidence is classified as confirmed power loss.

The outage is simulated with a fake upsd bound to 127.0.0.1 and a mocked Home Assistant transport.
A real UPS pull and a real plug pull are owner checks recorded in UNVERIFIED.md.
"""

from __future__ import annotations

from test_nut import FULL, FakeUpsd, collector, listing
from test_power_loss import BOOT_ID, DETECTED, HB, boot_event, kinds, make, plug, post

from hostwatch.events.thresholds import ThresholdEngine
from hostwatch.schema import Batch


def test_simulated_ups_outage_logs_on_battery_then_back_on_line():
    srv = FakeUpsd([listing("OL", FULL), listing("OB", FULL), listing("OL", FULL)])
    try:
        nut = collector(srv.port)
        engine = ThresholdEngine()
        assert engine.evaluate(nut.collect(), [], now=HB) == []
        on_battery = engine.evaluate(nut.collect(), [], now=HB + 20)
        assert [(e.kind, e.severity) for e in on_battery] == [("ups.on_battery", "warning")]
        back = engine.evaluate(nut.collect(), [], now=HB + 200)
        assert [e.kind for e in back] == ["ups.on_line"]
    finally:
        srv.close()


def test_post_outage_boot_with_plug_witness_is_power_loss_through_the_hub(tmp_path):
    client, store = make(tmp_path, plug((HB - 1000, "on"), (HB + 60, "unavailable"), (DETECTED - 30, "on")))

    # The agent side: the UPS goes on battery and the event is delivered to the hub.
    srv = FakeUpsd([listing("OL", FULL), listing("OB", FULL)])
    try:
        nut = collector(srv.port)
        engine = ThresholdEngine()
        engine.evaluate(nut.collect(), [], now=HB - 30)
        events = engine.evaluate(nut.collect(), [], now=HB + 10)
    finally:
        srv.close()
    assert [e.kind for e in events] == ["ups.on_battery"]
    batch = Batch(agent_version="t", host="h1", platform="x86", sent_at=HB + 10, sources=[], samples=[],
                  events=events)
    r = client.post("/internal/v1/ingest", content=batch.model_dump_json(),
                    headers={"Authorization": "Bearer " + "t" * 64, "Content-Type": "application/json"})
    assert r.status_code == 200
    assert kinds(store) == ["ups.on_battery"]

    # The host comes back after the outage and the agent reports an abrupt end.
    post(client, boot_event())
    assert kinds(store) == ["boot.power_loss", "boot.unknown_unclean", "ups.on_battery"]
    pl = store.event_by_key("h1", f"boot:{BOOT_ID}:power_loss")
    assert pl["severity"] == "critical" and pl["boot_id"] == BOOT_ID
    w = pl["detail"]["power_witness"]
    assert [i["state"] for i in w["plug"]["intervals"]] == ["unavailable"]
    assert [e["kind"] for e in w["ups"]["events"]] == ["ups.on_battery"]
    assert pl["detail"]["supersedes"] == "boot.unknown_unclean"


def test_without_a_witness_the_boot_stays_unknown_unclean(tmp_path):
    client, store = make(tmp_path, configured=False)
    post(client, boot_event())
    assert kinds(store) == ["boot.unknown_unclean"]
