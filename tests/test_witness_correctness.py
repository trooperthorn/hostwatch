"""Witness evidence rules, eligibility, retries and query bounds for power loss."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from hostwatch.__main__ import main
from hostwatch.config import Config
from hostwatch.events import boot
from hostwatch.hub import create_app
from hostwatch.schema import Batch, Event
from hostwatch.store import Store
from hostwatch.witness import homeassistant as ha
from hostwatch.witness import power
from hostwatch.witness.homeassistant import HomeAssistantWitness

TOKEN = "t" * 64
ENTITY = "switch.rack_plug"
BOOT_ID = "bbbbbbbb-0000-0000-0000-000000000002"
HB = 1_700_000_000.0
DETECTED = HB + 300.0
SKEW = 120.0
RETRY_S = 86400.0


def witness_for(tmp_path, handler):
    tok = tmp_path / "token"
    tok.write_text("SECRET\n", encoding="utf-8")
    return HomeAssistantWitness("https://ha.example:8123", str(tok), {"h1": ENTITY},
                                transport=httpx.MockTransport(handler))


def plug(*states):
    def handler(req):
        first = {"entity_id": ENTITY, "state": states[0][1], "last_changed": ha._iso(states[0][0])}
        rest = [{"state": s, "last_changed": ha._iso(t)} for t, s in states[1:]]
        return httpx.Response(200, json=[[first, *rest]])
    return handler


def boot_event(kind=boot.UNKNOWN_UNCLEAN, hints=None):
    detail = {"boot_id": BOOT_ID, "heartbeat_ts": HB, "detected_at": DETECTED,
              "journal_hints": hints or {"abrupt_end": True}}
    return Event(kind="boot." + kind, severity=boot.SEVERITY[kind], source="boot", ts=HB, title="t",
                 detail=detail, dedup_key=f"boot:{BOOT_ID}", boot_id=BOOT_ID)


def stored_boot(store, kind=boot.UNKNOWN_UNCLEAN, hints=None):
    ev = boot_event(kind, hints)
    store.add_events("h1", [ev.model_dump()])
    return store.event_by_key("h1", ev.dedup_key)


def kinds(store):
    return sorted(e["kind"] for e in store.events(host="h1", limit=5000))


def assess(store, witness, row, now=DETECTED + 10, **kw):
    return power.assess_boot_event(store, witness, "h1", row, SKEW, RETRY_S, now, **kw)


def test_outage_starting_after_boot_does_not_confirm(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    row = stored_boot(store)
    w = witness_for(tmp_path, plug((HB - 1000, "on"), (DETECTED + SKEW + 60, "unavailable"),
                                   (DETECTED + 900, "on")))
    assert assess(store, w, row) == "noted"
    assert kinds(store) == ["boot.unknown_unclean"]
    plugev = store.event_by_key("h1", f"boot:{BOOT_ID}")["detail"]["power_witness"]["plug"]
    assert plugev["intervals"] == []
    assert [i["start"] for i in plugev["non_confirming"]] == [DETECTED + SKEW + 60]


def test_outage_spanning_heartbeat_to_boot_confirms(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    row = stored_boot(store)
    w = witness_for(tmp_path, plug((HB - 1000, "on"), (HB - 30, "unavailable"), (DETECTED + 30, "on")))
    assert assess(store, w, row) == "power_loss"
    assert "boot.power_loss" in kinds(store)


def test_boot_unknown_with_overlapping_outage_becomes_power_loss(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    row = stored_boot(store, boot.UNKNOWN, hints={})
    w = witness_for(tmp_path, plug((HB - 1000, "on"), (HB + 60, "off"), (DETECTED - 30, "on")))
    assert power.eligible(row) == "promote"
    assert assess(store, w, row) == "power_loss"
    pl = store.event_by_key("h1", f"boot:{BOOT_ID}:power_loss")
    assert pl["detail"]["supersedes"] == "boot.unknown"


def test_retry_after_home_assistant_was_unavailable_gives_power_loss(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    row = stored_boot(store)
    state = {"up": False}
    good = plug((HB - 1000, "on"), (HB + 60, "unavailable"), (DETECTED - 30, "on"))

    def handler(req):
        return good(req) if state["up"] else httpx.Response(503)

    w = witness_for(tmp_path, handler)
    now = DETECTED + 10
    assert assess(store, w, row, now=now) == "noted"
    pw = store.event_by_key("h1", f"boot:{BOOT_ID}")["detail"]["power_witness"]
    assert pw["retry_pending"] is True and pw["incomplete"] is True
    state["up"] = True
    # Before the backoff has passed nothing is asked.
    assert power.retry_pending(store, w, SKEW, RETRY_S, now + 1) == 0
    assert kinds(store) == ["boot.unknown_unclean"]
    # After the backoff the retry confirms the outage.
    assert power.retry_pending(store, w, SKEW, RETRY_S, now + power.RETRY_BASE_S + 1) == 1
    assert "boot.power_loss" in kinds(store)
    assert store.pending_witness_events() == []


def test_backoff_grows_and_retry_stops_after_the_period(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    row = stored_boot(store)
    w = witness_for(tmp_path, lambda r: httpx.Response(503))
    now = DETECTED + 10
    assess(store, w, row, now=now)
    first = store.event_by_key("h1", f"boot:{BOOT_ID}")["detail"]["power_witness"]["retry"]
    later = now + power.RETRY_BASE_S + 1
    assert power.retry_pending(store, w, SKEW, RETRY_S, later) == 1
    second = store.event_by_key("h1", f"boot:{BOOT_ID}")["detail"]["power_witness"]["retry"]
    assert second["attempts"] == 2 and second["first_attempt"] == first["first_attempt"]
    assert second["next_attempt"] - later == 2 * power.RETRY_BASE_S
    assert power.retry_pending(store, w, SKEW, RETRY_S, now + RETRY_S + 5) == 0
    pw = store.event_by_key("h1", f"boot:{BOOT_ID}")["detail"]["power_witness"]
    assert pw["retry_pending"] is False and pw["retry_expired"] is True
    assert store.pending_witness_events() == []


def test_retry_disabled_when_period_is_zero(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    row = stored_boot(store)
    w = witness_for(tmp_path, lambda r: httpx.Response(503))
    assert power.assess_boot_event(store, w, "h1", row, SKEW, 0.0, DETECTED) == "noted"
    assert store.pending_witness_events() == []


def test_hub_start_retries_pending_assessment(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    row = stored_boot(store)
    down = witness_for(tmp_path, lambda r: httpx.Response(503))
    long_period = 10 * 365 * 86400.0
    power.assess_boot_event(store, down, "h1", row, SKEW, long_period, DETECTED + 10)
    assert "boot.power_loss" not in kinds(store)
    up = witness_for(tmp_path, plug((HB - 1000, "on"), (HB + 60, "unavailable"), (DETECTED - 30, "on")))
    cfg = Config(ingest_token=TOKEN, data_dir=tmp_path, witness_skew_s=SKEW, witness_retry_s=long_period)
    app = create_app(cfg, store, power_witness=up)
    with TestClient(app) as client:
        client.portal.call(app.state.witness_startup_done.wait)
    assert "boot.power_loss" in kinds(store)


def ups_row(ts, kind="ups.on_battery", i=0):
    return {"kind": kind, "severity": "warning", "source": "thresholds", "ts": ts, "title": "t",
            "detail": {}, "dedup_key": f"ups|{kind}|{i}", "boot_id": None}


def test_many_newer_unrelated_events_do_not_hide_an_on_battery_event(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    store.add_events("h1", [ups_row(HB + 20)])
    store.add_events("h1", [{"kind": "ups.on_line", "severity": "info", "source": "thresholds",
                             "ts": DETECTED + 1000 + i, "title": "t", "detail": {},
                             "dedup_key": f"noise|{i}", "boot_id": None} for i in range(1500)])
    row = stored_boot(store)
    assert assess(store, None, row) == "power_loss"
    ups = store.event_by_key("h1", f"boot:{BOOT_ID}:power_loss")["detail"]["power_witness"]["ups"]
    assert [e["kind"] for e in ups["events"]] == ["ups.on_battery"]


def test_truncated_ups_record_is_reported_incomplete(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    store.add_events("h1", [ups_row(HB + i, i=i) for i in range(power.MAX_UPS_EVENTS + 5)])
    row = stored_boot(store)
    assess(store, None, row)
    ups = store.event_by_key("h1", f"boot:{BOOT_ID}:power_loss")["detail"]["power_witness"]["ups"]
    assert ups["total"] == power.MAX_UPS_EVENTS + 5 and ups["incomplete"] is True
    assert len(ups["events"]) == power.MAX_UPS_EVENTS


def test_cli_reassess_confirms_and_is_audited(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOSTWATCH_DATA_DIR", str(tmp_path))
    store = Store(tmp_path / "hostwatch.db")
    stored_boot(store)
    good = witness_for(tmp_path, plug((HB - 1000, "on"), (HB + 60, "unavailable"), (DETECTED - 30, "on")))
    monkeypatch.setattr(HomeAssistantWitness, "from_config", classmethod(lambda cls, cfg, transport=None: good))
    assert main(["boot", "reassess", "h1", BOOT_ID]) == 0
    assert "boot.power_loss" in kinds(Store(tmp_path / "hostwatch.db"))
    rows = Store(tmp_path / "hostwatch.db").audit_rows(limit=10, kind="cli")
    assert rows and rows[0]["path"] == "boot reassess" and rows[0]["status"] == 0
    assert main(["boot", "reassess", "h1", BOOT_ID]) == 1
    assert main(["boot", "reassess", "h1", "nope"]) == 1
    capsys.readouterr()
