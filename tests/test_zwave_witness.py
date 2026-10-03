"""Z-Wave plug witness (node status entities, several entities per host) and wall power reading.

Home Assistant is a mocked httpx transport. Nothing here contacts a real host.
"""

from __future__ import annotations

import time

import httpx
from fastapi.testclient import TestClient
from test_orion import H, cfg, key, seed
from test_power_loss import BOOT_ID, DETECTED, HB, TOKEN, boot_event, kinds, post

from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.integrations import homeassistant as ha_out
from hostwatch.integrations import orion as orion_doc
from hostwatch.integrations import prometheus as prom
from hostwatch.integrations.summary import build_host_summary
from hostwatch.store import Store
from hostwatch.witness import homeassistant as ha
from hostwatch.witness.homeassistant import HomeAssistantWitness, parse_entities, parse_power_witness
from hostwatch.witness.power import read_wall_power

NODE = "sensor.plug_node_status"
SWITCH = "switch.rack_plug"
WATTS = "sensor.plug_electric_consumption_power"


def series(entity, *states):
    first = {"entity_id": entity, "state": states[0][1], "last_changed": ha._iso(states[0][0])}
    rest = [{"state": s, "last_changed": ha._iso(t)} for t, s in states[1:]]
    return [[first, *rest]]


def router(histories=None, states=None):
    """History requests answer by filter_entity_id, state requests by path."""
    def handler(req):
        if req.url.path.startswith("/api/history/period/"):
            eid = req.url.params["filter_entity_id"]
            if histories is None or eid not in histories:
                return httpx.Response(200, json=[])
            return httpx.Response(200, json=histories[eid])
        eid = req.url.path.rsplit("/", 1)[1]
        if states is None or eid not in states:
            return httpx.Response(404)
        return httpx.Response(200, json=states[eid])
    return handler


def make_witness(tmp_path, spec, handler):
    tok = tmp_path / "token"
    tok.write_text("SECRET\n", encoding="utf-8")
    return HomeAssistantWitness("https://ha.example:8123", str(tok), {"h1": spec},
                                transport=httpx.MockTransport(handler))


def make_hub(tmp_path, spec, handler):
    config = Config(ingest_token=TOKEN, data_dir=tmp_path)
    store = Store(tmp_path / "db.sqlite")
    witness = make_witness(tmp_path, spec, handler)
    return TestClient(create_app(config, store, power_witness=witness)), store


# --- parsing --------------------------------------------------------------------------------------

def test_several_entities_and_roles_are_parsed():
    assert parse_power_witness("h1=switch.a|sensor.b_node_status , h2=switch.c") == {
        "h1": "switch.a|sensor.b_node_status", "h2": "switch.c"}
    got = [(e.role, e.entity_id) for e in parse_entities(
        f"{SWITCH}|{NODE}|{WATTS}|node_status:sensor.odd_name|power:sensor.meter|bogus:x.y|")]
    assert got == [("switch", SWITCH), ("node_status", NODE), ("power", WATTS),
                   ("node_status", "sensor.odd_name"), ("power", "sensor.meter")]


# --- node status as outage evidence ----------------------------------------------------------------

def test_node_status_alive_dead_alive_confirms_power_loss(tmp_path):
    hist = {NODE: series(NODE, (HB - 1000, "alive"), (HB + 60, "dead"), (DETECTED - 30, "alive"))}
    client, store = make_hub(tmp_path, NODE, router(hist))
    post(client, boot_event())
    assert kinds(store) == ["boot.power_loss", "boot.unknown_unclean"]
    plug = store.event_by_key("h1", f"boot:{BOOT_ID}:power_loss")["detail"]["power_witness"]["plug"]
    assert [(i["state"], i["entity_id"]) for i in plug["intervals"]] == [("dead", NODE)]


def test_node_status_asleep_and_awake_are_not_an_outage(tmp_path):
    hist = {NODE: series(NODE, (HB - 1000, "alive"), (HB + 60, "asleep"), (HB + 120, "awake"),
                         (HB + 180, "alive"))}
    client, store = make_hub(tmp_path, NODE, router(hist))
    post(client, boot_event())
    assert kinds(store) == ["boot.unknown_unclean"]
    plug = store.event_by_key("h1", f"boot:{BOOT_ID}")["detail"]["power_witness"]["plug"]
    assert plug["available"] is True and plug["intervals"] == []


def test_node_status_unavailable_counts_but_off_does_not():
    states = series(NODE, (0, "alive"), (100, "off"), (200, "unavailable"), (300, "unknown"), (400, "alive"))
    got = ha.intervals_from_history(states[0], 0, 1000, ha.NODE_STATUS_OUTAGE_STATES)
    assert [(i.state, i.start, i.end) for i in got] == [("unavailable", 200, 300), ("unknown", 300, 400)]


def test_two_entities_for_one_host_combine_their_evidence(tmp_path):
    # The switch stayed on (a smart plug that kept reporting), only the node status shows the cut.
    hist = {SWITCH: series(SWITCH, (HB - 1000, "on")),
            NODE: series(NODE, (HB - 1000, "alive"), (HB + 60, "dead"), (DETECTED - 30, "alive"))}
    client, store = make_hub(tmp_path, f"{SWITCH}|{NODE}", router(hist))
    post(client, boot_event())
    assert kinds(store) == ["boot.power_loss", "boot.unknown_unclean"]
    plug = store.event_by_key("h1", f"boot:{BOOT_ID}:power_loss")["detail"]["power_witness"]["plug"]
    assert plug["entity_id"] == f"{SWITCH}, {NODE}"

    # Evidence from both entities appears together.
    hist2 = {SWITCH: series(SWITCH, (HB - 1000, "on"), (HB + 70, "unavailable"), (HB + 90, "on")),
             NODE: series(NODE, (HB - 1000, "alive"), (HB + 60, "dead"), (DETECTED - 30, "alive"))}
    res = make_witness(tmp_path, f"{SWITCH}|{NODE}", router(hist2)).outages("h1", HB - 120, DETECTED + 120)
    assert res.available
    assert sorted((i.entity_id, i.state) for i in res.intervals) == [(NODE, "dead"), (SWITCH, "unavailable")]


def test_one_unreadable_entity_does_not_hide_the_other_or_count_as_no_outage(tmp_path):
    hist = {NODE: series(NODE, (HB - 1000, "alive"), (HB + 60, "dead"), (DETECTED - 30, "alive"))}
    # The switch has no history at all (missing entity); the node status still gives evidence.
    res = make_witness(tmp_path, f"{SWITCH}|{NODE}", router(hist)).outages("h1", HB - 120, DETECTED + 120)
    assert res.available and [i.state for i in res.intervals] == ["dead"]
    assert SWITCH in res.reason

    # When every entity fails the witness is unavailable, never an empty answer.
    res = make_witness(tmp_path, f"{SWITCH}|{NODE}", router({})).outages("h1", HB - 120, DETECTED + 120)
    assert not res.available and res.intervals == []


def test_a_power_only_host_has_no_outage_witness(tmp_path):
    res = make_witness(tmp_path, WATTS, router()).outages("h1", HB, DETECTED)
    assert not res.available and "no power witness entity" in res.reason


# --- wall power ---------------------------------------------------------------------------------------

def power_state(state, unit="W"):
    return {"entity_id": WATTS, "state": state, "attributes": {"unit_of_measurement": unit}}


def summary_for(tmp_path, spec, states):
    store = Store(tmp_path / "db.sqlite")
    seed(store)
    witness = make_witness(tmp_path, spec, router(states=states))
    read_wall_power(store, witness, H)
    return store, build_host_summary(store, H, time.time())


def test_power_entity_value_is_wall_watts_in_summary_orion_prometheus_and_home_assistant(tmp_path):
    spec = f"{NODE}|{WATTS}"
    # The host name used by the seeded samples is h1, the same as the mapping.
    _, s = summary_for(tmp_path, spec, {WATTS: power_state("42.5")})
    assert s.wall_power.value == 42.5 and s.wall_power.status == 0
    assert s.package_power.value == 20.0
    doc = orion_doc.summary_document(s)
    assert doc["wall_power_w"] == 42.5 and doc["package_power_w"] == 20.0
    assert 'hostwatch_wall_power_watts{host="h1"} 42.5' in prom.render([s])
    wall = [e for e in ha_out.build_entities(s) if e.key == "wall_power"]
    assert len(wall) == 1 and wall[0].state == "42.5"


def test_kilowatts_are_converted(tmp_path):
    _, s = summary_for(tmp_path, WATTS, {WATTS: power_state("0.05", "kW")})
    assert s.wall_power.value == 50.0


def test_unavailable_power_entity_is_unavailable_not_zero(tmp_path):
    store, s = summary_for(tmp_path, WATTS, {WATTS: power_state("unavailable")})
    assert s.wall_power is not None and s.wall_power.value is None and s.wall_power.status is None
    assert "unavailable" in s.wall_power.reason
    doc = orion_doc.summary_document(s)
    assert "wall_power_w" not in doc and doc["wall_power_available"] == 0 and doc["wall_power_reason"]
    assert "hostwatch_wall_power_watts" not in prom.render([s])
    wall = [e for e in ha_out.build_entities(s) if e.key == "wall_power"]
    assert wall[0].state is None
    # The stored sample is a NULL value, not 0.0.
    rows = [r for r in store.latest(H) if r["source"] == "wall"]
    assert len(rows) == 1 and rows[0]["value"] is None


def test_bad_values_and_errors_are_unavailable(tmp_path):
    for n, bad in enumerate((power_state("abc"), power_state("-3"), power_state("5", "V"))):
        folder = tmp_path / f"case{n}"
        folder.mkdir()
        _, s = summary_for(folder, WATTS, {WATTS: bad})
        assert s.wall_power.value is None
    w = make_witness(tmp_path, WATTS, lambda r: httpx.Response(401))
    assert w.read_power("h1").watts is None
    w = make_witness(tmp_path, WATTS, router(states={}))
    assert "does not know" in w.read_power("h1").reason


def test_host_without_a_power_entity_has_no_wall_power(tmp_path):
    _, s = summary_for(tmp_path, NODE, {})
    assert s.wall_power is None
    assert "wall_power_w" not in orion_doc.summary_document(s)


def test_a_reading_is_reused_within_the_minimum_interval(tmp_path):
    calls = []

    def handler(req):
        calls.append(req.url.path)
        return httpx.Response(200, json=power_state("10"))

    clock = [100.0]
    w = make_witness(tmp_path, WATTS, handler)
    w._clock = lambda: clock[0]
    w.read_power("h1")
    w.read_power("h1")
    assert len(calls) == 1
    clock[0] += ha.POWER_MIN_INTERVAL_S + 1
    w.read_power("h1")
    assert len(calls) == 2


def test_hub_endpoints_read_the_power_entity_on_each_summary_build(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    seed(store)
    witness = make_witness(tmp_path, WATTS, router(states={WATTS: power_state("33")}))
    client = TestClient(create_app(cfg(tmp_path), store, power_witness=witness))
    headers = key(store, "read:metrics")
    doc = client.get("/api/v1/orion/hosts/h1/power", headers=headers).json()
    assert doc["wall_power_w"] == 33.0
    ui = client.get("/api/v1/ui/status", headers=headers).json()
    assert ui["hosts"][0]["wall_power"]["value"] == 33.0
