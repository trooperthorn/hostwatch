"""Home Assistant smart plug witness tests, using mocked httpx transports only."""

from __future__ import annotations

import logging

import httpx
import pytest

from hostwatch.config import Config
from hostwatch.witness import homeassistant as ha
from hostwatch.witness.homeassistant import HomeAssistantWitness, parse_power_witness

TOKEN = "SECRET-LONG-LIVED-TOKEN-123"
ENTITY = "switch.rack_plug"
START = 1_700_000_000.0
END = START + 3600


def iso(offset):
    return ha._iso(START + offset)


def witness(tmp_path, handler, mapping=None):
    f = tmp_path / "token"
    f.write_text(TOKEN + "\n", encoding="utf-8")
    return HomeAssistantWitness("https://ha.example:8123/", str(f), mapping or {"srv": ENTITY},
                                transport=httpx.MockTransport(handler))


def history(states):
    first = {"entity_id": ENTITY, "state": states[0][1], "last_changed": states[0][0]}
    rest = [{"state": s, "last_changed": t} for t, s in states[1:]]
    return [[first, *rest]]


def test_unavailable_period_gives_one_interval(tmp_path):
    seen = {}

    def handler(req):
        seen["req"] = req
        return httpx.Response(200, json=history([
            (iso(-100), "on"), (iso(600), "unavailable"), (iso(1800), "on")]))

    res = witness(tmp_path, handler).outages("srv", START, END)
    assert res.available
    assert [(i.start, i.end, i.state) for i in res.intervals] == [(START + 600, START + 1800, "unavailable")]
    req = seen["req"]
    assert req.headers["Authorization"] == f"Bearer {TOKEN}"
    assert req.url.params["filter_entity_id"] == ENTITY
    assert req.url.path.startswith("/api/history/period/")


def test_off_and_unknown_count_on_does_not(tmp_path):
    def handler(req):
        return httpx.Response(200, json=history([
            (iso(0), "on"), (iso(100), "off"), (iso(200), "unknown"), (iso(300), "on")]))

    res = witness(tmp_path, handler).outages("srv", START, END)
    assert [(i.state, i.start, i.end) for i in res.intervals] == [
        ("off", START + 100, START + 200), ("unknown", START + 200, START + 300)]


def test_always_on_is_available_with_no_intervals(tmp_path):
    res = witness(tmp_path, lambda r: httpx.Response(200, json=history([(iso(-5), "on")]))).outages(
        "srv", START, END)
    assert res.available and res.intervals == []


def test_open_ended_outage_and_clipping_and_offsets(tmp_path):
    states = [("2023-11-14T16:00:00-05:00", "off")]  # 21:00 UTC, before the window start
    res = witness(tmp_path, lambda r: httpx.Response(200, json=history(states))).outages(
        "srv", START, END)
    (i,) = res.intervals
    assert i.start == START and i.end == END and i.open_ended
    assert ha._to_epoch("2023-11-14T22:13:20Z") == START
    assert ha._to_epoch("2023-11-14T22:13:20") == START


@pytest.mark.parametrize("code", [401, 403])
def test_refused_token_is_unavailable(tmp_path, code):
    res = witness(tmp_path, lambda r: httpx.Response(code)).outages("srv", START, END)
    assert not res.available and "token" in res.reason and res.intervals == []


def test_connection_error_is_unavailable_without_secret(tmp_path):
    def handler(req):
        raise httpx.ConnectError(f"boom {req.url} {req.headers['Authorization']}")

    res = witness(tmp_path, handler).outages("srv", START, END)
    assert not res.available and "unreachable" in res.reason
    assert TOKEN not in res.reason


@pytest.mark.parametrize("body", [[], [[]], {"message": "x"}, [[{"state": "on"}]], "text"])
def test_missing_entity_or_bad_shape_is_unavailable(tmp_path, body):
    res = witness(tmp_path, lambda r: httpx.Response(200, json=body)).outages("srv", START, END)
    assert not res.available and res.intervals == []


def test_unmapped_host_missing_token_file_and_server_error(tmp_path):
    w = witness(tmp_path, lambda r: httpx.Response(500))
    assert not w.outages("other", START, END).available
    assert "HTTP 500" in w.outages("srv", START, END).reason
    gone = HomeAssistantWitness("https://ha", str(tmp_path / "nope"), {"srv": ENTITY})
    assert not gone.outages("srv", START, END).available


def test_token_never_logged(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    w = witness(tmp_path, lambda r: httpx.Response(401))
    res = w.outages("srv", START, END)
    assert TOKEN not in res.reason
    assert all(TOKEN not in rec.getMessage() for rec in caplog.records)
    assert TOKEN not in repr(res) and TOKEN not in repr(w.__dict__)


def test_tls_verify_on_by_default(tmp_path, monkeypatch):
    kwargs = {}
    real = httpx.Client

    def spy(*a, **kw):
        kwargs.update(kw)
        return real(*a, **kw)

    monkeypatch.setattr(ha.httpx, "Client", spy)
    witness(tmp_path, lambda r: httpx.Response(401)).outages("srv", START, END)
    assert kwargs["verify"] is True


def test_config_and_mapping(monkeypatch):
    assert parse_power_witness("a=switch.x, b = switch.y;bad,=z") == {"a": "switch.x", "b": "switch.y"}
    monkeypatch.setenv("HOSTWATCH_HA_URL", "https://ha")
    monkeypatch.setenv("HOSTWATCH_HA_TOKEN_FILE", "/run/secrets/ha")
    monkeypatch.setenv("HOSTWATCH_POWER_WITNESS", "srv=switch.x")
    w = HomeAssistantWitness.from_config(Config())
    assert w.configured and w.mapping == {"srv": "switch.x"}
    monkeypatch.delenv("HOSTWATCH_HA_URL")
    assert not HomeAssistantWitness.from_config(Config()).configured
