"""Customise panel: every reorder builds a valid preferences payload, a hidden group never hides danger,
and reset restores the default order."""

from __future__ import annotations

from hostwatch.integrations.summary import GROUP_IDS

from tests.test_ui_views import build, login, seed, web

URL = "/api/v1/me/preferences"


def payload(order, hidden=()):
    """The body the panel's savePrefs builds: the view and, per group, only its id and visible flag."""
    return {"view": "expanded", "groups": [{"id": g, "visible": g not in hidden} for g in order]}


def test_every_single_move_builds_a_valid_payload(tmp_path):
    client, _ = build(tmp_path)
    csrf = login(client)
    for i in range(len(GROUP_IDS)):
        for to in (max(i - 1, 0), min(i + 1, len(GROUP_IDS) - 1)):
            order = list(GROUP_IDS)
            order.insert(to, order.pop(i))
            r = client.put(URL, json=payload(order, hidden={order[0]}), headers=csrf)
            assert r.status_code == 200, (i, to)
            got = client.get(URL).json()
            assert [g["id"] for g in got["groups"]] == order
            assert [g["visible"] for g in got["groups"]][0] is False


def test_reset_restores_the_default_order_and_visibility(tmp_path):
    client, _ = build(tmp_path)
    csrf = login(client)
    shuffled = list(reversed(GROUP_IDS))
    assert client.put(URL, json=payload(shuffled, hidden={"cpu"}), headers=csrf).status_code == 200
    default = client.get(URL).json()["default_groups"]
    assert default == list(GROUP_IDS)
    assert client.put(URL, json=payload(default), headers=csrf).status_code == 200
    got = client.get(URL).json()
    assert [g["id"] for g in got["groups"]] == list(GROUP_IDS)
    assert all(g["visible"] for g in got["groups"])


def test_hidden_critical_group_still_makes_the_host_critical(tmp_path):
    client, store = build(tmp_path)
    seed(store, "h1", degraded=1)
    csrf = login(client)
    before = client.get("/api/v1/hosts/summary/grouped").json()
    raid = next(g for g in before["hosts"][0]["groups"] if g["id"] == "raid")
    assert raid["status"] == "critical"
    order = list(GROUP_IDS)
    assert client.put(URL, json=payload(order, hidden={"raid"}), headers=csrf).status_code == 200
    after = client.get("/api/v1/hosts/summary/grouped").json()
    assert after["hosts"][0]["status_key"] == "critical"
    assert after["banner"]["status_key"] == "critical"
    assert after["hosts"][0]["status"] == before["hosts"][0]["status"]
    assert after["banner"]["text"] == before["banner"]["text"]
    js = web("app.js")
    assert "Hidden group needs attention" in js and "hiddenAttention" in js
    assert "hidden-attention" in web("app.css")
