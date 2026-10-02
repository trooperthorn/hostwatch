"""Optional Prometheus endpoint: off by default, scoped, valid exposition, no zero for unknown."""

from __future__ import annotations

import dataclasses
import re
import time

import pytest
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.integrations import prometheus
from hostwatch.integrations.summary import Component, HostSummary
from hostwatch.store import Store

from test_orion import H, cfg, key, seed

SAMPLE_RE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})? (\S+)$')
LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\\n]|\\.)*)"')


def parse(text: str):
    """Tiny strict parser for the text format; raises AssertionError on a malformed line."""
    assert text.endswith("\n")
    samples = []
    typed = set()
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            typed.add(line.split()[2])
            continue
        if line.startswith("# HELP "):
            continue
        m = SAMPLE_RE.match(line)
        assert m, f"malformed line: {line!r}"
        name, _, body, value = m.groups()
        labels = {}
        if body:
            consumed = ",".join(f'{k}="{v}"' for k, v in LABEL_RE.findall(body))
            assert consumed == body, f"malformed labels: {body!r}"
            labels = dict(LABEL_RE.findall(body))
        float(value)
        assert name in typed
        samples.append((name, labels, float(value)))
    return samples


def make(tmp_path, enabled):
    store = Store(tmp_path / "db.sqlite")
    c = cfg(tmp_path)
    c = dataclasses.replace(c, prometheus_enabled=enabled)
    return TestClient(create_app(c, store)), store


def test_disabled_by_default_is_404(tmp_path):
    assert Config().prometheus_enabled is False
    client, store = make(tmp_path, False)
    seed(store)
    assert client.get("/metrics").status_code == 404
    assert client.get("/metrics", headers=key(store, "read:metrics")).status_code == 404


def test_scopes_when_enabled(tmp_path):
    client, store = make(tmp_path, True)
    seed(store)
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers=key(store, "read:events")).status_code == 403
    r = client.get("/metrics", headers=key(store, "read:metrics"))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")


def test_output_parses_and_has_expected_samples(tmp_path):
    client, store = make(tmp_path, True)
    seed(store)
    samples = parse(client.get("/metrics", headers=key(store, "read:metrics")).text)
    by = {(n, tuple(sorted(l.items()))): v for n, l, v in samples}
    assert by[("hostwatch_cpu_utilization_percent", (("host", H),))] == 12.5
    assert by[("hostwatch_memory_used_percent", (("host", H),))] == 25.0
    assert by[("hostwatch_source_up", (("host", H), ("source", "cpu")))] == 1.0
    assert by[("hostwatch_host_status", (("host", H),))] == 0.0


def test_unavailable_value_has_no_sample_and_source_up_is_zero(tmp_path):
    client, store = make(tmp_path, True)
    seed(store, unavailable=("cpu",))
    samples = parse(client.get("/metrics", headers=key(store, "read:metrics")).text)
    assert not [s for s in samples if s[0] == "hostwatch_cpu_utilization_percent"]
    up = [s for s in samples if s[0] == "hostwatch_source_up" and s[1]["source"] == "cpu"]
    assert up and up[0][2] == 0.0
    assert [s for s in samples if s[0] == "hostwatch_memory_used_percent"]


def test_host_name_is_escaped():
    nasty = 'a"b\nc\\d'
    unknown = Component("x", None, "", "unknown", "no data")
    s = HostSummary(nasty, time.time(), Component("cpu", 5.0, "%", "ok"), unknown, unknown, [], [], [],
                    {"cpu": Component("source.cpu", 1.0, "", "ok")}, {}, [], None)
    text = prometheus.render([s])
    assert text.count("a" + chr(92) + '"b' + chr(92) + "nc" + chr(92) * 2 + "d") >= 1
    assert len(text.splitlines()) == len([ln for ln in text.split("\n") if ln]) 
    samples = parse(text)
    assert samples and all("\n" not in v for _, l, _ in samples for v in l.values())
