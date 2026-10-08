"""Sending: only the OTLP paths, the encoding options, partial success, and what the code no longer has."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest
from agent_helpers import FakeObserve, body_json, event_cycle

from hostwatch import otlp, tiers
from hostwatch.agent import Agent
from hostwatch.config import Config
from test_outbox import make_cfg, requests_for

ROOT = Path(__file__).resolve().parent.parent


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        low, n = n & 0x7F, n >> 7
        out.append(low | (0x80 if n else 0))
        if not n:
            return bytes(out)


def partial_protobuf(rejected: int, message: str) -> bytes:
    text = message.encode()
    inner = (b"\x08" + varint(rejected) if rejected else b"") + (b"\x12" + varint(len(text)) + text if text else b"")
    return b"\x0a" + varint(len(inner)) + inner


PB = {"Content-Type": "application/x-protobuf"}
JS = {"Content-Type": "application/json"}


# -- the answer parser -------------------------------------------------------------------------

@pytest.mark.parametrize("body,ctype,signal,expected", [
    (b"", PB["Content-Type"], "metrics", (0, "")),
    (partial_protobuf(3, "bad name"), PB["Content-Type"], "metrics", (3, "bad name")),
    (partial_protobuf(0, "note only"), PB["Content-Type"], "logs", (0, "note only")),
    (partial_protobuf(7, ""), "application/x-protobuf; charset=x", "logs", (7, "")),
    (b"{}", JS["Content-Type"], "metrics", (0, "")),
    (b'{"partialSuccess": {"rejectedDataPoints": "4", "errorMessage": "x"}}', JS["Content-Type"], "metrics", (4, "x")),
    (b'{"partialSuccess": {"rejectedLogRecords": 2}}', JS["Content-Type"], "logs", (2, "")),
    (b'{"partialSuccess": {"rejectedLogRecords": 2}}', JS["Content-Type"], "metrics", (0, "")),
    (b'{"partialSuccess": {"rejectedDataPoints": "many"}}', JS["Content-Type"], "metrics", (0, "")),
    (b"\xff\xff\xff", PB["Content-Type"], "metrics", (0, "")),
    (b"not json", JS["Content-Type"], "metrics", (0, "")),
    (b"[1]", JS["Content-Type"], "metrics", (0, "")),
])
def test_the_partial_success_of_an_answer_is_read_from_either_encoding(body, ctype, signal, expected):
    assert otlp.parse_partial_success(body, ctype, signal) == expected


# -- partial success ---------------------------------------------------------------------------

@pytest.mark.parametrize("headers,body", [
    (PB, partial_protobuf(2, "2 points have a name that is too long")),
    (JS, b'{"partialSuccess": {"rejectedDataPoints": "2", "errorMessage": "2 points have a name that is too long"}}'),
])
def test_a_partial_success_is_acknowledged_counted_and_never_resent(tmp_path, caplog, headers, body):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(requests_for("e1", n_points=5), "e1")
    observe = FakeObserve(answers=[(200, headers, body)])
    with caplog.at_level(logging.WARNING, logger="hostwatch.agent"), observe.client() as client:
        agent.flush(client)
        agent.flush(client)
    assert len(observe.posts) == 1 and agent.outbox.depth() == 0 and agent.outbox.dead_letter_count() == 0
    assert agent.outbox.rejected_points_total() == 2 and agent.outbox.rejected_records_total() == 0
    assert any("rejected 2 item" in r.getMessage() and "name that is too long" in r.getMessage()
               for r in caplog.records)
    agent._outbox_status()
    assert "rejected 2 item" in agent.status["outbox"].reason
    assert agent.status["outbox"].available is True  # the rest was stored; this is not a delivery fault


def test_rejected_log_records_are_counted_apart_from_points(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(requests_for("e1", n_records=3), "e1")
    with FakeObserve(answers=[(200, PB, partial_protobuf(1, "no event name"))]).client() as client:
        agent.flush(client)
    assert agent.outbox.rejected_records_total() == 1 and agent.outbox.rejected_points_total() == 0


def test_a_clean_200_and_an_unreadable_200_body_both_acknowledge(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(requests_for("e1", n_points=1), "e1")
    agent.outbox.enqueue(requests_for("e2", n_points=1), "e2")
    with FakeObserve(answers=[(200, JS, b"{}"), (200, PB, b"\xff\xff")]).client() as client:
        agent.flush(client)
    assert agent.outbox.depth() == 0 and agent.outbox.rejected_points_total() == 0


def test_204_and_other_2xx_acknowledge_without_reading_a_body(tmp_path):
    agent = Agent(make_cfg(tmp_path))
    agent.outbox.enqueue(requests_for("e1", n_points=1), "e1")
    with FakeObserve(answers=[204]).client() as client:
        agent.flush(client)
    assert agent.outbox.depth() == 0


# -- what is sent ------------------------------------------------------------------------------

def run_once(tmp_path, **over):
    agent = Agent(make_cfg(tmp_path, **over))
    agent.detect()
    assert event_cycle(agent) is True
    assert agent._guard("poll", lambda: agent.run_tier(tiers.AVAILABILITY)) is True
    observe = FakeObserve()
    with observe.client() as client:
        agent.flush(client)
    return observe


def test_only_the_otlp_paths_are_posted_and_the_headers_are_the_contract(tmp_path):
    observe = run_once(tmp_path)
    assert observe.posts and set(observe.signals()) <= {"/v1/metrics", "/v1/logs"}
    for req in observe.posts:
        assert req.method == "POST"
        assert req.headers["content-type"] == "application/json"
        assert req.headers["content-encoding"] == "gzip"
        assert req.headers["authorization"] == "Bearer " + "k" * 24
        assert re.fullmatch(r"hw-[0-9a-f]{32}-[ml]\d+", req.headers["idempotency-key"])
        assert len(req.headers["idempotency-key"]) <= 128
        assert len(req.content) <= otlp.MAX_BODY_BYTES
    assert not [c for c in observe.calls if "ingest" in c.url.path]


def test_protobuf_and_uncompressed_output_are_options(tmp_path):
    observe = run_once(tmp_path, otlp_format="protobuf")
    assert observe.posts
    for req in observe.posts:
        assert req.headers["content-type"] == "application/x-protobuf"


def test_json_and_uncompressed_output_are_options(tmp_path):
    observe = run_once(tmp_path, otlp_format="json", otlp_gzip=False)
    for req in observe.posts:
        assert req.headers["content-type"] == "application/json"
        assert "content-encoding" not in req.headers
        assert "resourceMetrics" in body_json(req) or "resourceLogs" in body_json(req)


def test_every_request_names_the_host_the_key_is_bound_to(tmp_path):
    observe = run_once(tmp_path, host_name="Binding-Host")
    for req in observe.posts:
        tree = body_json(req)
        res = (tree.get("resourceMetrics") or tree["resourceLogs"])[0]["resource"]["attributes"]
        assert {"key": "host.name", "value": {"stringValue": "Binding-Host"}} in res


def test_the_agent_is_the_only_place_that_sends_and_it_uses_no_other_path():
    sources = {p: p.read_text(encoding="utf-8") for p in (ROOT / "hostwatch").rglob("*.py")
               if "control" not in p.parts}
    posts = [p for p, text in sources.items() if re.search(r"\.post\(", text)]
    assert [p.name for p in posts] == ["agent.py"]
    paths = set(re.findall(r'"(/(?:v1|internal)/[\w/\-]+)"', "\n".join(sources.values())))
    assert paths == {"/v1/metrics", "/v1/logs", "/internal/v1/agent-config"}


# -- the old batch format is gone --------------------------------------------------------------

OLD = re.compile(r"\bBatch\b|batch_id|/internal/v1/ingest|\bschema_version\b|\bSCHEMA_VERSION\b|"
                 r"hostwatch\.schema|from \.+schema import|ingest_batch|internal/v1/events")


def test_no_code_references_the_old_batch_schema():
    offenders = []
    for base in ("hostwatch", "tests", "deploy", "scripts", ".github"):
        for path in (ROOT / base).rglob("*"):
            if path.is_file() and path.suffix in {".py", ".yml", ".yaml", ".ps1", ".sh", ".toml", ".example"} \
                    and path != Path(__file__).resolve() and "__pycache__" not in path.parts:
                for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if OLD.search(line):
                        offenders.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()}")
    assert offenders == []


def test_the_old_modules_and_their_files_are_gone():
    for rel in ("hostwatch/schema.py", "hostwatch/hub.py", "hostwatch/store.py", "hostwatch/auth.py",
                "hostwatch/mtls.py", "hostwatch/web", "hostwatch/integrations", "hostwatch/witness"):
        assert not (ROOT / rel).exists(), rel


def test_the_hub_settings_are_gone_from_the_configuration():
    fields = set(Config.__dataclass_fields__)
    for name in ("role", "hub_url", "hub_bind", "hub_port", "ingest_token", "interval_s", "tls_cert",
                 "allowed_clients", "mqtt_host", "prometheus_enabled", "power_witness"):
        assert name not in fields, name


# -- TLS to Observe ----------------------------------------------------------------------------

def test_the_agent_verifies_the_certificate_of_an_https_observe(tmp_path, monkeypatch):
    """The client the loop builds keeps certificate verification on, and nothing in the agent code
    switches it off."""
    import httpx

    from hostwatch import agent as agent_module

    cfg = make_cfg(tmp_path, observe_url="https://observe.example")
    assert agent_module.observe_tls_verify(cfg) is True
    seen: dict = {}
    real = httpx.Client

    def spy(*args, **kwargs):
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(agent_module.httpx, "Client", spy)
    agent = Agent(cfg, platform="x86")
    agent.stop()  # the loop exits after building its client
    agent.run()
    assert seen.get("verify") is True
    # The TrueNAS client has its own, separate TLS setting for the local appliance; Observe's is not it.
    for rel in ("hostwatch/agent.py", "hostwatch/windows/service.py"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert not re.search(r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False", text), rel
