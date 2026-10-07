"""Shared helpers for agent tests: a one-shot collection view, a fake Observe and request decoding."""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field

import httpx

from hostwatch.agent import Agent
from hostwatch.model import Event, Sample, SourceStatus
from hostwatch.otlp import PROTOBUF
from otlp_decoder import decode


@dataclass
class Cycle:
    samples: list[Sample]
    sources: list[SourceStatus]
    events: list[Event] = field(default_factory=list)


def collect_once(agent: Agent) -> Cycle:
    """Every collector and every event source once, without queueing anything: the readings, the
    source statuses and the events a cycle would turn into requests. Pending boot events are taken
    out of their marker, as a real event cycle does."""
    samples = agent.collect_samples()
    events = agent.pending_events
    agent._stage_pending([])
    events.extend(agent._collect_events())
    agent._outbox_status()
    events.extend(agent.thresholds.evaluate(samples, agent.status.values()))
    return Cycle(samples, list(agent.status.values()), events)


def event(kind="md.degraded", key="k1", ts=1000.0, severity="critical", source="journal", **detail) -> Event:
    return Event(kind=kind, severity=severity, source=source, ts=ts, title=f"{kind} happened",
                 detail=detail, dedup_key=key)


def body_json(request: httpx.Request) -> dict:
    """The OTLP JSON shape of a request the agent sent, whatever its encoding."""
    raw = request.content
    if request.headers.get("content-encoding") == "gzip":
        raw = gzip.decompress(raw)
    if request.headers["content-type"] == PROTOBUF:
        return decode(raw, "metrics" if request.url.path == "/v1/metrics" else "logs")
    return json.loads(raw)


@dataclass
class FakeObserve:
    """An httpx transport that plays Observe. `config` is the agent-config answer (a dict), or an
    exception or status to fail with. `answers` is a list of statuses (or (status, headers, body))
    for ingest requests, consumed in order; the last one repeats."""

    config: object = field(default_factory=lambda: {"host": "h1", "intervals": {}})
    answers: list = field(default_factory=lambda: [200])
    calls: list[httpx.Request] = field(default_factory=list)
    posts: list[httpx.Request] = field(default_factory=list)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.url.path == "/internal/v1/agent-config":
            cfg = self.config
            if isinstance(cfg, Exception):
                raise cfg
            if isinstance(cfg, int):
                return httpx.Response(cfg)
            return httpx.Response(200, json=cfg)
        assert request.url.path in ("/v1/metrics", "/v1/logs"), request.url.path
        self.posts.append(request)
        i = min(len(self.posts) - 1, len(self.answers) - 1)
        answer = self.answers[i]
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, tuple):
            status, headers, content = answer
            return httpx.Response(status, headers=headers, content=content)
        return httpx.Response(answer)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def signals(self) -> list[str]:
        return [r.url.path for r in self.posts]


def event_cycle(agent: Agent, watch: bool = False) -> bool:
    """One guarded event read, as the loop runs it. Returns False when it failed."""
    return agent._guard("event read", lambda: agent.event_cycle(watch))


def request_json(req) -> dict:
    """The OTLP JSON shape of a queued request, whatever its encoding."""
    raw = gzip.decompress(req.body) if req.headers.get("Content-Encoding") == "gzip" else req.body
    if req.headers["Content-Type"] == PROTOBUF:
        return decode(raw, req.signal)
    return json.loads(raw)


def log_records(tree: dict) -> list[dict]:
    """Flat records of an OTLP logs tree: event name, time in seconds, source and dedup key."""
    out = []
    for rl in tree.get("resourceLogs", []):
        for sl in rl["scopeLogs"]:
            for rec in sl["logRecords"]:
                attrs = {}
                for kv in rec["attributes"]:
                    ((_, v),) = kv["value"].items()
                    attrs[kv["key"]] = v
                out.append({"event": attrs["event.name"], "ts": int(rec["timeUnixNano"]) / 1e9,
                            "source": attrs.get("observe.source"), "dedup_key": attrs.get("observe.dedup_key"),
                            "attrs": attrs, "scope": sl["scope"]["name"]})
    return out


def drain_logs(agent: Agent) -> list[dict]:
    """Take every queued request out of the outbox, as a delivery would, and return the log
    records the logs requests carried."""
    out = []
    while (req := agent.outbox.peek()) is not None:
        if req.signal == "logs":
            out.extend(log_records(request_json(req)))
        agent.outbox.ack(req.seq)
    return out
