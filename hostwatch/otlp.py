"""OTLP request builder: metrics and logs as protobuf (default) or JSON, optionally gzip.

The encoder is hand written so the agent has no new runtime dependency. A request is first built
in the OTLP JSON shape (lowerCamelCase names, 64-bit integers as decimal strings) and the
protobuf form is written from the same tree with a small field table, so the two encodings
cannot drift apart. Nothing here touches the network or the clock.

Limits match what Observe accepts on POST /v1/metrics and /v1/logs: a body of at most 1 MiB as
sent, at most 4 MiB once inflated, an inflate ratio below 100, at most 5000 points or 500 log
records per request, 64 resource attributes, 32 attributes per point or record, keys of at most
128 characters and string values of at most 1024. A batch that does not fit is split into several
requests, each carrying the full resource. A point that Observe would refuse outright (a value
that is not finite, a name that is too long) is skipped and counted instead of failing its
whole request, because unavailable beats wrong.

The Idempotency-Key of each request is derived from the outbox entry id, the signal and the
position of the request in the split. The same entry therefore always yields the same keys and,
because the encoding is deterministic (sorted JSON, gzip with a zero timestamp), the same bodies.
Observe answers a replayed key with a 200 and stores nothing, and answers a key reused with a
different body with a 409, so replays must never change a body.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

from .otel_map import LogRecord, Point

PROTOBUF = "application/x-protobuf"
JSON = "application/json"
FORMATS = {"protobuf": PROTOBUF, "json": JSON}
METRICS_PATH = "/v1/metrics"
LOGS_PATH = "/v1/logs"

MAX_BODY_BYTES = 1_048_576
MAX_INFLATED_BYTES = 4 * 1024 * 1024
MAX_INFLATE_RATIO = 100
MIN_INFLATED_ALLOWANCE = 64 * 1024
MAX_POINTS = 5000
MAX_RECORDS = 500
MAX_RESOURCE_ATTRS = 64
MAX_POINT_ATTRS = 32
MAX_ATTR_KEY = 128
MAX_ATTR_VALUE = 1024
MAX_NAME = 128
MAX_UNIT = 32
MAX_IDEMPOTENCY_KEY = 128

CUMULATIVE = 2
INT64_MIN, INT64_MAX = -(1 << 63), (1 << 63) - 1

Attr = str | int | float | bool


class OtlpError(ValueError):
    """A request cannot be built within the limits."""


@dataclass(frozen=True)
class OtlpRequest:
    signal: str  # "metrics" or "logs"
    path: str
    headers: dict[str, str]
    body: bytes
    count: int  # points or log records in this request
    inflated_size: int


@dataclass(frozen=True)
class BuiltRequests:
    requests: list[OtlpRequest]
    skipped: int  # points or records left out because Observe would refuse them


# -- the JSON shape -------------------------------------------------------------------------

def _ns(ts: float) -> str:
    n = int(round(float(ts) * 1e9))
    return str(min(max(n, 0), INT64_MAX))


def _any_value(value: Attr) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        if INT64_MIN <= value <= INT64_MAX:
            return {"intValue": str(value)}
        return {"stringValue": str(value)[:MAX_ATTR_VALUE]}
    if isinstance(value, float):
        if math.isfinite(value):
            return {"doubleValue": value}
        return {"stringValue": repr(value)}
    return {"stringValue": str(value)[:MAX_ATTR_VALUE]}


def _attributes(attrs: dict[str, Attr], limit: int) -> list[dict[str, Any]]:
    """Attributes in insertion order. Keys that are empty or too long are dropped and any beyond
    the limit are cut, so one odd attribute never costs the whole point."""
    out: list[dict[str, Any]] = []
    for key, value in attrs.items():
        if not key or len(key) > MAX_ATTR_KEY:
            continue
        if len(out) >= limit:
            break
        out.append({"key": key, "value": _any_value(value)})
    return out


def _resource(resource: dict[str, Attr]) -> dict[str, Any]:
    if len(resource) > MAX_RESOURCE_ATTRS:
        raise OtlpError(f"more than {MAX_RESOURCE_ATTRS} resource attributes")
    if not resource.get("host.name"):
        raise OtlpError("the resource needs a host.name, which Observe binds to the ingest key")
    for key in resource:
        if not key or len(key) > MAX_ATTR_KEY:
            raise OtlpError(f"resource attribute key {key!r} is empty or longer than {MAX_ATTR_KEY}")
    return {"attributes": [{"key": k, "value": _any_value(v)} for k, v in resource.items()]}


def _point_ok(p: Point) -> bool:
    return (isinstance(p.value, (int, float)) and not isinstance(p.value, bool)
            and math.isfinite(p.value) and 0 < len(p.name) <= MAX_NAME and len(p.unit) <= MAX_UNIT
            and 0 < len(p.scope) <= MAX_NAME and math.isfinite(p.ts) and p.ts >= 0)


def metrics_json(resource: dict[str, Attr], points: Sequence[Point],
                 start_ts: float | None = None) -> dict[str, Any]:
    """An ExportMetricsServiceRequest in the OTLP JSON shape. Points are grouped by scope and then
    by metric, in the order they first appear. `start_ts` is the start time written on sums."""
    scopes: dict[str, dict[tuple, dict[str, Any]]] = {}
    for p in points:
        scope = scopes.setdefault(p.scope, {})
        key = (p.name, p.unit, p.kind, p.monotonic)
        metric = scope.get(key)
        if metric is None:
            metric = {"name": p.name, "unit": p.unit}
            body: dict[str, Any] = {"dataPoints": []}
            if p.kind == "sum":
                body["aggregationTemporality"] = CUMULATIVE
                body["isMonotonic"] = bool(p.monotonic)
                metric["sum"] = body
            else:
                metric["gauge"] = body
            scope[key] = metric
        dp: dict[str, Any] = {"timeUnixNano": _ns(p.ts), "asDouble": float(p.value)}
        if attrs := _attributes(p.attributes, MAX_POINT_ATTRS):
            dp["attributes"] = attrs
        if p.kind == "sum" and start_ts is not None:
            dp["startTimeUnixNano"] = _ns(min(start_ts, p.ts))
        (metric.get("sum") or metric["gauge"])["dataPoints"].append(dp)
    return {"resourceMetrics": [{"resource": _resource(resource), "scopeMetrics": [
        {"scope": {"name": name}, "metrics": list(metrics.values())}
        for name, metrics in scopes.items()]}]}


def _record_ok(r: LogRecord) -> bool:
    return (0 < len(r.event_name) <= MAX_ATTR_VALUE and 0 < len(r.scope) <= MAX_NAME
            and math.isfinite(r.ts) and r.ts >= 0)


def logs_json(resource: dict[str, Attr], records: Sequence[LogRecord]) -> dict[str, Any]:
    """An ExportLogsServiceRequest in the OTLP JSON shape. The event name is carried as the
    event.name attribute, which is where Observe reads it."""
    scopes: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        attrs: dict[str, Attr] = {"event.name": r.event_name}
        attrs.update({k: v for k, v in r.attributes.items() if k != "event.name"})
        scopes.setdefault(r.scope, []).append({
            "timeUnixNano": _ns(r.ts), "severityNumber": int(r.severity_number),
            "severityText": r.severity_text, "body": {"stringValue": r.body},
            "attributes": _attributes(attrs, MAX_POINT_ATTRS)})
    return {"resourceLogs": [{"resource": _resource(resource), "scopeLogs": [
        {"scope": {"name": name}, "logRecords": recs} for name, recs in scopes.items()]}]}


# -- protobuf -------------------------------------------------------------------------------

_VARINT, _FIXED64, _LEN = 0, 1, 2

# name -> {field number: (json name, kind, sub message)}; a name ending in [] repeats.
_SCHEMAS: dict[str, dict[int, tuple[str, str, str | None]]] = {
    "MetricsRequest": {1: ("resourceMetrics[]", "msg", "ResourceMetrics")},
    "ResourceMetrics": {1: ("resource", "msg", "Resource"), 2: ("scopeMetrics[]", "msg", "ScopeMetrics")},
    "Resource": {1: ("attributes[]", "msg", "KeyValue")},
    "ScopeMetrics": {1: ("scope", "msg", "Scope"), 2: ("metrics[]", "msg", "Metric")},
    "Scope": {1: ("name", "str", None)},
    "Metric": {1: ("name", "str", None), 3: ("unit", "str", None), 5: ("gauge", "msg", "Gauge"),
               7: ("sum", "msg", "Sum")},
    "Gauge": {1: ("dataPoints[]", "msg", "NumberPoint")},
    "Sum": {1: ("dataPoints[]", "msg", "NumberPoint"), 2: ("aggregationTemporality", "vint", None),
            3: ("isMonotonic", "bool", None)},
    "NumberPoint": {2: ("startTimeUnixNano", "u64", None), 3: ("timeUnixNano", "u64", None),
                    4: ("asDouble", "f64", None), 7: ("attributes[]", "msg", "KeyValue")},
    "KeyValue": {1: ("key", "str", None), 2: ("value", "msg", "AnyValue")},
    "AnyValue": {1: ("stringValue", "str", None), 2: ("boolValue", "bool", None),
                 3: ("intValue", "vint64", None), 4: ("doubleValue", "f64", None)},
    "LogsRequest": {1: ("resourceLogs[]", "msg", "ResourceLogs")},
    "ResourceLogs": {1: ("resource", "msg", "Resource"), 2: ("scopeLogs[]", "msg", "ScopeLogs")},
    "ScopeLogs": {1: ("scope", "msg", "Scope"), 2: ("logRecords[]", "msg", "LogRecord")},
    "LogRecord": {1: ("timeUnixNano", "u64", None), 2: ("severityNumber", "vint", None),
                  3: ("severityText", "str", None), 5: ("body", "msg", "AnyValue"),
                  6: ("attributes[]", "msg", "KeyValue")},
}
_WIRE = {"msg": _LEN, "str": _LEN, "u64": _FIXED64, "f64": _FIXED64, "vint": _VARINT,
         "vint64": _VARINT, "bool": _VARINT}


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        if value:
            out.append(low | 0x80)
        else:
            out.append(low)
            return bytes(out)


def _field(number: int, kind: str, value: Any, sub: str | None) -> bytes:
    tag = _varint(number << 3 | _WIRE[kind])
    if kind == "msg":
        body = _message(sub or "", value)
        return tag + _varint(len(body)) + body
    if kind == "str":
        data = str(value).encode("utf-8")
        return tag + _varint(len(data)) + data
    if kind == "u64":
        return tag + int(value).to_bytes(8, "little")
    if kind == "f64":
        return tag + struct.pack("<d", float(value))
    if kind == "bool":
        return tag + _varint(1 if value else 0)
    if kind == "vint64":
        return tag + _varint(int(value) & (1 << 64) - 1)
    return tag + _varint(int(value))


def _message(name: str, obj: dict[str, Any]) -> bytes:
    out = bytearray()
    for number, (field, kind, sub) in sorted(_SCHEMAS[name].items()):
        if field.endswith("[]"):
            for item in obj.get(field[:-2], ()):
                out += _field(number, kind, item, sub)
        elif field in obj and obj[field] is not None:
            out += _field(number, kind, obj[field], sub)
    return bytes(out)


def to_protobuf(request: dict[str, Any], signal: str) -> bytes:
    """A request in the OTLP JSON shape as protobuf bytes. Fields that are present are always
    written, even at their proto3 default, which every reader accepts."""
    return _message({"metrics": "MetricsRequest", "logs": "LogsRequest"}[signal], request)


def to_json(request: dict[str, Any]) -> bytes:
    return json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


# -- requests -------------------------------------------------------------------------------

def idempotency_key(entry_id: str, signal: str, part: int) -> str:
    """The Idempotency-Key for one request of an outbox entry. It depends only on the entry id,
    the signal and the position in the split, so every replay of the entry sends the same key.
    An id that is too long or not printable ASCII is replaced by its hash, so the key always
    fits the 128 characters Observe allows."""
    entry = str(entry_id)
    if not entry or not entry.isascii() or not entry.isprintable() or len(entry) > 90:
        entry = "h" + hashlib.sha256(entry.encode("utf-8")).hexdigest()[:40]
    return f"hw-{entry}-{signal[0]}{part}"


def _gzip(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=6, mtime=0)


def _within_limits(raw: bytes, wire: bytes, compress: bool) -> bool:
    if len(raw) > MAX_INFLATED_BYTES or len(wire) > MAX_BODY_BYTES:
        return False
    return not (compress and len(raw) > max(MIN_INFLATED_ALLOWANCE, MAX_INFLATE_RATIO * len(wire)))


def _build(signal: str, items: list, make_tree: Callable[[list], dict[str, Any]], entry_id: str,
           fmt: str, compress: bool, cap: int) -> list[OtlpRequest]:
    out: list[OtlpRequest] = []
    queue: list[list] = [items[i:i + cap] for i in range(0, len(items), cap)][::-1]
    while queue:  # a chunk too big for the wire is halved and its halves are sent in order
        chunk = queue.pop()
        tree = make_tree(chunk)
        raw = to_protobuf(tree, signal) if fmt == "protobuf" else to_json(tree)
        wire = _gzip(raw) if compress else raw
        if not _within_limits(raw, wire, compress):
            if len(chunk) == 1:
                raise OtlpError(f"a single {signal} item does not fit the request limits")
            mid = len(chunk) // 2
            queue.extend([chunk[mid:], chunk[:mid]])
            continue
        headers = {"Content-Type": FORMATS[fmt],
                   "Idempotency-Key": idempotency_key(entry_id, signal, len(out))}
        if compress:
            headers["Content-Encoding"] = "gzip"
        out.append(OtlpRequest(signal, METRICS_PATH if signal == "metrics" else LOGS_PATH, headers,
                               wire, len(chunk), len(raw)))
    return out


def _check_format(fmt: str) -> None:
    if fmt not in FORMATS:
        raise OtlpError(f"unknown format {fmt!r}; use protobuf or json")


def build_metrics_requests(entry_id: str, resource: dict[str, Attr], points: Iterable[Point], *,
                           fmt: str = "protobuf", compress: bool = True,
                           start_ts: float | None = None) -> BuiltRequests:
    """Requests for the points of one outbox entry. Nothing is built for an empty list."""
    _check_format(fmt)
    _resource(resource)
    every = list(points)
    good = [p for p in every if _point_ok(p)]
    return BuiltRequests(_build("metrics", good, lambda c: metrics_json(resource, c, start_ts),
                                entry_id, fmt, compress, MAX_POINTS), len(every) - len(good))


def build_logs_requests(entry_id: str, resource: dict[str, Attr], records: Iterable[LogRecord], *,
                        fmt: str = "protobuf", compress: bool = True) -> BuiltRequests:
    """Requests for the log records of one outbox entry."""
    _check_format(fmt)
    _resource(resource)
    every = list(records)
    good = [r for r in every if _record_ok(r)]
    return BuiltRequests(_build("logs", good, lambda c: logs_json(resource, c), entry_id, fmt,
                                compress, MAX_RECORDS), len(every) - len(good))
