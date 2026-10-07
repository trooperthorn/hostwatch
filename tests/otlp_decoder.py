"""A small independent OTLP protobuf decoder used only by tests. It reads the wire format from
its own field table (written from the OTLP proto definitions, not from the encoder under test) and
returns the OTLP JSON shape, so a protobuf body can be compared with the JSON form."""

from __future__ import annotations

import struct

S = {
    "M": {1: ("resourceMetrics", "R", "RM")}, "L": {1: ("resourceLogs", "R", "RL")},
    "RM": {1: ("resource", "1", "Res"), 2: ("scopeMetrics", "R", "SM")},
    "RL": {1: ("resource", "1", "Res"), 2: ("scopeLogs", "R", "SL")},
    "Res": {1: ("attributes", "R", "KV")},
    "SM": {1: ("scope", "1", "Sc"), 2: ("metrics", "R", "Me")},
    "SL": {1: ("scope", "1", "Sc"), 2: ("logRecords", "R", "LR")},
    "Sc": {1: ("name", "s", None)},
    "Me": {1: ("name", "s", None), 3: ("unit", "s", None), 5: ("gauge", "1", "Ga"), 7: ("sum", "1", "Su")},
    "Ga": {1: ("dataPoints", "R", "NP")},
    "Su": {1: ("dataPoints", "R", "NP"), 2: ("aggregationTemporality", "v", None),
           3: ("isMonotonic", "b", None)},
    "NP": {2: ("startTimeUnixNano", "f64u", None), 3: ("timeUnixNano", "f64u", None),
           4: ("asDouble", "d", None), 7: ("attributes", "R", "KV")},
    "KV": {1: ("key", "s", None), 2: ("value", "1", "AV")},
    "AV": {1: ("stringValue", "s", None), 2: ("boolValue", "b", None), 3: ("intValue", "i", None),
           4: ("doubleValue", "d", None)},
    "LR": {1: ("timeUnixNano", "f64u", None), 2: ("severityNumber", "v", None),
           3: ("severityText", "s", None), 5: ("body", "1", "AV"), 6: ("attributes", "R", "KV")},
}


def _varint(buf, pos):
    shift = result = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def _msg(buf: bytes, name: str) -> dict:
    out: dict = {}
    pos = 0
    while pos < len(buf):
        tag, pos = _varint(buf, pos)
        num, wire = tag >> 3, tag & 7
        field, kind, sub = S[name][num]  # an unknown field is a failure in a test
        if wire == 0:
            raw, pos = _varint(buf, pos)
            if kind == "b":
                val = bool(raw)
            elif kind == "i":
                val = str(raw - (1 << 64) if raw >= 1 << 63 else raw)
            else:
                val = raw
        elif wire == 1:
            raw = buf[pos:pos + 8]
            pos += 8
            val = struct.unpack("<d", raw)[0] if kind == "d" else str(int.from_bytes(raw, "little"))
        elif wire == 2:
            n, pos = _varint(buf, pos)
            raw = buf[pos:pos + n]
            assert len(raw) == n, "truncated"
            pos += n
            val = raw.decode("utf-8") if kind == "s" else _msg(raw, sub)
        else:
            raise AssertionError(f"wire type {wire}")
        if kind == "R":
            out.setdefault(field, []).append(val)
        else:
            out[field] = val
    return out


def decode(body: bytes, signal: str) -> dict:
    return _msg(body, "M" if signal == "metrics" else "L")
