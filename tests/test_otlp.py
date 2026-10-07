"""OTLP encoder and request builder tests: round trips through an independent decoder, edge
values, request limits and a stable Idempotency-Key."""

from __future__ import annotations

import gzip
import json
import math
import random
from pathlib import Path

import pytest
from otlp_decoder import decode

from hostwatch import otel_map as m
from hostwatch import otlp
from hostwatch.model import Event, Sample

RES = m.resource_attributes("host1", "linux", "1.2.3", machine_id="abc")
FIXTURES = Path(__file__).parent / "fixtures" / "otel"


def pt(name="hw.cpu.utilization", value=0.5, ts=1700000000.0, attrs=None, kind=m.GAUGE,
       scope="hostwatch.collector.cpu", unit="1", monotonic=False):
    return m.Point(scope, name, unit, kind, value, ts, attrs or {}, monotonic)


def rec(event="hostwatch.md.degraded", ts=1700000000.5, attrs=None, body="md0 degraded",
        scope="hostwatch.collector.journal"):
    return m.LogRecord(scope, ts, event, 17, "ERROR", body, attrs or {"observe.source": "journal"})


def inflate(req):
    return gzip.decompress(req.body) if req.headers.get("Content-Encoding") == "gzip" else req.body


def tree(req):
    raw = inflate(req)
    if req.headers["Content-Type"] == otlp.JSON:
        return json.loads(raw)
    return decode(raw, req.signal)


def attr_map(attrs):
    out = {}
    for kv in attrs:
        ((_, v),) = kv["value"].items()
        out[kv["key"]] = v
    return out


def all_points(t):
    for rm in t["resourceMetrics"]:
        for sm in rm["scopeMetrics"]:
            for me in sm["metrics"]:
                body = me.get("gauge") or me["sum"]
                for dp in body["dataPoints"]:
                    yield sm["scope"]["name"], me, body, dp


def first_record(req):
    return tree(req)["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]


@pytest.mark.parametrize("fmt", ["protobuf", "json"])
@pytest.mark.parametrize("compress", [True, False])
def test_metrics_round_trip(fmt, compress):
    points = [pt(attrs={"cpu": "0", "n": 3, "f": 1.5, "ok": True}),
              pt("hw.energy", 12.0, kind=m.SUM, monotonic=True, unit="J",
                 scope="hostwatch.collector.rapl")]
    built = otlp.build_metrics_requests("e1", RES, points, fmt=fmt, compress=compress,
                                        start_ts=1699999000.0)
    assert built.skipped == 0 and len(built.requests) == 1
    req = built.requests[0]
    assert req.path == "/v1/metrics" and req.count == 2
    assert req.headers["Content-Type"] == otlp.FORMATS[fmt]
    assert ("Content-Encoding" in req.headers) is compress
    t = tree(req)
    res = attr_map(t["resourceMetrics"][0]["resource"]["attributes"])
    assert res["host.name"] == "host1" and res["observe.platform"] == "linux"
    got = list(all_points(t))
    assert [g[0] for g in got] == ["hostwatch.collector.cpu", "hostwatch.collector.rapl"]
    _, me, _, dp = got[0]
    assert me["name"] == "hw.cpu.utilization" and me["unit"] == "1" and "gauge" in me
    assert dp["asDouble"] == 0.5 and dp["timeUnixNano"] == "1700000000000000000"
    assert attr_map(dp["attributes"]) == {"cpu": "0", "n": "3", "f": 1.5, "ok": True}
    _, me2, body2, dp2 = got[1]
    assert "sum" in me2 and body2["aggregationTemporality"] == 2 and body2["isMonotonic"] is True
    assert dp2["startTimeUnixNano"] == "1699999000000000000"


def test_protobuf_and_json_forms_carry_the_same_data():
    points = [pt(attrs={"a": "x"}), pt(value=0.25), pt("hw.temp", 41.0, unit="Cel", attrs={"hw.id": "cpu0"})]
    p = tree(otlp.build_metrics_requests("e", RES, points).requests[0])
    j = tree(otlp.build_metrics_requests("e", RES, points, fmt="json").requests[0])
    assert p == j
    logs = [rec(), rec(attrs={"observe.source": "x", "observe.detail.n": 7})]
    assert tree(otlp.build_logs_requests("e", RES, logs).requests[0]) == \
        tree(otlp.build_logs_requests("e", RES, logs, fmt="json").requests[0])


@pytest.mark.parametrize("fmt", ["protobuf", "json"])
def test_logs_round_trip(fmt):
    r = rec(attrs={"observe.source": "journal", "observe.dedup_key": "k", "observe.detail.n": 5,
                   "observe.host.clean_shutdown": False})
    req = otlp.build_logs_requests("e2", RES, [r], fmt=fmt).requests[0]
    assert req.path == "/v1/logs" and req.count == 1
    sl = tree(req)["resourceLogs"][0]["scopeLogs"][0]
    assert sl["scope"]["name"] == "hostwatch.collector.journal"
    lr = sl["logRecords"][0]
    assert lr["severityNumber"] == 17 and lr["severityText"] == "ERROR"
    assert lr["body"] == {"stringValue": "md0 degraded"}
    assert lr["timeUnixNano"] == "1700000000500000000"
    assert attr_map(lr["attributes"]) == {
        "event.name": "hostwatch.md.degraded", "observe.source": "journal",
        "observe.dedup_key": "k", "observe.detail.n": "5", "observe.host.clean_shutdown": False}


def test_event_name_attribute_wins_over_a_clashing_attribute():
    r = rec(attrs={"event.name": "other"})
    lr = first_record(otlp.build_logs_requests("e", RES, [r]).requests[0])
    assert attr_map(lr["attributes"])["event.name"] == "hostwatch.md.degraded"


def test_every_mapped_fixture_encodes_and_decodes():
    for f in sorted(FIXTURES.glob("*.json")):
        doc = json.loads(f.read_text())
        if f.stem == "events":
            records = [m.map_event(Event(**e)) for e in doc["events"]]
            built = otlp.build_logs_requests("fx", RES, records)
            assert not built.skipped
            got = [lr for r in built.requests for sl in tree(r)["resourceLogs"][0]["scopeLogs"]
                   for lr in sl["logRecords"]]
            assert sorted(attr_map(lr["attributes"])["event.name"] for lr in got) == \
                sorted(r.event_name for r in records)
            continue
        points = m.map_samples([Sample(**s) for s in doc["samples"]])
        built = otlp.build_metrics_requests("fx", RES, points)
        assert not built.skipped
        got = [(g[1]["name"], g[3]["asDouble"]) for r in built.requests for g in all_points(tree(r))]
        assert sorted(got) == sorted((p.name, float(p.value)) for p in points), f.stem


# -- edge values ----------------------------------------------------------------------------

@pytest.mark.parametrize("value", [0.0, 1e-300, 1.7976931348623157e308, -273.15, 5e-324])
def test_extreme_finite_values_survive(value):
    for fmt in ("protobuf", "json"):
        t = tree(otlp.build_metrics_requests("e", RES, [pt(value=value)], fmt=fmt).requests[0])
        assert next(all_points(t))[3]["asDouble"] == value


def test_integer_values_are_sent_as_doubles():
    t = tree(otlp.build_metrics_requests("e", RES, [pt(value=7)]).requests[0])
    assert next(all_points(t))[3]["asDouble"] == 7.0


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_non_finite_points_are_skipped_not_sent(bad):
    built = otlp.build_metrics_requests("e", RES, [pt(value=bad), pt(value=1.0)])
    assert built.skipped == 1 and built.requests[0].count == 1


def test_point_observe_would_refuse_is_skipped():
    points = [pt(name="x" * 129), pt(unit="u" * 33), pt(scope=""), pt(ts=-1.0), pt(ts=math.nan), pt()]
    built = otlp.build_metrics_requests("e", RES, points)
    assert built.skipped == 5 and built.requests[0].count == 1


def test_a_record_observe_would_refuse_is_skipped():
    built = otlp.build_logs_requests("e", RES, [rec(event=""), rec(scope=""), rec(ts=math.inf), rec()])
    assert built.skipped == 3 and built.requests[0].count == 1


def test_nothing_to_send_builds_no_request():
    built = otlp.build_metrics_requests("e", RES, [pt(value=math.nan)])
    assert built.requests == [] and built.skipped == 1
    assert otlp.build_metrics_requests("e", RES, []).requests == []
    assert otlp.build_logs_requests("e", RES, []).requests == []


@pytest.mark.parametrize("n", [0, 1, -1, 127, 128, 2**31, 2**63 - 1, -(2**63)])
def test_int_attribute_edges(n):
    for fmt in ("protobuf", "json"):
        t = tree(otlp.build_metrics_requests("e", RES, [pt(attrs={"n": n})], fmt=fmt).requests[0])
        assert attr_map(next(all_points(t))[3]["attributes"])["n"] == str(n)


def test_int_attribute_beyond_int64_becomes_a_string():
    t = tree(otlp.build_metrics_requests("e", RES, [pt(attrs={"n": 2**70})]).requests[0])
    assert next(all_points(t))[3]["attributes"][0]["value"] == {"stringValue": str(2**70)}


def test_non_finite_float_attribute_becomes_a_string():
    t = tree(otlp.build_metrics_requests("e", RES, [pt(attrs={"x": math.nan, "y": math.inf})]).requests[0])
    assert attr_map(next(all_points(t))[3]["attributes"]) == {"x": "nan", "y": "inf"}


def test_bool_is_not_sent_as_int():
    t = tree(otlp.build_metrics_requests("e", RES, [pt(attrs={"b": True, "z": False})]).requests[0])
    assert attr_map(next(all_points(t))[3]["attributes"]) == {"b": True, "z": False}


def test_unicode_and_empty_strings_round_trip():
    text = "café ☃ \U0001F680 \"quoted\" \\ \n\t"
    for fmt in ("protobuf", "json"):
        r = rec(body=text, attrs={"k": text, "e": ""})
        attrs = attr_map(first_record(otlp.build_logs_requests("e", RES, [r], fmt=fmt).requests[0])["attributes"])
        assert attrs["k"] == text and attrs["e"] == ""
        lr = first_record(otlp.build_logs_requests("e", RES, [r], fmt=fmt).requests[0])
        assert lr["body"]["stringValue"] == text


def test_long_string_values_are_cut_to_the_observe_limit():
    t = tree(otlp.build_metrics_requests("e", RES, [pt(attrs={"s": "y" * 5000})]).requests[0])
    assert len(attr_map(next(all_points(t))[3]["attributes"])["s"]) == 1024


def test_attribute_count_and_key_limits():
    attrs = {f"k{i}": i for i in range(40)}
    attrs["x" * 129] = 1
    attrs[""] = 1
    t = tree(otlp.build_metrics_requests("e", RES, [pt(attrs=attrs)]).requests[0])
    got = attr_map(next(all_points(t))[3]["attributes"])
    assert len(got) == 32 and "" not in got and "x" * 129 not in got


def test_timestamps_round_to_the_nanosecond_and_clamp():
    t = tree(otlp.build_metrics_requests("e", RES, [pt(ts=0.0), pt(ts=1.234567891)]).requests[0])
    assert [g[3]["timeUnixNano"] for g in all_points(t)] == ["0", "1234567891"]
    assert otlp._ns(1e30) == str(2**63 - 1)


def test_sum_start_time_never_follows_the_point_time():
    p = pt(kind=m.SUM, monotonic=True, ts=100.0)
    t = tree(otlp.build_metrics_requests("e", RES, [p], start_ts=500.0).requests[0])
    assert next(all_points(t))[3]["startTimeUnixNano"] == "100000000000"
    t = tree(otlp.build_metrics_requests("e", RES, [p]).requests[0])
    assert "startTimeUnixNano" not in next(all_points(t))[3]


def test_points_of_one_metric_share_one_metric_entry():
    points = [pt(attrs={"cpu": "0"}), pt(attrs={"cpu": "1"}), pt("hw.temp", 3.0, unit="Cel")]
    t = tree(otlp.build_metrics_requests("e", RES, points).requests[0])
    metrics = t["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
    assert [x["name"] for x in metrics] == ["hw.cpu.utilization", "hw.temp"]
    assert len(metrics[0]["gauge"]["dataPoints"]) == 2


def test_resource_validation():
    with pytest.raises(otlp.OtlpError):
        otlp.build_metrics_requests("e", {"service.name": "x"}, [pt()])
    with pytest.raises(otlp.OtlpError):
        otlp.build_logs_requests("e", {"host.name": ""}, [rec()])
    with pytest.raises(otlp.OtlpError):
        otlp.build_metrics_requests("e", {"host.name": "h", **{f"a{i}": "v" for i in range(64)}}, [pt()])
    with pytest.raises(otlp.OtlpError):
        otlp.build_metrics_requests("e", {"host.name": "h", "k" * 129: "v"}, [pt()])
    with pytest.raises(otlp.OtlpError):
        otlp.build_metrics_requests("e", RES, [pt()], fmt="xml")


def test_json_body_is_compact_sorted_and_strict():
    body = otlp.build_metrics_requests("e", RES, [pt()], fmt="json", compress=False).requests[0].body
    assert body == json.dumps(json.loads(body), sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode()


# -- limits ---------------------------------------------------------------------------------

def test_points_are_split_at_the_point_cap():
    points = [pt(attrs={"i": i}) for i in range(otlp.MAX_POINTS * 2 + 1)]
    built = otlp.build_metrics_requests("big", RES, points)
    assert [r.count for r in built.requests] == [5000, 5000, 1]
    assert sum(len(list(all_points(tree(r)))) for r in built.requests) == len(points)


def test_records_are_split_at_the_record_cap():
    records = [rec(ts=1700000000.0 + i) for i in range(501)]
    built = otlp.build_logs_requests("big", RES, records)
    assert [r.count for r in built.requests] == [500, 1]


def test_every_request_fits_the_wire_limits():
    # Poorly compressible text forces splitting on size, not on count.
    rng = random.Random(7)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

    def text():
        return "".join(rng.choice(alphabet) for _ in range(900))

    points = [pt(attrs={"s": text(), "t": text()}) for _ in range(1500)]
    for compress in (True, False):
        built = otlp.build_metrics_requests("sz", RES, points, compress=compress)
        assert len(built.requests) > 1
        assert sum(r.count for r in built.requests) == len(points)
        for r in built.requests:
            assert len(r.body) <= otlp.MAX_BODY_BYTES
            assert r.inflated_size <= otlp.MAX_INFLATED_BYTES and len(inflate(r)) == r.inflated_size


def test_json_form_is_also_bounded():
    points = [pt(attrs={"s": "z" * 1000}) for _ in range(3000)]
    built = otlp.build_metrics_requests("j", RES, points, fmt="json", compress=False)
    assert len(built.requests) > 1 and all(len(r.body) <= otlp.MAX_BODY_BYTES for r in built.requests)


def test_highly_repetitive_bodies_stay_under_the_inflate_ratio():
    # Identical large points compress far better than 100 to 1, which Observe treats as a
    # decompression bomb, so the builder must split until the ratio is acceptable.
    points = [pt(attrs={"s": "a" * 1000}) for _ in range(3000)]
    built = otlp.build_metrics_requests("ratio", RES, points, compress=True)
    assert len(built.requests) > 1
    for r in built.requests:
        assert r.inflated_size <= max(otlp.MIN_INFLATED_ALLOWANCE, otlp.MAX_INFLATE_RATIO * len(r.body))
    assert sum(r.count for r in built.requests) == len(points)


def test_a_single_item_that_cannot_fit_is_an_error(monkeypatch):
    monkeypatch.setattr(otlp, "MAX_BODY_BYTES", 10)
    with pytest.raises(otlp.OtlpError):
        otlp.build_metrics_requests("e", RES, [pt()], compress=False)


# -- Idempotency-Key ------------------------------------------------------------------------

def test_requests_replay_byte_for_byte_with_the_same_keys():
    points = [pt(attrs={"i": i}) for i in range(6000)]
    records = [rec(ts=1700000000.0 + i) for i in range(600)]
    for fmt in ("protobuf", "json"):
        a = otlp.build_metrics_requests("entry-7", RES, points, fmt=fmt)
        b = otlp.build_metrics_requests("entry-7", RES, list(points), fmt=fmt)
        assert [(r.headers, r.body) for r in a.requests] == [(r.headers, r.body) for r in b.requests]
        la = otlp.build_logs_requests("entry-7", RES, records, fmt=fmt)
        lb = otlp.build_logs_requests("entry-7", RES, records, fmt=fmt)
        assert [(r.headers, r.body) for r in la.requests] == [(r.headers, r.body) for r in lb.requests]


def test_keys_differ_between_parts_signals_and_entries():
    pts = otlp.build_metrics_requests("a", RES, [pt(attrs={"i": i}) for i in range(5001)]).requests
    keys = [r.headers["Idempotency-Key"] for r in pts]
    assert len(set(keys)) == 2
    log_key = otlp.build_logs_requests("a", RES, [rec()]).requests[0].headers["Idempotency-Key"]
    assert log_key not in keys
    other = otlp.build_metrics_requests("b", RES, [pt()]).requests[0].headers["Idempotency-Key"]
    assert other not in keys


def test_key_is_valid_for_observe_for_any_entry_id():
    for entry in ["x", "a" * 500, "uuid-0000-1111", "café", "has space ok", "line\nbreak", "\x00"]:
        key = otlp.idempotency_key(entry, "metrics", 12)
        assert 0 < len(key) <= 128 and key.isascii() and key.isprintable()
    assert otlp.idempotency_key("a" * 500, "logs", 0) == otlp.idempotency_key("a" * 500, "logs", 0)
    assert otlp.idempotency_key("a" * 500, "logs", 0) != otlp.idempotency_key("a" * 501, "logs", 0)


def test_gzip_output_does_not_depend_on_the_clock():
    a = otlp.build_metrics_requests("e", RES, [pt()]).requests[0].body
    b = otlp.build_metrics_requests("e", RES, [pt()]).requests[0].body
    assert a == b and a[4:8] == b"\x00\x00\x00\x00"


# -- safe encoding --------------------------------------------------------------------------

LONE = chr(0xD800)


@pytest.mark.parametrize("fmt", ["protobuf", "json"])
def test_unpaired_surrogate_is_replaced_and_does_not_block_later_records(fmt):
    bad = rec(body="bad " + LONE + " end", attrs={"observe.source": "x" + LONE, "k" + LONE: "v"})
    good = rec(event="hostwatch.after", body="fine")
    built = otlp.build_logs_requests("e", RES, [bad, good], fmt=fmt)
    assert built.quarantined == 0 and built.skipped == 0
    t = tree(built.requests[0])
    records = t["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert len(records) == 2
    assert records[0]["body"]["stringValue"] == "bad � end"
    assert attr_map(records[0]["attributes"])["observe.source"] == "x�"
    assert records[1]["body"]["stringValue"] == "fine"


def test_control_characters_are_replaced_but_tab_and_newline_are_kept():
    r = rec(body="a\x00b\x1bc\x7fd\te\nf")
    lr = first_record(otlp.build_logs_requests("e", RES, [r]).requests[0])
    assert lr["body"]["stringValue"] == "a�b�c�d\te\nf"


def test_strings_are_cut_after_cleaning_so_the_sent_length_is_the_limit():
    t = tree(otlp.build_metrics_requests("e", RES, [pt(attrs={"s": LONE * 5000})]).requests[0])
    assert attr_map(next(all_points(t))[3]["attributes"])["s"] == "�" * 1024


def test_metric_names_and_scopes_are_cleaned():
    built = otlp.build_metrics_requests("e", RES, [pt(name="a" + LONE, scope="s" + LONE), pt(value=2.0)])
    names = [(scope, me["name"]) for scope, me, _, _ in all_points(tree(built.requests[0]))]
    assert ("s�", "a�") in names and len(names) == 2


class _Unprintable:
    def __str__(self):
        raise RuntimeError("cannot be rendered")


@pytest.mark.parametrize("fmt", ["protobuf", "json"])
def test_an_item_that_still_cannot_be_encoded_is_quarantined_and_counted(fmt, caplog):
    records = [rec(event="hostwatch.one"), rec(attrs={"k": _Unprintable()}), rec(event="hostwatch.three")]
    built = otlp.build_logs_requests("e", RES, records, fmt=fmt)
    assert built.quarantined == 1
    got = [attr_map(r["attributes"])["event.name"] for req in built.requests
           for r in tree(req)["resourceLogs"][0]["scopeLogs"][0]["logRecords"]]
    assert got == ["hostwatch.one", "hostwatch.three"]
    assert "quarantined" in caplog.text
