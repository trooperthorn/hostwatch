"""Thermal Control Suite status source: contract fixtures and fakes only, no real pipe is opened."""

from __future__ import annotations

from agent_helpers import collect_once
import copy
import io
import json
import struct
import threading
from pathlib import Path

import pytest
from fakes_windows import FakeCimQuery, FakeCommandRunner, FakeEventLogReader, FakePipeStatusReader

import hostwatch.windows as win
from hostwatch.agent import Agent
from hostwatch.collectors import build_collectors
from hostwatch.collectors.win_thermalsuite import (
    ACCEPTED_SCHEMA_VERSION,
    PIPE_NAME,
    STALE_AFTER_S,
    WinThermalSuiteCollector,
)
from hostwatch.config import Config
from hostwatch.windows import PipeAbsentError, SeamError, WindowsSeam

DOCS = json.loads((Path(__file__).parent / "fixtures" / "windows" / "thermalsuite.json").read_text(encoding="utf-8"))


def seam_for(pipes, pipe=None) -> WindowsSeam:
    return WindowsSeam(events=FakeEventLogReader({}), cim=FakeCimQuery({}),
                       pipe=pipe or FakePipeStatusReader(pipes), runner=FakeCommandRunner())


def collector(pipes) -> WinThermalSuiteCollector:
    return WinThermalSuiteCollector(seam=seam_for(pipes))


def serving(name: str) -> WinThermalSuiteCollector:
    return collector({PIPE_NAME: DOCS[name]})


def find(samples, metric, **labels):
    return [s for s in samples if s.metric == metric and all(s.labels.get(k) == v for k, v in labels.items())]


def pascal(value):
    """What the pipe serves: the same document with PascalCase property names."""
    if isinstance(value, dict):
        return {k[:1].upper() + k[1:]: pascal(v) for k, v in value.items()}
    if isinstance(value, list):
        return [pascal(v) for v in value]
    return value


def test_normal_status_reports_temperature_duty_rpm_and_state():
    c = serving("normal")
    assert c.detect() == (True, f"Thermal Control Suite pipe {PIPE_NAME}")
    samples = c.collect()
    assert {s.source for s in samples} == {"win_thermalsuite"}
    [temp] = find(samples, "zone_temp", zone="cpu")
    assert (temp.value, temp.unit) == (51.0, "C")
    assert find(samples, "zone_load", zone="cpu")[0].value is None  # null stays no value, never zero
    zone_duty = find(samples, "zone_duty", zone="cpu")[0]
    assert (zone_duty.value, zone_duty.labels["reasons"]) == (40.0, "")
    [duty] = find(samples, "fan_duty", sensor="f1")
    assert (duty.value, duty.unit) == (38.0, "%")
    assert duty.labels == {"chip": "thermalsuite", "sensor": "f1", "state": "active", "mode": "active", "reasons": "",
                           "dry_run": "false", "firmware_controlled": "false", "config_error": "false",
                           "applied": "true"}
    assert find(samples, "fan", sensor="f1")[0].value == 812.0
    assert find(samples, "fan_target", sensor="f1")[0].value == 40.0
    assert find(samples, "failsafe")[0].value == 0.0
    assert c.seam.pipe.calls == [PIPE_NAME, PIPE_NAME]


def test_failsafe_status_labels_reasons_and_marks_fans_failsafe():
    samples = serving("failsafe").collect()
    assert find(samples, "failsafe")[0].value == 4.0
    assert find(samples, "zone_duty", zone="cpu")[0].labels["reasons"] == "PassFailed"
    assert find(samples, "zone_temp", zone="gpu")[0].value is None
    f1, f2 = find(samples, "fan_duty", sensor="f1")[0], find(samples, "fan_duty", sensor="f2")[0]
    # A failed control pass is a control wide reason, so every fan is failsafe; f2 is also stalled.
    assert f1.labels["state"] == f2.labels["state"] == "failsafe"
    assert f1.labels["reasons"] == "control:PassFailed"
    assert f2.labels["reasons"] == "control:PassFailed,fan:f2:Stalled"
    assert find(samples, "fan", sensor="f2")[0].value == 0.0  # a stalled fan really reads 0 rpm


def test_a_stalled_fan_without_a_control_failure_is_failsafe_for_that_fan_only():
    doc = copy.deepcopy(DOCS["failsafe"])
    doc["failSafeReasons"] = ["fan:f2:Stalled"]
    samples = collector({PIPE_NAME: doc}).collect()
    assert find(samples, "fan_duty", sensor="f1")[0].labels["state"] == "active"
    assert find(samples, "fan_duty", sensor="f2")[0].labels["state"] == "failsafe"


def test_dry_run_reports_the_label_and_never_a_claimed_duty():
    samples = serving("dryrun").collect()
    [duty] = find(samples, "fan_duty")
    assert duty.value is None  # the actual of 0 in dry run is not a measurement
    assert (duty.labels["state"], duty.labels["mode"], duty.labels["dry_run"], duty.labels["applied"]) == (
        "dry_run", "dry_run", "true", "false")
    assert find(samples, "fan_target")[0].value == 35.0
    assert find(samples, "fan")[0].value == 790.0


def test_firmware_controlled_fan_is_labelled_and_has_no_duty():
    samples = serving("firmware").collect()
    owned = find(samples, "fan_duty", sensor="f1")[0]
    assert (owned.value, owned.labels["firmware_controlled"], owned.labels["state"]) == (48.0, "false", "active")
    fw = find(samples, "fan_duty", sensor="f3")[0]
    assert fw.value is None
    assert (fw.labels["firmware_controlled"], fw.labels["state"]) == ("true", "firmware_controlled")
    assert find(samples, "fan", sensor="f3")[0].value == 1100.0


def test_pipe_pascal_case_keys_read_the_same_as_the_file():
    for name in ("normal", "failsafe", "dryrun", "firmware"):
        c = collector({PIPE_NAME: pascal(DOCS[name])})
        assert c.detect()[0] is True
        got = [(s.metric, s.value, s.labels) for s in c.collect()]
        want = [(s.metric, s.value, s.labels) for s in serving(name).collect()]
        assert got == want


def test_unknown_schema_versions_are_rejected():
    c = serving("unknown_version")
    ok, reason = c.detect()
    assert ok is False and "schemaVersion 2 is not supported" in reason and not c.is_absent()
    with pytest.raises(SeamError, match="not supported"):
        c.collect()
    for bad in ("1", 1.0, True, None, [1]):
        doc = dict(DOCS["normal"], schemaVersion=bad)
        assert "integer schemaVersion" in collector({PIPE_NAME: doc}).detect()[1]
    doc = dict(DOCS["normal"])
    del doc["schemaVersion"]
    assert collector({PIPE_NAME: doc}).detect()[0] is False
    assert ACCEPTED_SCHEMA_VERSION == 1


def test_fields_added_within_the_version_are_ignored():
    doc = copy.deepcopy(DOCS["normal"])
    doc["extra"] = {"anything": 1}
    doc["fans"][0]["newField"] = "x"
    assert len(collector({PIPE_NAME: doc}).collect()) == len(serving("normal").collect())


def test_missing_pipe_is_absent():
    c = collector({})
    ok, reason = c.detect()
    assert ok is False and "does not exist" in reason and c.is_absent() is True
    # Once the service appears the source is no longer absent.
    c.seam.pipe.pipes[PIPE_NAME] = DOCS["normal"]
    assert c.detect()[0] is True and c.is_absent() is False


def test_timeout_and_bad_payload_are_unavailable_not_absent():
    timeout = SeamError(f"pipe {PIPE_NAME} did not answer within 3 seconds")
    c = collector({PIPE_NAME: timeout})
    assert c.detect() == (False, str(timeout)) and c.is_absent() is False
    with pytest.raises(SeamError):
        c.collect()
    for doc in ({}, {"schemaVersion": 1}, dict(DOCS["normal"], zones={}), dict(DOCS["normal"], fans="x")):
        c = collector({PIPE_NAME: doc})
        assert c.detect()[0] is False and c.is_absent() is False


def test_a_stale_or_never_completed_pass_is_unavailable():
    stale = dict(DOCS["normal"], passAgeSeconds=STALE_AFTER_S + 1)
    assert "stale" in collector({PIPE_NAME: stale}).detect()[1]
    for age in (None, "1", float("inf"), True):
        doc = dict(DOCS["normal"], passAgeSeconds=age)
        assert collector({PIPE_NAME: doc}).detect()[0] is False
    assert collector({PIPE_NAME: dict(DOCS["normal"], passAgeSeconds=STALE_AFTER_S)}).detect()[0] is True


def test_no_seam_is_unavailable():
    assert WinThermalSuiteCollector().detect() == (False, "no Windows seam")


def test_reads_with_the_short_timeout_and_the_documented_pipe_name():
    seen = []

    class Recording(FakePipeStatusReader):
        def read(self, pipe_name, timeout_s=None):
            seen.append((pipe_name, timeout_s))
            return super().read(pipe_name, timeout_s)

    pipe = Recording({PIPE_NAME: DOCS["normal"]})
    WinThermalSuiteCollector(seam=seam_for({}, pipe)).detect()
    assert seen == [("ThermalControlSuite.Ipc", win.DEFAULT_PIPE_TIMEOUT_S)]
    assert win.DEFAULT_PIPE_TIMEOUT_S <= 5


def test_collector_is_registered_only_on_windows(tmp_path):
    cfg = Config(data_dir=tmp_path, sysfs=tmp_path / "sys", procfs=tmp_path / "proc")
    assert "win_thermalsuite" in [c.id for c in build_collectors(cfg, platform="windows")]
    assert "win_thermalsuite" not in [c.id for c in build_collectors(cfg, platform="x86")]


def test_collector_runs_through_the_agent(tmp_path):
    cfg = Config(data_dir=tmp_path, sysfs=tmp_path / "sys", procfs=tmp_path / "proc")
    seam = seam_for({PIPE_NAME: DOCS["failsafe"]})
    agent = Agent(cfg, seam)
    agent.collectors = [WinThermalSuiteCollector(seam=seam)]
    batch = collect_once(agent)
    [status] = [s for s in batch.sources if s.source == "win_thermalsuite"]
    assert status.available and status.present
    assert find(batch.samples, "fan_duty", sensor="f2")


def test_an_absent_pipe_marks_the_source_not_present_in_the_agent(tmp_path):
    cfg = Config(data_dir=tmp_path, sysfs=tmp_path / "sys", procfs=tmp_path / "proc")
    seam = seam_for({})
    agent = Agent(cfg, seam)
    agent.collectors = [WinThermalSuiteCollector(seam=seam)]
    batch = collect_once(agent)
    [status] = [s for s in batch.sources if s.source == "win_thermalsuite"]
    assert (status.available, status.present) == (False, False)


# The framing and the real reader's control flow, without any real pipe.

def frame(obj) -> bytes:
    body = json.dumps(obj).encode("utf-8")
    return struct.pack("<i", len(body)) + body


class Duplex:
    """A binary stream that records what is written and answers with canned bytes, a few at a time."""

    def __init__(self, reply: bytes, chunk: int = 3) -> None:
        self.reply, self.chunk, self.written = io.BytesIO(reply), chunk, b""

    def write(self, data):
        self.written += data

    def flush(self):
        pass

    def read(self, n):
        return self.reply.read(min(n, self.chunk))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_the_only_request_written_is_the_documented_status_query():
    stream = Duplex(frame({"Success": True, "ReadOnlyStatus": pascal(DOCS["normal"])}))
    status = win.exchange_status(stream)
    (length,) = struct.unpack("<i", stream.written[:4])
    assert length == len(stream.written) - 4
    assert json.loads(stream.written[4:]) == {"Type": "GetStatusReadOnly"}
    assert status["SchemaVersion"] == 1 and status["Zones"][0]["Id"] == "cpu"
    assert win.encode_status_request() == stream.written


def test_exchange_rejects_bad_frames_and_failures():
    good = {"Success": True, "ReadOnlyStatus": {}}
    cases = [
        ("closed before a full reply", b""),
        ("closed before a full reply", frame(good)[:-2]),
        ("unusable frame length 0", struct.pack("<i", 0)),
        ("unusable frame length 2000000", struct.pack("<i", 2_000_000)),
        ("not JSON", struct.pack("<i", 3) + b"{x}"),
        ("not a JSON object", frame([1])),
        ("reported failure: nope", frame({"Success": False, "Error": "nope"})),
        ("no ReadOnlyStatus", frame({"Success": True, "Status": {}})),
        ("no ReadOnlyStatus", frame({"Success": True, "ReadOnlyStatus": [1]})),
    ]
    for fragment, reply in cases:
        with pytest.raises(SeamError, match=fragment):
            win.exchange_status(Duplex(reply))


def test_real_reader_reports_a_missing_pipe_without_connecting(monkeypatch):
    monkeypatch.setattr(win.os, "listdir", lambda path: ["other"])
    monkeypatch.setattr(win, "open", lambda *a, **k: pytest.fail("a pipe was opened"), raising=False)
    with pytest.raises(PipeAbsentError):
        win.NamedPipeStatusReader().read(PIPE_NAME)

    def broken(path):
        raise OSError("denied")
    monkeypatch.setattr(win.os, "listdir", broken)
    with pytest.raises(SeamError) as err:
        win.NamedPipeStatusReader().read(PIPE_NAME)
    assert not isinstance(err.value, PipeAbsentError)
    with pytest.raises(SeamError, match="invalid pipe name"):
        win.NamedPipeStatusReader().read("bad name\\x")


def test_real_reader_returns_a_good_reply_and_opens_the_pipe_read_write(monkeypatch):
    reply = frame({"Success": True, "ReadOnlyStatus": pascal(DOCS["normal"])})
    opened = []

    def fake_open(path, mode, buffering):
        opened.append((path, mode, buffering))
        return Duplex(reply)

    monkeypatch.setattr(win.os, "listdir", lambda path: [PIPE_NAME])
    monkeypatch.setattr(win, "open", fake_open, raising=False)
    assert win.NamedPipeStatusReader().read(PIPE_NAME, timeout_s=5)["SchemaVersion"] == 1
    assert opened == [(win.PIPE_DIR + PIPE_NAME, "r+b", 0)]


def test_real_reader_times_out_on_a_silent_service(monkeypatch):
    release = threading.Event()

    class Silent(Duplex):
        def read(self, n):
            release.wait(10)  # ends as soon as the test releases it, so no thread outlives the test
            return b""

    monkeypatch.setattr(win.os, "listdir", lambda path: [PIPE_NAME])
    monkeypatch.setattr(win, "open", lambda path, mode, buffering: Silent(b""), raising=False)
    try:
        with pytest.raises(SeamError, match="did not answer within 0.05 seconds"):
            win.NamedPipeStatusReader(timeout_s=0.05).read(PIPE_NAME)
    finally:
        release.set()


def test_fans_are_reported_with_failsafe_reasons(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    cfg = Config(procfs=tmp_path / "proc", sysfs=tmp_path / "sys", data_dir=data, host_name="h1",
                 journal=tmp_path / "j", journal_volatile=tmp_path / "jv", pstore=tmp_path / "p", scrutiny_url="")
    seam = seam_for({PIPE_NAME: DOCS["failsafe"]})
    agent = Agent(cfg, seam)
    agent.collectors = [WinThermalSuiteCollector(seam=seam)]
    fans = {s.labels["sensor"]: s for s in collect_once(agent).samples
            if s.source == "win_thermalsuite" and s.metric == "fan"}
    assert "control:PassFailed" in fans["f2"].labels.get("reasons", "")
    assert fans["f1"].value == 1650.0