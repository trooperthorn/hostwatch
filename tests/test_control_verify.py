"""hostwatch-control verification: signature, host, expiry, replay, sequence and the local allowlist.

Commands are signed with a throwaway key made in the test. The fixed vector in
tests/fixtures/control_vector.json is checked against stored bytes, never regenerated.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from hostwatch.control import config as cfgmod  # noqa: E402
from hostwatch.control import verify as v  # noqa: E402
from hostwatch.control.signing import canonical_json, verify_signature  # noqa: E402
from hostwatch.control.state import STATE_FILE, ReplayState, StateError  # noqa: E402

VECTOR = json.loads((Path(__file__).parent / "fixtures" / "control_vector.json").read_text(encoding="utf-8"))
NOW = 1759600060
HOST = "MediaIn-SVR"

TOML = """
watchpost_public_key = "{key}"
host = "MediaIn-SVR"

[fan]
controller = "thermalctl"
headers = ["pwm1", "pwm2"]
min_duty_floor = 20
min_duty_ceiling = 100
allow_mode_change = true

[services]
restart = ["hostwatch-agent", "docker:scrutiny"]

[reboot]
allow = true
delay_s = 60
"""


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


@pytest.fixture
def signer():
    return Ed25519PrivateKey.generate()


def pub_text(signer) -> str:
    raw = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + b64(raw)


def make_cmd(**over):
    cmd = {"v": 1, "id": "id-1", "host": HOST, "action": "fan.set_floor",
           "params": {"controller": "thermalctl", "header": "pwm2", "min_duty": 25},
           "requested_by": "sean", "issued_at": NOW - 10, "expires_at": NOW + 110, "seq": 1}
    cmd.update(over)
    return cmd


def sign(signer, cmd) -> str:
    return b64(signer.sign(canonical_json(cmd)))


@pytest.fixture
def make(tmp_path, signer):
    cfg_path = tmp_path / "control.toml"
    cfg_path.write_text(TOML.format(key=pub_text(signer)), encoding="utf-8")
    if os.name == "posix":
        cfg_path.chmod(0o644)
    cfg = cfgmod.load(cfg_path)
    state_path = tmp_path / "data" / STATE_FILE

    def build(clock=lambda: NOW):
        return v.CommandVerifier(cfg, state_path, clock=clock)

    build.cfg, build.state_path = cfg, state_path
    return build


def run(verifier, signer, cmd=None, **over):
    cmd = make_cmd(**over) if cmd is None else cmd
    return verifier.check(cmd, sign(signer, cmd))


# --- the shared vector -------------------------------------------------------------------

def test_vector_canonical_json_matches_stored_bytes():
    assert canonical_json(VECTOR["command"]).decode("utf-8") == VECTOR["canonical_json"]
    assert " " not in VECTOR["canonical_json"]


def test_vector_signature_verifies():
    key = cfgmod.parse_public_key(VECTOR["public_key"])
    assert verify_signature(VECTOR["command"], VECTOR["signature"], key)


def test_vector_pinned_key_is_the_documented_seed():
    seed = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTOR["seed_hex"]))
    assert pub_text(seed) == VECTOR["public_key"]


@pytest.mark.parametrize("path,value", [
    (("v",), 2), (("id",), "x"), (("host",), "Other"), (("action",), "host.reboot"),
    (("params", "controller"), "thermal-control-suite"), (("params", "header"), "pwm1"),
    (("params", "min_duty"), 5), (("requested_by",), "mallory"), (("issued_at",), 1),
    (("expires_at",), 1759609999), (("seq",), 43),
])
def test_vector_each_tampered_field_fails(path, value):
    cmd = copy.deepcopy(VECTOR["command"])
    node = cmd
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    key = cfgmod.parse_public_key(VECTOR["public_key"])
    assert not verify_signature(cmd, VECTOR["signature"], key)


def test_vector_added_and_removed_fields_fail():
    key = cfgmod.parse_public_key(VECTOR["public_key"])
    added = dict(VECTOR["command"], extra=1)
    removed = {k: x for k, x in VECTOR["command"].items() if k != "seq"}
    assert not verify_signature(added, VECTOR["signature"], key)
    assert not verify_signature(removed, VECTOR["signature"], key)


def test_vector_tampered_signature_and_wrong_key_fail():
    key = cfgmod.parse_public_key(VECTOR["public_key"])
    raw = bytearray(base64.b64decode(VECTOR["signature"]))
    raw[0] ^= 1
    assert not verify_signature(VECTOR["command"], b64(bytes(raw)), key)
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert not verify_signature(VECTOR["command"], VECTOR["signature"], other)


@pytest.mark.parametrize("bad", [None, 5, "", "not base64!!", b64(b"short")])
def test_malformed_signatures_are_false_not_errors(bad):
    key = cfgmod.parse_public_key(VECTOR["public_key"])
    assert verify_signature(VECTOR["command"], bad, key) is False


def test_canonical_json_keeps_utf8_and_sorts_nested_keys():
    assert canonical_json({"b": {"z": 1, "a": "é"}, "a": 0}) == '{"a":0,"b":{"a":"é","z":1}}'.encode("utf-8")


# --- ordered checks ----------------------------------------------------------------------

def test_good_command_is_accepted(make, signer):
    d = run(make(), signer)
    assert d.ok and d.command["id"] == "id-1"


def test_tampered_command_is_refused_with_bad_signature(make, signer):
    cmd = make_cmd()
    sig = sign(signer, cmd)
    cmd["params"] = dict(cmd["params"], min_duty=95)
    d = make().check(cmd, sig)
    assert (d.ok, d.reason) == (False, v.BAD_SIGNATURE)


def test_signature_from_another_key_is_refused(make):
    d = run(make(), Ed25519PrivateKey.generate())
    assert d.reason == v.BAD_SIGNATURE


def test_non_object_command_is_malformed(make):
    assert make().check([1], "x").reason == v.MALFORMED


def test_missing_field_is_malformed_after_signature(make, signer):
    cmd = make_cmd()
    del cmd["seq"]
    assert run(make(), signer, cmd).reason == v.MALFORMED


def test_wrong_host_is_refused(make, signer):
    assert run(make(), signer, host="Other-SVR").reason == v.WRONG_HOST


def test_expired_is_refused_but_skew_is_allowed(make, signer):
    exp = NOW - 31
    assert run(make(), signer, expires_at=exp).reason == v.EXPIRED
    ok = run(make(), signer, id="id-2", expires_at=NOW - 30)
    assert ok.ok


def test_signature_is_checked_before_host(make, signer):
    cmd = make_cmd(host="Other-SVR")
    assert make().check(cmd, sign(Ed25519PrivateKey.generate(), cmd)).reason == v.BAD_SIGNATURE


def test_replayed_id_is_refused(make, signer):
    verifier = make()
    assert run(verifier, signer, id="same", seq=1).ok
    assert run(verifier, signer, id="same", seq=2).reason == v.REPLAYED_ID


def test_lower_and_equal_seq_are_refused(make, signer):
    verifier = make()
    assert run(verifier, signer, id="a", seq=10).ok
    assert run(verifier, signer, id="b", seq=9).reason == v.STALE_SEQ
    assert run(verifier, signer, id="c", seq=10).reason == v.STALE_SEQ
    assert run(verifier, signer, id="d", seq=11).ok


def test_seq_and_ids_survive_restart(make, signer):
    assert run(make(), signer, id="a", seq=5).ok
    again = make()
    assert run(again, signer, id="a", seq=6).reason == v.REPLAYED_ID
    assert run(again, signer, id="b", seq=5).reason == v.STALE_SEQ
    assert run(again, signer, id="b", seq=6).ok


def test_corrupt_state_file_fails_closed(make, signer):
    make.state_path.parent.mkdir(parents=True)
    make.state_path.write_text("{not json", encoding="utf-8")
    d = run(make(), signer)
    assert (d.ok, d.reason) == (False, v.STATE_UNAVAILABLE)
    assert make.state_path.read_text(encoding="utf-8") == "{not json"


@pytest.mark.parametrize("body", ['{"last_seq": "9", "ids": []}', '{"ids": []}', '[]',
                                  '{"last_seq": -1, "ids": []}', '{"last_seq": 1, "ids": [3]}',
                                  '{"last_seq": true, "ids": []}'])
def test_invalid_state_shapes_fail_closed(make, signer, body):
    make.state_path.parent.mkdir(parents=True)
    make.state_path.write_text(body, encoding="utf-8")
    assert run(make(), signer).reason == v.STATE_UNAVAILABLE


def test_unwritable_state_refuses_and_does_not_advance(make, signer, monkeypatch):
    verifier = make()

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    assert run(verifier, signer, id="a", seq=3).reason == v.STATE_UNAVAILABLE
    monkeypatch.undo()
    assert run(verifier, signer, id="a", seq=3).ok


def test_state_file_is_written_atomically_without_leftovers(make, signer):
    assert run(make(), signer, seq=7).ok
    data = json.loads(make.state_path.read_text(encoding="utf-8"))
    assert data["last_seq"] == 7 and data["ids"] == ["id-1"]
    assert [p.name for p in make.state_path.parent.iterdir()] == [STATE_FILE]


def test_state_keeps_only_recent_ids(tmp_path):
    state = ReplayState(tmp_path / STATE_FILE)
    for i in range(1005):
        state.record(f"id-{i}", i)
    assert len(ReplayState(tmp_path / STATE_FILE).ids) == 1000
    assert ReplayState(tmp_path / STATE_FILE).last_seq == 1004


def test_missing_state_file_is_a_fresh_start(tmp_path):
    state = ReplayState(tmp_path / "nothing.json")
    assert state.last_seq is None and state.seq_ok(0)


def test_state_error_type_is_raised_directly(tmp_path):
    (tmp_path / STATE_FILE).write_text("zzz", encoding="utf-8")
    with pytest.raises(StateError):
        ReplayState(tmp_path / STATE_FILE)


# --- allowlist ---------------------------------------------------------------------------

def test_unknown_action_is_refused(make, signer):
    assert run(make(), signer, action="fan.set_everything", params={}).reason == v.UNKNOWN_ACTION


def test_header_not_listed_is_refused(make, signer):
    p = {"controller": "thermalctl", "header": "pwm9", "min_duty": 30}
    assert run(make(), signer, params=p).reason == v.HEADER_NOT_ALLOWED


def test_floor_below_min_duty_floor_is_refused(make, signer):
    p = {"controller": "thermalctl", "header": "pwm1", "min_duty": 19}
    assert run(make(), signer, params=p).reason == v.FLOOR_BELOW_MIN
    assert run(make(), signer, id="b", params=dict(p, min_duty=20)).ok


def test_floor_above_ceiling_is_refused(make, signer):
    p = {"controller": "thermalctl", "header": "pwm1", "min_duty": 101}
    assert run(make(), signer, params=p).reason == v.FLOOR_ABOVE_MAX


def test_wrong_controller_is_refused(make, signer):
    p = {"controller": "thermal-control-suite", "header": "pwm1", "min_duty": 30}
    assert run(make(), signer, params=p).reason == v.CONTROLLER_NOT_ALLOWED


@pytest.mark.parametrize("params", [
    {"controller": "thermalctl", "header": "pwm1"},
    {"controller": "thermalctl", "header": "pwm1", "min_duty": 30, "extra": 1},
    {"controller": "thermalctl", "header": "pwm1", "min_duty": "30"},
    {"controller": "thermalctl", "header": "pwm1", "min_duty": True},
    {"controller": "thermalctl", "header": "pwm1", "min_duty": 30.5},
    {"controller": "thermalctl", "header": ["pwm1"], "min_duty": 30},
])
def test_bad_floor_parameters_are_refused(make, signer, params):
    assert run(make(), signer, params=params).reason == v.BAD_PARAMS


def test_set_mode_allowed_and_refused(make, signer):
    p = {"controller": "thermalctl", "mode": "active"}
    assert run(make(), signer, action="fan.set_mode", params=p).ok
    assert run(make(), signer, id="b", seq=2, action="fan.set_mode",
               params=dict(p, mode="turbo")).reason == v.BAD_PARAMS


def test_set_mode_refused_when_not_allowed(tmp_path, signer):
    cfg = cfgmod.parse({**_data(signer), "fan": {"controller": "thermalctl", "headers": ["pwm1"]}})
    verifier = v.CommandVerifier(cfg, tmp_path / STATE_FILE, clock=lambda: NOW)
    d = run(verifier, signer, action="fan.set_mode", params={"controller": "thermalctl", "mode": "active"})
    assert d.reason == v.MODE_CHANGE_NOT_ALLOWED


def _data(signer):
    return {"watchpost_public_key": pub_text(signer), "host": HOST}


def test_fan_actions_refused_without_fan_section(tmp_path, signer):
    verifier = v.CommandVerifier(cfgmod.parse(_data(signer)), tmp_path / STATE_FILE, clock=lambda: NOW)
    assert run(verifier, signer).reason == v.ACTION_NOT_ENABLED


def test_unit_not_listed_is_refused(make, signer):
    assert run(make(), signer, action="service.restart", params={"name": "sshd"}).reason == v.UNIT_NOT_ALLOWED
    assert run(make(), signer, id="b", action="service.restart", params={"name": "docker:scrutiny"}).ok


def test_unit_name_must_match_exactly(make, signer):
    for name in ("hostwatch-agent ", "hostwatch-agent;reboot", "docker:other", "HOSTWATCH-AGENT"):
        d = run(make(), signer, id=name, action="service.restart", params={"name": name})
        assert d.reason == v.UNIT_NOT_ALLOWED, name


def test_service_params_must_be_exact(make, signer):
    d = run(make(), signer, action="service.restart", params={"name": "hostwatch-agent", "x": 1})
    assert d.reason == v.BAD_PARAMS


def test_reboot_allowed_refused_and_no_params(make, signer, tmp_path):
    assert run(make(), signer, action="host.reboot", params={}).ok
    assert run(make(), signer, id="b", seq=2, action="host.reboot",
               params={"host": HOST}).reason == v.BAD_PARAMS
    cfg = cfgmod.parse({**_data(signer), "reboot": {"allow": False}})
    verifier = v.CommandVerifier(cfg, tmp_path / "s.json", clock=lambda: NOW)
    assert run(verifier, signer, action="host.reboot", params={}).reason == v.REBOOT_NOT_ALLOWED


def test_allowlist_refusal_does_not_consume_the_sequence(make, signer):
    verifier = make()
    bad = {"controller": "thermalctl", "header": "pwm9", "min_duty": 30}
    assert run(verifier, signer, id="a", seq=50, params=bad).reason == v.HEADER_NOT_ALLOWED
    assert run(verifier, signer, id="a", seq=50).ok


# --- control.toml loader -----------------------------------------------------------------

def write_cfg(tmp_path, signer, text=None, mode=0o644):
    p = tmp_path / "control.toml"
    p.write_text(text or TOML.format(key=pub_text(signer)), encoding="utf-8")
    if os.name == "posix":
        p.chmod(mode)
    return p


def test_loader_reads_all_sections(tmp_path, signer):
    cfg = cfgmod.load(write_cfg(tmp_path, signer))
    assert cfg.host == HOST and len(cfg.public_key) == 32
    assert cfg.fan.headers == ("pwm1", "pwm2") and cfg.fan.min_duty_floor == 20
    assert cfg.restart == ("hostwatch-agent", "docker:scrutiny")
    assert cfg.reboot.allow and cfg.reboot.delay_s == 60


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
@pytest.mark.parametrize("mode", [0o664, 0o666, 0o620, 0o602])
def test_loader_refuses_group_or_other_writable_file(tmp_path, signer, mode):
    with pytest.raises(cfgmod.ConfigError, match="writable by group or others"):
        cfgmod.load(write_cfg(tmp_path, signer, mode=mode))


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_loader_accepts_owner_only_and_read_only_group(tmp_path, signer):
    cfgmod.load(write_cfg(tmp_path, signer, mode=0o600))
    cfgmod.load(write_cfg(tmp_path, signer, mode=0o640))


def test_group_write_check_is_a_mode_check_on_posix(tmp_path, monkeypatch):
    p = tmp_path / "c.toml"
    p.write_text("x", encoding="utf-8")

    monkeypatch.setattr(cfgmod.os, "name", "posix")
    monkeypatch.setattr(Path, "stat", lambda self, **k: St(0o100666))
    with pytest.raises(cfgmod.ConfigError, match="writable by group or others"):
        cfgmod.check_permissions(p)


class St:
    def __init__(self, mode, uid=0):
        self.st_mode, self.st_uid = mode, uid


def fake_stats(monkeypatch, file_st, dir_st):
    monkeypatch.setattr(cfgmod, "TRUSTED_UIDS", (0,))
    monkeypatch.setattr(cfgmod.os, "name", "posix")
    monkeypatch.setattr(Path, "stat", lambda self, **k: file_st if self.name == "control.toml" else dir_st)


def test_root_owned_file_in_a_closed_directory_is_accepted(monkeypatch, tmp_path):
    fake_stats(monkeypatch, St(0o100644), St(0o040755))
    cfgmod.check_permissions(tmp_path / "control.toml")


def test_non_root_owner_is_refused(monkeypatch, tmp_path):
    fake_stats(monkeypatch, St(0o100644, uid=1000), St(0o040755))
    with pytest.raises(cfgmod.ConfigError, match="not root"):
        cfgmod.check_permissions(tmp_path / "control.toml")


@pytest.mark.parametrize("mode", [0o040775, 0o040757, 0o040777])
def test_group_or_other_writable_directory_is_refused(monkeypatch, tmp_path, mode):
    fake_stats(monkeypatch, St(0o100644), St(mode))
    with pytest.raises(cfgmod.ConfigError, match="directory"):
        cfgmod.check_permissions(tmp_path / "control.toml")


def test_windows_owner_must_be_system_or_administrators(monkeypatch):
    monkeypatch.setattr(cfgmod.os, "name", "nt")
    p = Path("C:/ProgramData/hostwatch/control.toml")
    monkeypatch.setattr(cfgmod, "_windows_owner_sid", lambda path: "S-1-5-21-1-2-3-1001")
    with pytest.raises(cfgmod.ConfigError, match="SYSTEM or Administrators"):
        cfgmod.check_permissions(p)
    for sid in ("S-1-5-18", "S-1-5-32-544", None):
        monkeypatch.setattr(cfgmod, "_windows_owner_sid", lambda path, sid=sid: sid)
        cfgmod.check_permissions(p)


def test_loader_reports_missing_and_invalid_files(tmp_path, signer):
    with pytest.raises(cfgmod.ConfigError, match="cannot read"):
        cfgmod.load(tmp_path / "absent.toml")
    with pytest.raises(cfgmod.ConfigError, match="not valid TOML"):
        cfgmod.load(write_cfg(tmp_path, signer, text="host = ["))


@pytest.mark.parametrize("patch,message", [
    ({"watchpost_public_key": "abc"}, "must start with"),
    ({"watchpost_public_key": "ed25519:!!!"}, "base64"),
    ({"watchpost_public_key": "ed25519:" + b64(b"short")}, "32 bytes"),
    ({"host": ""}, "host"),
    ({"fan": {"controller": "other", "headers": ["a"]}}, "controller"),
    ({"fan": {"controller": "thermalctl", "headers": []}}, "headers"),
    ({"fan": {"controller": "thermalctl", "headers": ["a"], "min_duty_floor": 90, "min_duty_ceiling": 50}}, "limits"),
    ({"fan": {"controller": "thermalctl", "headers": ["a"], "min_duty_floor": True}}, "integer"),
    ({"services": {"restart": ["a b"]}}, "not allowed"),
    ({"services": {"restart": ["--now"]}}, "not allowed"),
    ({"reboot": {"allow": "yes"}}, "true or false"),
    ({"reboot": {"allow": True, "delay_s": -1}}, "negative"),
])
def test_loader_rejects_invalid_values(signer, patch, message):
    with pytest.raises(cfgmod.ConfigError, match=message):
        cfgmod.parse({**_data(signer), **patch})


# --- isolation ---------------------------------------------------------------------------

def test_collector_does_not_import_the_control_package():
    code = ("import sys, hostwatch.agent, hostwatch.hub, hostwatch.cli; "
            "print(any(m.startswith('hostwatch.control') for m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.stdout.strip() == "False", out.stderr


def test_control_modules_import_without_cryptography_or_win32():
    code = ("import sys; sys.modules['cryptography'] = None; import hostwatch.control.verify; "
            "print('win32api' in sys.modules or 'win32service' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.stdout.strip() == "False", out.stderr


def test_missing_cryptography_is_reported_not_swallowed():
    code = ("import sys; sys.modules['cryptography'] = None\n"
            "from hostwatch.control.signing import verify_signature, SigningUnavailable\n"
            "try:\n verify_signature({}, 'AA==', bytes(32))\nexcept SigningUnavailable: print('unavailable')\n")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.stdout.strip() == "unavailable", out.stderr


def test_a_reboot_ignores_only_a_confirm_host_text_and_refuses_any_other_extra_param(make, signer):
    assert run(make(), signer, action="host.reboot", params={"confirm_host": HOST}).ok
    other = run(make(), signer, id="b", seq=2, action="host.reboot", params={"confirm_host": HOST, "force": "1"})
    assert other.reason == v.BAD_PARAMS
    wrong_type = run(make(), signer, id="c", seq=3, action="host.reboot", params={"confirm_host": 1})
    assert wrong_type.reason == v.BAD_PARAMS
    assert run(make(), signer, id="d", seq=4, action="host.reboot", params={"delay": "0"}).reason == v.BAD_PARAMS
