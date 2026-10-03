"""NUT client tests against a fake upsd bound to 127.0.0.1."""

from __future__ import annotations

import socket
import threading

import pytest

from hostwatch.collectors.nut import ALLOWED_COMMANDS, NutClient, NutCollector, NutError


class FakeUpsd:
    """Serves one scripted LIST VAR reply per connection and records every received line."""

    def __init__(self, replies, stall=False):
        self.replies = list(replies)
        self.stall = stall
        self.received: list[str] = []
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.srv.settimeout(0.1)
        self.port = self.srv.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except OSError:
                continue
            with conn:
                self._serve(conn)

    def _serve(self, conn):
        conn.settimeout(5)
        if self.stall:
            self.stop.wait(3)
            return
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        f = conn.makefile("rwb")
        try:
            for raw in f:
                line = raw.decode().strip()
                self.received.append(line)
                if line.startswith(("USERNAME", "PASSWORD")):
                    f.write(b"OK\n")
                elif line.startswith("LIST VAR"):
                    f.write(reply.encode())
                elif line == "LOGOUT":
                    f.write(b"OK Goodbye\n")
                    f.flush()
                    return
                f.flush()
        except OSError:
            pass

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        self.srv.close()


def listing(status, extra=""):
    return f'BEGIN LIST VAR ups\nVAR ups ups.status "{status}"\n{extra}END LIST VAR ups\n'


FULL = ('VAR ups battery.charge "97"\nVAR ups battery.runtime "1200"\n'
        'VAR ups input.voltage "121.5"\nVAR ups ups.load "23"\nVAR ups ups.mfr "Acme \\"X\\""\n')


@pytest.fixture
def fake():
    servers = []

    def make(*a, **k):
        s = FakeUpsd(*a, **k)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()


def collector(port, **kw):
    kw.setdefault("timeout", 1.0)
    return NutCollector(None, None, host="127.0.0.1", ups="ups", port=port, **kw)


def flags(samples):
    return {s.labels["flag"]: s.value for s in samples if s.metric == "ups_status_flag"}


def test_ol_then_ob_then_ob_lb(fake):
    srv = fake([listing("OL", FULL), listing("OB", FULL), listing("OB LB", FULL)])
    c = collector(srv.port)
    first = c.collect()
    assert flags(first) == {"OL": 1, "OB": 0, "LB": 0}
    vals = {s.metric: s.value for s in first}
    assert vals["battery_charge_pct"] == 97 and vals["battery_runtime_s"] == 1200
    assert vals["input_voltage_v"] == 121.5 and vals["ups_load_pct"] == 23
    assert flags(c.collect()) == {"OL": 0, "OB": 1, "LB": 0}
    last = c.collect()
    assert flags(last) == {"OL": 0, "OB": 1, "LB": 1}
    assert all(s.labels["status"] == "OB LB" for s in last if s.metric == "ups_status_flag")


def test_missing_variables_are_none_and_extra_flags_kept(fake):
    srv = fake([listing("OB DISCHRG")])
    s = collector(srv.port).collect()
    assert flags(s)["DISCHRG"] == 1
    assert [x.value for x in s if x.metric == "battery_charge_pct"] == [None]
    assert [x.value for x in s if x.metric == "ups_load_pct"] == [None]


def test_err_unknown_ups_is_unavailable(fake):
    srv = fake(["ERR UNKNOWN-UPS\n"])
    ok, reason = collector(srv.port).detect()
    assert not ok and "UNKNOWN-UPS" in reason


def test_timeout_is_unavailable(fake):
    srv = fake([""], stall=True)
    ok, reason = collector(srv.port, timeout=0.3).detect()
    assert not ok and "timed out" in reason


def test_refused_connection_is_unavailable():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    ok, reason = collector(port).detect()
    assert not ok and ("cannot reach" in reason or "timed out" in reason)  # Windows reports a refused port as a timeout


def test_only_allowed_commands_are_sent(fake, tmp_path):
    pw = tmp_path / "pw"
    pw.write_text("s3cret\n")
    srv = fake([listing("OL", FULL)])
    collector(srv.port, user="mon", password_file=str(pw)).collect()
    srv.close()
    assert srv.received == ["USERNAME mon", "PASSWORD s3cret", "LIST VAR ups", "LOGOUT"]
    assert all(line.split(" ", 1)[0] in ALLOWED_COMMANDS for line in srv.received)


def test_anonymous_sends_no_login(fake):
    srv = fake([listing("OL")])
    collector(srv.port).collect()
    srv.close()
    assert srv.received == ["LIST VAR ups", "LOGOUT"]


def test_client_refuses_other_commands():
    for line in ("INSTCMD ups beeper.off", "SET VAR ups x 1", "FSD ups"):
        with pytest.raises(NutError):
            NutClient("127.0.0.1", 1, "ups", 1)._send(line)


def test_user_without_password_file_is_unavailable_with_reason():
    c = NutCollector(None, None, host="127.0.0.1", ups="ups", user="mon")
    ok, reason = c.detect()
    assert not ok and "PASSWORD_FILE" in reason


def test_unreadable_password_file_reason_has_no_content(tmp_path):
    c = NutCollector(None, None, host="127.0.0.1", ups="ups", user="mon",
                     password_file=str(tmp_path / "missing"))
    ok, reason = c.detect()
    assert not ok and "password file" in reason


def test_unconfigured_is_absent():
    c = NutCollector(None, None)
    ok, reason = c.detect()
    assert not ok and c.is_absent() and "HOSTWATCH_NUT_HOST" in reason
    assert not collector(1).is_absent()


def test_malformed_lines_are_ignored(fake):
    srv = fake(['BEGIN LIST VAR ups\ngarbage\nVAR other x "1"\nVAR ups ups.status OL\n'
                'VAR ups battery.charge "abc"\nEND LIST VAR ups\n'])
    s = collector(srv.port).collect()
    assert flags(s)["OL"] == 1
    assert [x.value for x in s if x.metric == "battery_charge_pct"] == [None]


# --- Hardening: protocol injection, per-cycle retry, secret reprs -------------------------------

def test_send_rejects_cr_and_lf():
    client = NutClient("127.0.0.1", 1, "ups", 1.0)
    for bad in ("LIST VAR ups\nSET VAR ups x y", "GET VAR ups\rLOGOUT", "USERNAME a\r\nPASSWORD b"):
        with pytest.raises(NutError):
            client._send(bad)  # raises before the socket is touched


@pytest.mark.parametrize("field", ["nut_ups", "nut_user"])
@pytest.mark.parametrize("bad", ["ups\nSET VAR x y", "ups\rx", "my ups", "ups\tx"])
def test_config_rejects_whitespace_in_ups_and_user(field, bad):
    from hostwatch.config import Config
    with pytest.raises(ValueError):
        Config(**{field: bad}).validate()


def test_config_accepts_plain_ups_name():
    from hostwatch.config import Config
    Config(nut_ups="cyberpower", nut_user="monuser").validate()


def test_failed_poll_is_retried_next_cycle_and_ob_raises(fake, tmp_path):
    import time
    from hostwatch.agent import Agent
    from hostwatch.config import Config
    srv = fake([listing("OL", FULL), listing("OL", FULL), "ERR UNKNOWN-UPS\n", listing("OB", FULL)])
    for d in ("sys", "proc", "data"):
        (tmp_path / d).mkdir()
    cfg = Config(sysfs=tmp_path / "sys", procfs=tmp_path / "proc", data_dir=tmp_path / "data",
                 ingest_token="t" * 32, host_name="h1", pstore=tmp_path / "none",
                 journal=tmp_path / "none", rasdaemon_db=tmp_path / "none.db")
    agent = Agent(cfg)
    agent.collectors = [collector(srv.port)]
    agent.seeded = True
    agent.detect()
    agent._last_detect = time.monotonic() + 1e6  # no re-detection: only the per-cycle retry may recover
    first = agent.collect_once()
    assert agent.status["nut"].available
    assert not [e for e in first.events if e.kind.startswith("ups.")]
    agent.collect_once()  # the poll fails
    assert not agent.status["nut"].available
    third = agent.collect_once()  # retried without waiting for re-detection
    assert agent.status["nut"].available
    assert "ups.on_battery" in [e.kind for e in third.events]


def test_config_repr_contains_no_secret_values(tmp_path):
    from hostwatch.config import Config
    secrets = ["ingest-token-" + "a" * 32, "hw_ingestkeyvalue123456", "mqtt-pass-xyzzy-42"]
    cfg = Config(ingest_token=secrets[0], ingest_key=secrets[1], mqtt_password=secrets[2],
                 mqtt_username="u", mqtt_host="broker", nut_user="monuser",
                 nut_password_file=str(tmp_path / "nut.pw"), ha_token_file=str(tmp_path / "ha.tok"))
    text = repr(cfg) + str(cfg) + f"{cfg!r}" + repr(vars(cfg)) + repr(__import__("dataclasses").asdict(cfg))
    for s in secrets:
        assert s not in text
    import dataclasses
    replaced = dataclasses.replace(cfg, ingest_key="hw_replacedsecret999")
    assert "hw_replacedsecret999" not in repr(replaced)
    assert cfg.ingest_token == secrets[0]  # still usable as a str
