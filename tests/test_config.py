"""Config defaults and the read-only property of the compose mounts."""

from __future__ import annotations

from pathlib import Path

from hostwatch.config import Config

COMPOSE = Path(__file__).resolve().parent.parent / "deploy" / "docker-compose.yml"
ENV_EXAMPLE = COMPOSE.parent / ".env.example"


def _volumes() -> list[str]:
    """Return the list items under the service volumes key, without a YAML parser."""
    items, inside = [], False
    for line in COMPOSE.read_text().splitlines():
        if line.startswith("    volumes:"):
            inside = True
            continue
        if inside:
            stripped = line.strip()
            if stripped.startswith("- "):
                items.append(stripped[2:].strip())
            elif stripped and not stripped.startswith("#"):
                break
    return items


def test_event_source_defaults(monkeypatch):
    for name in ("HOSTWATCH_JOURNAL", "HOSTWATCH_JOURNAL_VOLATILE", "HOSTWATCH_PSTORE", "HOSTWATCH_RASDAEMON_DB"):
        monkeypatch.delenv(name, raising=False)
    cfg = Config()
    assert cfg.journal == Path("/host/journal")
    assert cfg.journal_volatile == Path("/host/journal-volatile")
    assert cfg.pstore == Path("/host/pstore")
    assert cfg.rasdaemon_db == Path("/host/rasdaemon/ras-mc_event.db")


def test_event_source_overrides(monkeypatch):
    monkeypatch.setenv("HOSTWATCH_JOURNAL", "/x/j")
    monkeypatch.setenv("HOSTWATCH_PSTORE", "/x/p")
    monkeypatch.setenv("HOSTWATCH_RASDAEMON_DB", "/x/r.db")
    cfg = Config()
    assert (cfg.journal, cfg.pstore, cfg.rasdaemon_db) == (Path("/x/j"), Path("/x/p"), Path("/x/r.db"))


def test_every_host_mount_is_read_only():
    bind = [v for v in _volumes() if v.startswith("/")]
    sources = {v.split(":")[0] for v in bind}
    assert {"/sys", "/var/log/journal", "/run/log/journal", "/sys/fs/pstore", "/var/lib/rasdaemon"} <= sources
    for v in bind:
        assert v.endswith(":ro"), v


def test_host_proc_is_not_mounted():
    for v in _volumes():
        source = v.split(":")[0]
        assert source != "/proc", v
        assert not source.startswith("/proc/"), v


def test_mount_points_match_config_defaults(monkeypatch):
    for name in ("HOSTWATCH_JOURNAL", "HOSTWATCH_JOURNAL_VOLATILE", "HOSTWATCH_PSTORE", "HOSTWATCH_RASDAEMON_DB"):
        monkeypatch.delenv(name, raising=False)
    targets = {v.split(":")[1] for v in _volumes() if v.startswith("/")}
    cfg = Config()
    assert cfg.journal.as_posix() in targets
    assert cfg.journal_volatile.as_posix() in targets
    assert cfg.pstore.as_posix() in targets
    assert cfg.rasdaemon_db.parent.as_posix() in targets


def test_no_privileged_or_capabilities_added():
    text = COMPOSE.read_text()
    assert "privileged" not in text.replace("no-new-privileges", "")
    assert "cap_add" not in text


def test_env_example_lists_event_variables():
    text = ENV_EXAMPLE.read_text()
    for name in ("HOSTWATCH_JOURNAL", "HOSTWATCH_JOURNAL_VOLATILE", "HOSTWATCH_PSTORE", "HOSTWATCH_RASDAEMON_DB"):
        assert name in text


def _group_add() -> list[str]:
    items, inside = [], False
    for line in COMPOSE.read_text().splitlines():
        if line.startswith("    group_add:"):
            inside = True
            continue
        if inside:
            stripped = line.strip()
            if stripped.startswith("- "):
                items.append(stripped[2:].strip())
            elif stripped and not stripped.startswith("#"):
                break
    return items


def test_group_add_has_journal_gid_and_host_mounts_stay_read_only():
    assert any("HOSTWATCH_JOURNAL_GID" in item for item in _group_add())
    host_mounts = [v for v in _volumes() if v.startswith("/")]
    assert host_mounts
    assert all(v.endswith(":ro") for v in host_mounts)


def test_env_example_documents_journal_gid():
    text = ENV_EXAMPLE.read_text()
    assert "HOSTWATCH_JOURNAL_GID" in text and "getent group systemd-journal" in text


def test_dockerfile_creates_owned_data_dir():
    text = (Path(__file__).resolve().parent.parent / "Dockerfile").read_text()
    assert "mkdir /data" in text and "chown 10001:10001 /data" in text
    assert text.index("chown 10001:10001 /data") < text.index("USER hostwatch")


def test_compose_tests_do_not_depend_on_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert COMPOSE.is_file() and ENV_EXAMPLE.is_file()


# TLS serving and the bind guard. The bind check is exposure control, not authentication.

import datetime
import logging
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from hostwatch.__main__ import uvicorn_kwargs

TOKEN = "t" * 32


def _make_cert(tmp_path: Path, stem: str) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, stem)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / f"{stem}.pem", tmp_path / f"{stem}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return str(cert_path), str(key_path)


def _cfg(**kw) -> Config:
    return Config(role="hub", ingest_token=TOKEN, **kw)


def test_loopback_without_tls_passes():
    for host in ("127.0.0.1", "::1", "localhost"):
        _cfg(hub_bind=host).validate()


def test_non_loopback_without_tls_is_refused():
    with pytest.raises(ValueError, match="not a loopback"):
        _cfg(hub_bind="0.0.0.0").validate()


def test_non_loopback_with_tls_passes(tmp_path):
    cert, key = _make_cert(tmp_path, "hub")
    _cfg(hub_bind="0.0.0.0", tls_cert=cert, tls_key=key).validate()


def test_insecure_override_passes_and_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="hostwatch.config"):
        _cfg(hub_bind="0.0.0.0", allow_insecure_bind=True).validate()
    assert any("clear text" in r.getMessage() for r in caplog.records)


def test_override_read_from_environment(monkeypatch):
    monkeypatch.setenv("HOSTWATCH_ALLOW_INSECURE_BIND", "1")
    assert Config().allow_insecure_bind is True
    monkeypatch.setenv("HOSTWATCH_ALLOW_INSECURE_BIND", "0")
    assert Config().allow_insecure_bind is False


def test_cert_without_key_and_missing_files_are_refused(tmp_path):
    cert, key = _make_cert(tmp_path, "hub")
    with pytest.raises(ValueError, match="together"):
        _cfg(tls_cert=cert).validate()
    with pytest.raises(ValueError, match="requires"):
        _cfg(tls_client_ca=cert).validate()
    with pytest.raises(ValueError, match="readable file"):
        _cfg(tls_cert=str(tmp_path / "nope.pem"), tls_key=key).validate()


def test_uvicorn_kwargs_plain():
    kw = uvicorn_kwargs(_cfg(hub_port=9000))
    assert kw["host"] == "127.0.0.1" and kw["port"] == 9000
    assert not any(k.startswith("ssl_") for k in kw)


def test_uvicorn_kwargs_tls_and_client_ca(tmp_path):
    cert, key = _make_cert(tmp_path, "hub")
    ca, _ = _make_cert(tmp_path, "ca")
    kw = uvicorn_kwargs(_cfg(tls_cert=cert, tls_key=key))
    assert kw["ssl_certfile"] == cert and kw["ssl_keyfile"] == key
    assert "ssl_ca_certs" not in kw
    kw = uvicorn_kwargs(_cfg(tls_cert=cert, tls_key=key, tls_client_ca=ca))
    assert kw["ssl_ca_certs"] == ca and kw["ssl_cert_reqs"] == ssl.CERT_OPTIONAL
    # The generated files really load as a server certificate.
    ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(cert, key)


def test_legacy_token_with_api_key_prefix_fails_validation():
    with pytest.raises(ValueError, match="hw_"):
        Config(ingest_token="hw_" + "a" * 40).validate()


def test_mtls_uvicorn_mode_raises_at_validation():
    with pytest.raises(ValueError, match="does not expose the verified peer certificate.*proxy"):
        Config(mtls_mode="uvicorn").validate()


BOOL_VARS = (
    ("HOSTWATCH_ALLOW_INSECURE_BIND", "allow_insecure_bind"),
    ("HOSTWATCH_LEGACY_TOKEN_DISABLED", "legacy_token_disabled"),
    ("HOSTWATCH_TLS", "tls_enabled"),
)


@pytest.mark.parametrize("var,attr", BOOL_VARS)
@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "Yes", "on", "ON", " true "])
def test_bool_true_spellings(monkeypatch, var, attr, raw):
    monkeypatch.setenv(var, raw)
    assert getattr(Config(), attr) is True


@pytest.mark.parametrize("var,attr", BOOL_VARS)
@pytest.mark.parametrize("raw", ["0", "false", "FALSE", "No", "off", "OFF", ""])
def test_bool_false_spellings(monkeypatch, var, attr, raw):
    monkeypatch.setenv(var, raw)
    assert getattr(Config(), attr) is False


@pytest.mark.parametrize("var,attr", BOOL_VARS)
def test_bool_unset_is_false(monkeypatch, var, attr):
    monkeypatch.delenv(var, raising=False)
    assert getattr(Config(), attr) is False


@pytest.mark.parametrize("var,attr", BOOL_VARS)
def test_bool_invalid_value_names_variable(monkeypatch, var, attr):
    monkeypatch.setenv(var, "maybe")
    with pytest.raises(ValueError, match=var):
        Config()


def test_env_example_documents_spellings():
    text = ENV_EXAMPLE.read_text()
    for word in ("true", "yes", "on", "false", "no", "off"):
        assert word in text


# ---- Specific-IP bind with a source address allowlist (exposure control, not authentication) ----

def test_specific_ip_with_allowlist_passes_and_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="hostwatch.config"):
        _cfg(hub_bind="10.0.0.2", allowed_clients="10.0.0.5,fd00::5").validate()
    assert any("unencrypted" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "::ffff:0.0.0.0"])
def test_wildcard_bind_with_allowlist_is_refused(bind):
    with pytest.raises(ValueError, match="not a loopback"):
        _cfg(hub_bind=bind, allowed_clients="10.0.0.5").validate()


def test_specific_ip_without_allowlist_is_refused():
    with pytest.raises(ValueError, match="not a loopback"):
        _cfg(hub_bind="10.0.0.2").validate()


@pytest.mark.parametrize("raw,named", [("10.0.0.0/24", "10.0.0.0/24"), ("lab.example", "lab.example"),
                                       ("10.0.0.5,,10.0.0.6", "empty"), ("10.0.0.5,", "empty")])
def test_bad_allowlist_entries_are_refused(raw, named):
    with pytest.raises(ValueError, match=named):
        _cfg(hub_bind="10.0.0.2", allowed_clients=raw).validate()


def test_tls_with_or_without_allowlist_passes(tmp_path):
    cert, key = _make_cert(tmp_path, "hub")
    _cfg(hub_bind="0.0.0.0", tls_cert=cert, tls_key=key).validate()
    _cfg(hub_bind="0.0.0.0", tls_cert=cert, tls_key=key, allowed_clients="10.0.0.5").validate()


def test_allowlist_read_from_environment(monkeypatch):
    monkeypatch.setenv("HOSTWATCH_ALLOWED_CLIENTS", "10.0.0.5")
    assert Config().allowed_clients == "10.0.0.5"


# Listener layout for the all role with a specific-IP bind: the local agent posts over loopback.

import socket

from fastapi.testclient import TestClient

from hostwatch.__main__ import bind_sockets, listen_addresses, local_agent_hub_url
from hostwatch.hub import create_app
from hostwatch.store import Store


def _listen_cfg(role, bind, **kw):
    return Config(role=role, hub_bind=bind, hub_port=8090, ingest_token=TOKEN, allowed_clients="10.0.0.9", **kw)


def test_all_role_specific_bind_listens_on_both():
    assert listen_addresses(_listen_cfg("all", "10.0.0.5")) == [("10.0.0.5", 8090), ("127.0.0.1", 8090)]


def test_hub_role_specific_bind_listens_only_on_it():
    assert listen_addresses(_listen_cfg("hub", "10.0.0.5")) == [("10.0.0.5", 8090)]


def test_loopback_and_wildcard_binds_listen_once():
    assert listen_addresses(_listen_cfg("all", "127.0.0.1")) == [("127.0.0.1", 8090)]
    assert listen_addresses(_listen_cfg("all", "0.0.0.0")) == [("0.0.0.0", 8090)]


def test_second_bind_failure_raises_and_closes_first():
    opened = []

    def fake(host, port):
        if host == "127.0.0.1":
            raise OSError("address in use")
        s = socket.socket()
        opened.append(s)
        return s

    with pytest.raises(RuntimeError, match=r"127\.0\.0\.1:8090.*address in use"):
        bind_sockets(_listen_cfg("all", "10.0.0.5"), bind_one=fake)
    assert len(opened) == 1 and opened[0].fileno() == -1


def test_loopback_listener_really_binds():
    socks = bind_sockets(Config(role="hub", hub_bind="127.0.0.1", hub_port=0, ingest_token=TOKEN))
    try:
        assert len(socks) == 1 and socks[0].getsockname()[0] == "127.0.0.1"
    finally:
        for s in socks:
            s.close()


def test_local_agent_url_is_loopback_and_admitted(tmp_path):
    cfg = _listen_cfg("all", "10.0.0.5", data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                      argon2_parallelism=1)
    url = local_agent_hub_url(cfg)
    assert url == "http://127.0.0.1:8090"
    # The agent's request arrives from a loopback peer, which the source filter always admits.
    client = TestClient(create_app(cfg, Store(tmp_path / "db.sqlite")), client=("127.0.0.1", 40000))
    assert client.get("/internal/v1/health").status_code == 200
    assert [r for r in Store(tmp_path / "db.sqlite").audit_rows() if r["kind"] == "source_denied"] == []


@pytest.mark.parametrize("raw", ["fe80::1%eth0", "10.0.0.5,fe80::1%eth0"])
def test_scoped_ipv6_allowlist_entry_is_refused(raw):
    with pytest.raises(ValueError, match="scope zone"):
        _cfg(hub_bind="10.0.0.2", allowed_clients=raw).validate()


def test_scoped_ipv6_bind_is_refused():
    with pytest.raises(ValueError, match="scope zone"):
        _cfg(hub_bind="fe80::1%eth0", allowed_clients="10.0.0.5").validate()


@pytest.mark.parametrize("raw", ["127.0.0.1", "224.0.0.1", "0.0.0.0", "127.0.0.1,224.0.0.1,255.255.255.255"])
def test_allowlist_without_a_usable_remote_entry_is_refused(raw):
    with pytest.raises(ValueError, match="can ever match"):
        _cfg(hub_bind="10.0.0.2", allowed_clients=raw).validate()


def test_allowlist_with_one_usable_entry_among_useless_ones_passes():
    _cfg(hub_bind="10.0.0.2", allowed_clients="127.0.0.1,10.0.0.5").validate()


@pytest.mark.parametrize("bind", ["255.255.255.255", "224.0.0.1", "ff02::1"])
def test_broadcast_or_multicast_bind_is_refused(bind):
    with pytest.raises(ValueError, match="multicast or broadcast"):
        _cfg(hub_bind=bind, allowed_clients="10.0.0.5").validate()


@pytest.mark.parametrize("value", [0, -1, 4.9])
def test_interval_below_the_minimum_is_refused(value):
    with pytest.raises(ValueError, match="HOSTWATCH_INTERVAL must be at least 5"):
        _cfg(interval_s=value).validate()


def test_the_minimum_interval_is_accepted():
    _cfg(interval_s=5.0).validate()
