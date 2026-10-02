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
    monkeypatch.setenv("HOSTWATCH_ALLOW_INSECURE_BIND", "yes")
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
