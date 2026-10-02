"""Client certificate identity: headers from a trusted proxy, the ASGI extension, bindings and audit."""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from hostwatch import auth
from hostwatch.config import Config
from hostwatch.hub import create_app
from hostwatch.mtls import SAN_HEADER, SUBJECT_HEADER, VERIFY_HEADER
from hostwatch.store import Store

TRUSTED = ("10.0.0.5", 40000)
OTHER = ("203.0.113.9", 40000)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lab"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_pki(tmp_path, cn: str, email: str):
    """Generate a CA and a client certificate signed by it, write both PEM files, return the client cert."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name("test-ca")).issuer_name(_name("test-ca"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (tmp_path / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "client.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert.verify_directly_issued_by(ca)
    return cert


def headers_for(cert) -> dict:
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return {VERIFY_HEADER: "SUCCESS", SUBJECT_HEADER: cert.subject.rfc4514_string(),
            SAN_HEADER: ",".join("email:" + e for e in sans.get_values_for_type(x509.RFC822Name))}


def build(tmp_path, mode="proxy", proxies="10.0.0.0/24", client=TRUSTED):
    cfg = Config(ingest_token="t" * 64, data_dir=tmp_path, argon2_time_cost=1, argon2_memory_kib=8,
                 argon2_parallelism=1, mtls_mode=mode, mtls_trusted_proxies=proxies)
    store = Store(tmp_path / "db.sqlite")
    uid = store.create_user("alice", auth.hash_password(cfg, "pw"))
    cert = make_pki(tmp_path, "alice-yubikey", "alice@lab.example")
    store.bind_cert(cert.subject.rfc4514_string(), uid)
    return TestClient(create_app(cfg, store), client=client), store, cert


def test_mapped_subject_authenticates_and_is_audited(tmp_path):
    client, store, cert = build(tmp_path)
    r = client.get("/internal/v1/latest", headers=headers_for(cert))
    assert r.status_code == 200
    row = store.audit_rows()[-1]
    assert row["actor"] == "alice" and row["kind"] == "access"
    assert "mtls" in str(row["detail"])


def test_mapped_san_authenticates(tmp_path):
    client, store, cert = build(tmp_path)
    store.bind_cert("san:email:alice@lab.example", store.get_user("alice")["id"])
    h = headers_for(cert)
    h[SUBJECT_HEADER] = "CN=someone-else"
    assert client.get("/internal/v1/latest", headers=h).status_code == 200


def test_mtls_principal_cannot_ingest(tmp_path):
    client, _, cert = build(tmp_path)
    assert client.post("/internal/v1/ingest", json={}, headers=headers_for(cert)).status_code == 403


def test_unmapped_subject_gets_401_and_audit(tmp_path):
    client, store, cert = build(tmp_path)
    h = headers_for(cert)
    h[SUBJECT_HEADER] = "CN=stranger,O=Lab"
    h[SAN_HEADER] = ""
    r = client.get("/internal/v1/latest", headers=h)
    assert r.status_code == 401
    row = store.audit_rows(kind="auth_failure")[-1]
    assert row["actor"] == "anonymous" and row["status"] == 401
    assert "unmapped client certificate" in str(row["detail"]) and "stranger" in str(row["detail"])


def test_header_from_non_allowlisted_remote_is_ignored(tmp_path):
    client, store, cert = build(tmp_path, client=OTHER)
    r = client.get("/internal/v1/latest", headers=headers_for(cert))
    assert r.status_code == 401
    assert "unmapped" not in str(store.audit_rows(kind="auth_failure")[-1]["detail"])


def test_proxy_must_report_success(tmp_path):
    client, _, cert = build(tmp_path)
    h = headers_for(cert)
    h[VERIFY_HEADER] = "FAILED:certificate has expired"
    assert client.get("/internal/v1/latest", headers=h).status_code == 401


def test_revoked_binding_and_disabled_user_rejected(tmp_path):
    client, store, cert = build(tmp_path)
    assert store.revoke_cert(cert.subject.rfc4514_string())
    assert client.get("/internal/v1/latest", headers=headers_for(cert)).status_code == 401


def test_mode_off_ignores_header(tmp_path):
    client, store, cert = build(tmp_path, mode="off")
    assert client.get("/internal/v1/latest", headers=headers_for(cert)).status_code == 401
    assert "unmapped" not in str(store.audit_rows(kind="auth_failure")[-1]["detail"])


def test_uvicorn_mode_ignores_header_and_reads_asgi_extension(tmp_path):
    client, store, cert = build(tmp_path, mode="uvicorn")
    assert client.get("/internal/v1/latest", headers=headers_for(cert)).status_code == 401
    from starlette.requests import Request
    from hostwatch.mtls import make_identity
    cfg = Config(ingest_token="t" * 64, mtls_mode="uvicorn")
    ident = make_identity(cfg, store)
    scope = {"type": "http", "headers": [], "client": TRUSTED,
             "extensions": {"tls": {"client_cert_name": cert.subject.rfc4514_string()}}}
    assert ident(Request(scope)).actor == "alice"


def test_config_validation(tmp_path):
    base = dict(ingest_token="t" * 64)
    with pytest.raises(ValueError, match="MTLS_MODE"):
        Config(mtls_mode="bogus", **base).validate()
    with pytest.raises(ValueError, match="TRUSTED_PROXIES"):
        Config(mtls_mode="proxy", **base).validate()
    with pytest.raises(ValueError, match="TRUSTED_PROXIES"):
        Config(mtls_mode="proxy", mtls_trusted_proxies="not-an-ip", **base).validate()
    Config(mtls_mode="proxy", mtls_trusted_proxies="10.0.0.0/24", **base).validate()
    Config(**base).validate()
