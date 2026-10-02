"""The all-role agent reaches its own hub over https://127.0.0.1 even though the
hub certificate names the LAN host, by pinning that certificate."""

from __future__ import annotations

import dataclasses
import datetime
import http.server
import ssl
import threading

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from hostwatch.agent import hub_tls_verify
from hostwatch.config import Config


def _self_signed(tmp_path, dns_name="hostwatch.lan"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "hub.crt", tmp_path / "hub.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return str(cert_path), str(key_path)


@pytest.fixture
def tls_server(tmp_path):
    cert, key = _self_signed(tmp_path)

    class Ok(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Ok)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield cert, srv.server_address[1]
    srv.shutdown()


def _cfg(cert, url):
    return dataclasses.replace(Config(), tls_cert=cert, hub_url=url)


def test_loopback_agent_trusts_the_pinned_hub_certificate(tls_server):
    cert, port = tls_server
    url = f"https://127.0.0.1:{port}/"
    with httpx.Client(verify=hub_tls_verify(_cfg(cert, url))) as c:
        assert c.get(url).text == "ok"


def test_default_verification_would_reject_the_loopback_connection(tls_server):
    cert, port = tls_server
    with pytest.raises(httpx.ConnectError):
        with httpx.Client(verify=ssl.create_default_context(cafile=cert)) as c:
            c.get(f"https://127.0.0.1:{port}/")


def test_remote_hub_keeps_default_verification(tmp_path):
    cert, _ = _self_signed(tmp_path)
    assert hub_tls_verify(_cfg(cert, "https://10.0.0.5:8090")) is True


def test_no_hub_certificate_keeps_default_verification():
    assert hub_tls_verify(_cfg("", "https://127.0.0.1:8090")) is True
