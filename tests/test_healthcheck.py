"""The container healthcheck command and the Dockerfile settings that use it."""
import io
import json
import re
from pathlib import Path

from hostwatch.__main__ import health_url, healthcheck, main
from hostwatch.config import Config

ROOT = Path(__file__).resolve().parent.parent


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def ok_opener(seen):
    def opener(url):
        seen.append(url)
        return FakeResponse(json.dumps({"status": "ok", "version": "x"}).encode())
    return opener


def test_exits_zero_when_health_answers(monkeypatch):
    monkeypatch.setenv("HOSTWATCH_ROLE", "all")
    seen = []
    assert healthcheck(Config(), opener=ok_opener(seen)) == 0
    assert seen == ["http://127.0.0.1:8090/internal/v1/health"]


def test_exits_nonzero_when_unreachable(monkeypatch, capsys):
    monkeypatch.setenv("HOSTWATCH_ROLE", "all")

    def refuse(url):
        raise ConnectionRefusedError("refused")
    assert healthcheck(Config(), opener=refuse) == 1
    assert "unhealthy" in capsys.readouterr().err


def test_exits_nonzero_on_bad_status_or_body(monkeypatch):
    monkeypatch.setenv("HOSTWATCH_ROLE", "all")
    assert healthcheck(Config(), opener=lambda u: FakeResponse(b"{}", status=503)) == 1
    assert healthcheck(Config(), opener=lambda u: FakeResponse(b'{"status": "bad"}')) == 1
    assert healthcheck(Config(), opener=lambda u: FakeResponse(b"not json")) == 1


def test_url_uses_configured_port(monkeypatch):
    monkeypatch.setenv("HOSTWATCH_ROLE", "all")
    monkeypatch.setenv("HOSTWATCH_HUB_PORT", "9443")
    assert health_url(Config()) == "http://127.0.0.1:9443/internal/v1/health"


def test_url_uses_https_when_tls_is_configured(monkeypatch, tmp_path):
    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    cert.write_text("x")
    key.write_text("x")
    monkeypatch.setenv("HOSTWATCH_ROLE", "all")
    monkeypatch.setenv("HOSTWATCH_TLS_CERT", str(cert))
    monkeypatch.setenv("HOSTWATCH_TLS_KEY", str(key))
    assert Config().tls_configured
    assert health_url(Config()).startswith("https://127.0.0.1:8090/")


def test_hub_role_with_specific_bind_probes_that_address(monkeypatch):
    monkeypatch.setenv("HOSTWATCH_ROLE", "hub")
    monkeypatch.setenv("HOSTWATCH_HUB_BIND", "192.0.2.10")
    assert health_url(Config()) == "http://192.0.2.10:8090/internal/v1/health"
    monkeypatch.setenv("HOSTWATCH_HUB_BIND", "0.0.0.0")
    assert health_url(Config()).startswith("http://127.0.0.1:")


def test_agent_role_has_nothing_to_probe(monkeypatch):
    monkeypatch.setenv("HOSTWATCH_ROLE", "agent")

    def boom(url):
        raise AssertionError("must not connect")
    assert healthcheck(Config(), opener=boom) == 0


def test_main_dispatches_healthcheck(monkeypatch):
    monkeypatch.setenv("HOSTWATCH_ROLE", "all")
    monkeypatch.setattr("hostwatch.__main__.healthcheck", lambda cfg: 7)
    assert main(["healthcheck"]) == 7


def _dockerfile() -> str:
    return (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_dockerfile_has_healthcheck_using_the_command():
    text = _dockerfile()
    assert re.search(r"^HEALTHCHECK .*--interval=\S+ .*--timeout=\S+ .*--retries=\d+", text, re.M)
    assert '"python", "-m", "hostwatch", "healthcheck"' in text
    code = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    assert not any("curl" in ln for ln in code)


def test_dockerfile_has_oci_labels_from_build_args():
    text = _dockerfile()
    for arg in ("VERSION", "REVISION", "LICENSES"):
        assert re.search(rf"^ARG {arg}=", text, re.M)
    for label, arg in (("source", None), ("version", "VERSION"), ("revision", "REVISION"),
                       ("licenses", "LICENSES")):
        assert f"org.opencontainers.image.{label}=" in text
        if arg:
            assert f'org.opencontainers.image.{label}="${{{arg}}}"' in text


def test_dockerfile_base_is_digest_pinned_with_update_note():
    text = _dockerfile()
    assert re.search(r"^FROM python:3\.12-slim@sha256:[0-9a-f]{64}$", text, re.M)
    assert "To update" in text
