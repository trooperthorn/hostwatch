"""The retired hub stays gone from the deploy files, the installers and the docs, and the Windows install
path points at Observe over the same OTLP settings as every other host."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RETIRED_SETTINGS = ("HOSTWATCH_ROLE", "HOSTWATCH_INTERVAL", "HOSTWATCH_INGEST_TOKEN", "HOSTWATCH_TLS",
                    "HOSTWATCH_MQTT", "HOSTWATCH_PROMETHEUS", "HOSTWATCH_BOOTSTRAP")
DEPLOY_FILES = [
    "deploy/.env.example", "deploy/agent/.env.example", "deploy/docker-compose.yml",
    "deploy/agent/docker-compose.yml", "deploy/truenas/compose.yaml", "deploy/windows/install.ps1",
    "deploy/windows/uninstall.ps1", "Dockerfile",
]


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


@pytest.mark.parametrize("rel", DEPLOY_FILES)
def test_deploy_files_name_no_retired_setting(rel):
    text = _text(rel)
    for name in RETIRED_SETTINGS:
        assert name not in text, (rel, name)


@pytest.mark.parametrize("rel", ["deploy/docker-compose.yml", "deploy/agent/docker-compose.yml",
                                 "deploy/truenas/compose.yaml"])
def test_compose_files_open_no_port_and_set_the_observe_destination(rel):
    text = _text(rel)
    assert not re.search(r"^\s*ports:", text, re.M), rel
    assert not re.search(r"^\s*(?:-\s*)?['\"]?\d{2,5}:\d{2,5}", text, re.M), rel


@pytest.mark.parametrize("rel", ["deploy/.env.example", "deploy/agent/.env.example"])
def test_env_examples_set_the_observe_settings(rel):
    text = _text(rel)
    assert re.search(r"^HOSTWATCH_OBSERVE_URL=", text, re.M), rel
    assert re.search(r"^HOSTWATCH_INGEST_KEY=$", text, re.M), rel


def test_no_web_ui_or_hub_module_remains_in_the_package():
    package = ROOT / "hostwatch"
    for retired in ("hub.py", "web", "static", "templates", "integrations", "witness", "witnesses", "db.py"):
        assert not (package / retired).exists(), retired
    source = "\n".join(p.read_text(encoding="utf-8") for p in package.rglob("*.py"))
    for module in ("fastapi", "uvicorn", "argon2", "paho"):
        assert not re.search(rf"^\s*(?:import|from)\s+{module}\b", source, re.M), module


def test_windows_installer_writes_the_observe_settings_only():
    script = _text("deploy/windows/install.ps1")
    for name in ("HOSTWATCH_OBSERVE_URL", "HOSTWATCH_INGEST_KEY", "HOSTWATCH_HOST_NAME"):
        assert name in script, name
    assert "Hub" not in script.replace("Alias('HubUrl')", "")


def test_unverified_lists_the_windows_agent_and_the_stale_lock():
    text = _text("UNVERIFIED.md")
    assert "hostwatch-agent" in text and "requirements.lock" in text


def test_docs_describe_the_agent_as_otlp_only():
    for rel in ("README.md", "docs/ARCHITECTURE.md", "docs/deploy-agents.md"):
        text = _text(rel)
        assert "OTLP" in text and "Observe" in text, rel
