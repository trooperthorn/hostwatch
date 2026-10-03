"""The remote agent compose file and the multi-host guide stay safe and name only real things."""
import re
from pathlib import Path

from hostwatch import cli
from test_truenas_deploy import _parse

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "deploy" / "agent" / "docker-compose.yml"
EXAMPLE = ROOT / "deploy" / "agent" / ".env.example"
DOC = ROOT / "docs" / "deploy-agents.md"


def _service() -> dict:
    return _parse(COMPOSE.read_text(encoding="utf-8"))["services"]["hostwatch-agent"]


def test_agent_compose_has_the_container_limits():
    service = _service()
    assert service["read_only"] is True
    assert service.get("privileged") is not True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    uid, _, gid = str(service["user"]).partition(":")
    assert uid.isdigit() and int(uid) > 0 and gid.isdigit() and int(gid) > 0
    assert service["network_mode"] == "host"
    assert service["environment"]["HOSTWATCH_ROLE"] == "agent"
    assert service["env_file"] == ".env"


def test_agent_compose_mounts_are_read_only_except_the_data_volume():
    writable = []
    for volume in _service()["volumes"]:
        source = volume.partition(":")[0]
        assert source != "/proc" and not source.startswith("/proc/"), volume
        if not volume.endswith(":ro"):
            writable.append(volume)
    assert len(writable) == 1 and writable[0].endswith(":/data")


def test_agent_compose_and_example_hold_no_secret_values():
    text = COMPOSE.read_text(encoding="utf-8") + EXAMPLE.read_text(encoding="utf-8")
    assert not re.search(r"hw_[0-9A-Za-z]{8,}", text)
    assert re.search(r"^HOSTWATCH_INGEST_KEY=$", text, re.M)
    assert not re.search(r"^\s*HOSTWATCH_INGEST_(KEY|TOKEN)\s*:", text, re.M)
    assert "deploy/agent/.env" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()


def test_guide_names_only_real_settings_commands_and_files():
    text = DOC.read_text(encoding="utf-8")
    known = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "hostwatch").rglob("*.py")) + COMPOSE.read_text(encoding="utf-8")
    for name in set(re.findall(r"HOSTWATCH_[A-Z0-9_]+", text + EXAMPLE.read_text(encoding="utf-8"))):
        assert name in known, name
    top = next(a.choices for a in cli._parser()._actions if a.__class__.__name__ == "_SubParsersAction")
    found = re.findall(r"python -m hostwatch ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?", text)
    assert found
    for command, action in found:
        assert command in top, command
        subs = next((a.choices for a in top[command]._actions if a.__class__.__name__ == "_SubParsersAction"), {})
        if subs and action:
            assert action in subs, f"{command} {action}"
    for rel in set(re.findall(r"`((?:deploy/[\w./\-]+|docs/[\w./\-]+)\.(?:md|sh|yaml|yml))`", text)):
        assert (ROOT / rel).is_file(), rel
    for needle in ("HOSTWATCH_ALLOWED_CLIENTS", "HOSTWATCH_HUB_BIND", "--scopes ingest,read:events", "ai-pi"):
        assert needle in text, needle
