"""Documentation checks: the threat model labels every control, and the quick start names only real things."""
import argparse
import re
from pathlib import Path

from hostwatch import cli

ROOT = Path(__file__).resolve().parent.parent
LABELS = ("enforced", "advisory", "planned")


def _quick_start() -> str:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    start = text.index("## Quick start")
    end = text.index("\n## ", start + 1)
    return text[start:end]


def _choices(parser: argparse.ArgumentParser) -> dict:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    return {}


def test_threat_model_exists_and_has_the_required_sections():
    text = (ROOT / "docs" / "THREAT-MODEL.md").read_text(encoding="utf-8")
    for heading in ("## Assets", "## Trust boundaries", "## Threats and controls", "## Residual risks"):
        assert heading in text, heading
    for name in ("host", "container", "hub", "agent", "LAN", "Home Assistant", "Orion", "MQTT", "NUT"):
        assert name.lower() in text.lower(), name
    for risk in ("RAPL", "plain HTTP", "shared token"):
        assert risk.lower() in text.lower(), risk


def test_every_control_line_has_exactly_one_label():
    lines = [ln for ln in (ROOT / "docs" / "THREAT-MODEL.md").read_text(encoding="utf-8").splitlines()
             if ln.startswith("- Control")]
    assert len(lines) >= 20
    seen = set()
    for line in lines:
        match = re.match(r"- Control \[(enforced|advisory|planned)\]: \S", line)
        assert match, line
        seen.add(match.group(1))
    assert seen == set(LABELS)


def test_quick_start_steps_are_numbered_in_order():
    numbers = [int(m.group(1)) for m in re.finditer(r"^(\d+)\. \*\*", _quick_start(), re.M)]
    assert numbers == list(range(1, len(numbers) + 1))
    assert len(numbers) >= 9


def test_quick_start_uses_only_cli_commands_that_exist():
    top = _choices(cli._parser())
    found = re.findall(r"python -m hostwatch ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?", _quick_start())
    assert found
    for command, action in found:
        assert command in top, command
        sub = _choices(top[command])
        if sub and action:
            assert action in sub, f"{command} {action}"


def test_quick_start_uses_only_known_environment_variables():
    sources = []
    for path in list((ROOT / "hostwatch").rglob("*.py")) + [ROOT / "deploy" / "docker-compose.yml",
                                                          ROOT / "deploy" / ".env.example"]:
        sources.append(path.read_text(encoding="utf-8"))
    known = "\n".join(sources)
    names = set(re.findall(r"HOSTWATCH_[A-Z0-9_]+", _quick_start()))
    assert {"HOSTWATCH_RAPL_GID", "HOSTWATCH_JOURNAL_GID", "HOSTWATCH_ROLE"} <= names
    for name in names:
        assert name in known, name


def test_quick_start_scripts_and_files_exist():
    section = _quick_start()
    for rel in set(re.findall(r"\./(scripts/[\w.\-]+)", section)) | {"deploy/.env.example"}:
        assert (ROOT / rel).is_file(), rel
