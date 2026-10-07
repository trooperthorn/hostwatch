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
    for name in ("host", "container", "Observe", "agent", "LAN", "NUT", "TrueNAS"):
        assert name.lower() in text.lower(), name
    for risk in ("RAPL", "plain HTTP", "outbox"):
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
    assert len(numbers) >= 7


def test_quick_start_uses_only_cli_commands_that_exist():
    top = _choices(cli._parser())
    found = re.findall(r"python -m hostwatch ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?", _quick_start())
    for command, action in found:
        if command in ("healthcheck", "collect-once"):
            continue
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
    assert {"HOSTWATCH_RAPL_GID", "HOSTWATCH_JOURNAL_GID", "HOSTWATCH_OBSERVE_URL", "HOSTWATCH_INGEST_KEY"} <= names
    for name in names:
        assert name in known, name


def test_quick_start_scripts_and_files_exist():
    section = _quick_start()
    for rel in set(re.findall(r"\./(scripts/[\w.\-]+)", section)) | {"deploy/.env.example"}:
        assert (ROOT / rel).is_file(), rel


def test_the_readme_names_no_retired_component_as_current():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for retired in ("HOSTWATCH_ROLE", "bootstrap-admin", "/internal/v1/" + "ingest", "HOSTWATCH_INGEST_TOKEN"):
        assert retired not in text, retired


def test_the_healthcheck_reads_the_agent_liveness_marker(tmp_path):
    import time

    from hostwatch.__main__ import ALIVE_MAX_AGE_S, healthcheck
    from hostwatch.agent import ALIVE_FILE
    from hostwatch.config import Config

    cfg = Config(data_dir=tmp_path)
    assert healthcheck(cfg) == 1  # no marker yet
    (tmp_path / ALIVE_FILE).write_text(str(time.time()), encoding="utf-8")
    assert healthcheck(cfg) == 0
    assert healthcheck(cfg, now=time.time() + ALIVE_MAX_AGE_S + 5) == 1
    (tmp_path / ALIVE_FILE).write_text("not a time", encoding="utf-8")
    assert healthcheck(cfg) == 1
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'CMD ["python", "-m", "hostwatch", "healthcheck"]' in dockerfile


def _dockerfile() -> str:
    return (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_main_dispatches_healthcheck(monkeypatch):
    from hostwatch.__main__ import main

    monkeypatch.setattr("hostwatch.__main__.healthcheck", lambda cfg: 7)
    assert main(["healthcheck"]) == 7


def test_dockerfile_healthcheck_needs_no_curl():
    text = _dockerfile()
    assert re.search(r"^HEALTHCHECK .*--interval=\S+ .*--timeout=\S+ .*--retries=\d+", text, re.M)
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
