"""The TrueNAS custom app file, the Post Init script and the deploy guide stay safe and truthful."""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from hostwatch import cli

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "deploy" / "truenas" / "compose.yaml"
SCRIPT = ROOT / "deploy" / "truenas" / "rapl-postinit.sh"
DOC = ROOT / "docs" / "deploy-truenas.md"
ENV = {"PATH": "/usr/bin:/bin"}


def _parse(text: str) -> dict:
    """Parse the YAML subset the compose file uses: nested maps, scalar lists and scalars."""
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            lines.append((len(raw) - len(raw.lstrip()), stripped))

    def scalar(value: str):
        value = value.strip().strip('"')
        return {"true": True, "false": False}.get(value, value)

    def block(i: int, indent: int):
        if lines[i][1].startswith("- "):
            items = []
            while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
                items.append(scalar(lines[i][1][2:]))
                i += 1
            return items, i
        out = {}
        while i < len(lines) and lines[i][0] == indent:
            key, _, rest = lines[i][1].partition(":")
            i += 1
            if rest.strip():
                out[key] = scalar(rest)
            elif i < len(lines) and lines[i][0] > indent:
                out[key], i = block(i, lines[i][0])
            else:
                out[key] = None
        return out, i

    return block(0, lines[0][0])[0]


def _run(*args, powercap: Path):
    bash = shutil.which("bash")
    assert bash, "bash is required to run the Post Init script test"
    return subprocess.run([bash, SCRIPT.as_posix(), *args], capture_output=True, text=True, timeout=30,
                          env={**ENV, "RAPL_POWERCAP_DIR": powercap.as_posix()})


@pytest.fixture(scope="module")
def service() -> dict:
    return _parse(COMPOSE.read_text(encoding="utf-8"))["services"]["hostwatch"]


def test_compose_has_the_container_limits(service):
    assert service["read_only"] is True
    assert service.get("privileged") is not True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    uid, _, gid = str(service["user"]).partition(":")
    assert uid.isdigit() and int(uid) > 0 and gid.isdigit() and int(gid) > 0
    assert service["network_mode"] == "host"
    assert service["environment"]["HOSTWATCH_ROLE"] == "agent"
    assert "102" in service["group_add"]


def test_compose_host_mounts_are_read_only_except_the_data_dataset(service):
    writable = []
    for volume in service["volumes"]:
        source = volume.partition(":")[0]
        assert source != "/proc" and not source.startswith("/proc/"), volume
        if not volume.endswith(":ro"):
            writable.append(volume)
    assert len(writable) == 1 and writable[0].endswith(":/data")
    assert any(v.startswith("/sys:") and v.endswith(":ro") for v in service["volumes"])


def test_compose_holds_no_secret_values(service):
    for name, value in service["environment"].items():
        if re.search(r"KEY|TOKEN|PASSWORD|SECRET", name):
            assert name.endswith("_FILE"), name
            assert str(value).startswith("/secrets/"), name
    text = COMPOSE.read_text(encoding="utf-8")
    assert not re.search(r"hw_[0-9A-Za-z]{8,}", text)
    assert not re.search(r"^\s*HOSTWATCH_INGEST_(KEY|TOKEN)\s*:", text, re.M)
    assert service["env_file"] == ["/mnt/Apps/hostwatch/agent.env"]


def test_script_never_removes_anything_and_changes_only_energy_files():
    text = SCRIPT.read_text(encoding="utf-8")
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"\brm\b|\brmdir\b|\bunlink\b|groupdel", code)
    for line in code.splitlines():
        if re.search(r"\b(chmod|chgrp)\b", line):
            assert '"$f"' in line, line
    assert 'BASE="${RAPL_POWERCAP_DIR:-/sys/class/powercap}"' in text
    assert "intel-rapl:*/energy_uj" in text
    for word in ("--dry-run", "--apply", "PLATYPUS", "idempotent"):
        assert word in text, word


def test_script_defaults_to_dry_run_without_root(tmp_path):
    for args in ((), ("--dry-run",)):
        result = _run(*args, powercap=tmp_path)
        assert result.returncode == 0, result.stderr
        assert "Dry run" in result.stdout
        assert "no energy_uj files" in result.stdout
    assert _run("--bogus", powercap=tmp_path).returncode == 2


@pytest.mark.skipif(sys.platform == "win32", reason="the fake zone directory name contains a colon")
def test_script_dry_run_leaves_the_tree_unchanged(tmp_path):
    zone = tmp_path / "intel-rapl:0"
    zone.mkdir()
    energy = zone / "energy_uj"
    energy.write_text("1\n")
    before = energy.stat().st_mode
    result = _run(powercap=tmp_path)
    assert result.returncode == 0
    assert f"would grant: {energy.as_posix()}" in result.stdout
    assert energy.stat().st_mode == before


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_script_apply_refuses_without_root(tmp_path):
    result = _run("--apply", powercap=tmp_path)
    assert result.returncode == 2 and "must run as root" in result.stderr


def test_guide_names_only_real_settings_commands_and_files():
    text = DOC.read_text(encoding="utf-8")
    known = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "hostwatch").rglob("*.py"))
    for name in set(re.findall(r"HOSTWATCH_[A-Z0-9_]+", text)):
        assert name in known, name

    def sub(parser):
        for action in parser._actions:
            if action.__class__.__name__ == "_SubParsersAction":
                return action.choices
        return {}

    top = sub(cli._parser())
    found = re.findall(r"python -m hostwatch ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?", text)
    assert found
    for command, action in found:
        assert command in top, command
        if sub(top[command]) and action:
            assert action in sub(top[command]), f"{command} {action}"
    for rel in set(re.findall(r"`((?:deploy/truenas|docs)/[\w./\-]+\.(?:md|sh|yaml))`", text)):
        assert (ROOT / rel).is_file(), rel
    for needle in ("10.10.11.98", "HOSTWATCH_ALLOWED_CLIENTS", "READONLY_ADMIN", "HOSTWATCH_HUB_BIND"):
        assert needle in text, needle
