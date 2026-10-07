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



def find_bash():
    """A real bash. On Windows the System32 bash.exe is the WSL launcher, which fails
    without a distribution installed, so Git Bash is preferred there."""
    if sys.platform != "win32":
        return shutil.which("bash")
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"):
        if os.path.exists(candidate):
            return candidate
    found = shutil.which("bash")
    if found and "system32" in found.lower():
        pytest.skip("only the WSL bash launcher is on PATH")
    return found

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
    bash = find_bash()
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
    assert "HOSTWATCH_ROLE" not in service["environment"]  # the agent is the only role
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
    for command, action in re.findall(r"python -m hostwatch ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?", text):
        if command in ("healthcheck", "collect-once"):
            continue
        assert command in top, command
        if sub(top[command]) and action:
            assert action in sub(top[command]), f"{command} {action}"
    for rel in set(re.findall(r"`((?:deploy/truenas|docs)/[\w./\-]+\.(?:md|sh|yaml))`", text)):
        assert (ROOT / rel).is_file(), rel
    for needle in ("TrueNAS-SVR", "READONLY_ADMIN", "HOSTWATCH_OBSERVE_URL", "HOSTWATCH_INGEST_KEY"):
        assert needle in text, needle


PSTORE_SCRIPT = ROOT / "scripts" / "pstore-access.sh"


def test_pstore_access_dry_run_plans_only_pstore_chgrp_and_chmod(tmp_path):
    pstore = tmp_path / "fake-root" / "sys" / "fs" / "pstore"
    pstore.mkdir(parents=True)
    (pstore / "dmesg-efi_pstore-1").write_text("Panic#1 Part1\n")
    bash = find_bash()
    assert bash
    result = subprocess.run([bash, PSTORE_SCRIPT.as_posix(), "--dry-run"], capture_output=True, text=True,
                            timeout=30, env={**ENV, "HOSTWATCH_PSTORE_DIR": pstore.as_posix()})
    assert result.returncode == 0, result.stderr
    planned = [ln[len("would run: "):] for ln in result.stdout.splitlines() if ln.startswith("would run: ")]
    file_changes = [c for c in planned if c.startswith(("chgrp", "chmod"))]
    assert any(c.startswith("chgrp hostwatch-rapl") for c in file_changes)
    assert any(c.startswith("chmod g+rx") for c in file_changes)
    assert any(c.startswith("chmod g+r ") and "dmesg-efi_pstore-1" in c for c in file_changes)
    for c in file_changes:
        assert pstore.as_posix() in c, c
        assert c.split()[0] == "chgrp" or c.split()[1] in ("g+r", "g+rx"), c
    others = [c for c in planned if c not in file_changes]
    for c in others:
        assert c.startswith(("getent group", "systemctl daemon-reload")), c
    assert not any(w in result.stdout for w in ("rm -", "chown", "0777", "o+r", "g+w"))
    assert (pstore / "dmesg-efi_pstore-1").read_text() == "Panic#1 Part1\n"


def test_pstore_unit_orders_after_the_pstore_mount_and_never_grants_write():
    text = PSTORE_SCRIPT.read_text(encoding="utf-8")
    assert "After=sys-fs-pstore.mount" in text
    assert "chmod g+rx /sys/fs/pstore" in text and "chmod g+r " in text
    assert "g+w" not in text and "chmod 0777" not in text
    assert chr(0x2014) not in text


def test_pstore_unit_is_skipped_not_failed_without_a_mount_unit():
    text = PSTORE_SCRIPT.read_text(encoding="utf-8")
    assert "Requires=sys-fs-pstore.mount" not in text
    assert "ConditionPathIsDirectory=/sys/fs/pstore" in text


def test_pstore_script_is_executable_in_git():
    out = subprocess.run(["git", "ls-files", "-s", "scripts/pstore-access.sh"], cwd=ROOT,
                         capture_output=True, text=True).stdout
    assert out.startswith("100755"), out


def test_truenas_postinit_pstore_section_plans_and_checks_modes(tmp_path):
    pstore = tmp_path / "pstore"
    pstore.mkdir()
    (pstore / "dmesg-1").write_text("x")
    sh = find_bash()
    result = subprocess.run([sh, (ROOT / "deploy" / "truenas" / "rapl-postinit.sh").as_posix(), "--dry-run"],
                            capture_output=True, text=True, timeout=30,
                            env={**ENV, "RAPL_PSTORE_DIR": pstore.as_posix(),
                                 "RAPL_POWERCAP_DIR": (tmp_path / "none").as_posix()})
    assert result.returncode == 0, result.stderr
    assert f"would grant: {pstore.as_posix()}" in result.stdout
    assert f"would grant: {pstore.as_posix()}/dmesg-1" in result.stdout
    assert "g+rx" in (ROOT / "deploy" / "truenas" / "rapl-postinit.sh").read_text(encoding="utf-8")


def test_docs_reference_the_pstore_script():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "scripts/pstore-access.sh" in readme and "ls -ld /sys/fs/pstore" in readme
    assert "pstore-access.sh" in (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "pstore-access.sh" in (ROOT / "UNVERIFIED.md").read_text(encoding="utf-8")
    assert "pstore" in (ROOT / "deploy" / "truenas" / "rapl-postinit.sh").read_text(encoding="utf-8")
