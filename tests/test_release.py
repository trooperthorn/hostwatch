"""Release hygiene: the image installs only from the hash-locked dependency list."""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _name(requirement: str) -> str:
    match = re.match(r"[A-Za-z0-9_.\-]+", requirement)
    assert match, requirement
    return re.sub(r"[-_.]+", "-", match.group(0)).lower()


def _lock_entries() -> dict:
    """Map each locked package name to (version, list of sha256 hashes)."""
    text = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    text = text.replace("\\r\n", "\\n")
    entries = {}
    for block in re.split(r"\n(?=[A-Za-z0-9])", text):
        match = re.match(r"([A-Za-z0-9_.\-]+)==([^\s;\\]+)", block)
        if match:
            hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", block)
            entries[_name(match.group(1))] = (match.group(2), hashes)
    return entries


def test_every_runtime_dependency_is_pinned_in_the_lock():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    entries = _lock_entries()
    assert entries
    for requirement in project["project"]["dependencies"]:
        assert _name(requirement) in entries, requirement


def test_every_lock_entry_has_a_sha256_hash():
    for name, (version, hashes) in _lock_entries().items():
        assert version, name
        assert hashes, name


def test_lock_lines_use_exact_pins_only():
    for line in (ROOT / "requirements.lock").read_text(encoding="utf-8").splitlines():
        if line and line[0].isalnum():
            assert re.match(r"[A-Za-z0-9_.\-]+(\[[^\]]*\])?==\S+", line), line


def test_dockerfile_installs_from_the_lock_with_hashes_required():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY requirements.lock" in text
    assert "pip install --require-hashes --no-cache-dir -r requirements.lock" in text
    assert "--no-deps" in text
    assert text.index("--require-hashes") < text.index("--no-deps")
