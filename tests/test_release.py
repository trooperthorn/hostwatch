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


# CI workflow supply chain checks. PyYAML is not a dependency, so these read the text.

WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _jobs() -> dict:
    """Split the jobs block into {name: text} at the two-space job keys."""
    block = _workflow().split("\njobs:\n", 1)[1]
    parts = re.split(r"\n(?=  [a-z][a-z0-9_-]*:\n)", "\n" + block)
    jobs = {}
    for part in parts:
        match = re.match(r"\s*([a-z][a-z0-9_-]*):\n", part)
        if match:
            jobs[match.group(1)] = part
    return jobs


def test_workflow_is_structurally_valid():
    text = _workflow()
    assert "\t" not in text
    assert re.search(r"^name: ci$", text, re.M)
    assert re.search(r"^on:$", text, re.M)
    assert set(_jobs()) == {"test", "build", "scan", "smoke", "image", "release"}
    for name, job in _jobs().items():
        assert "runs-on:" in job, name


def test_every_action_is_pinned_to_a_full_commit_sha():
    uses = re.findall(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$", _workflow(), re.M)
    assert uses
    for ref, rest in uses:
        assert re.fullmatch(r"[\w.\-]+/[\w.\-/]+@[0-9a-f]{40}", ref), ref
        assert re.search(r"#\s*v\d", rest), f"{ref} needs a version comment"


def test_trivy_gate_is_critical_and_fails_the_job():
    scan = _jobs()["scan"]
    # The first trivy step only prints a readable table; the last one is the gate.
    step = scan.rsplit("aquasecurity/trivy-action@", 1)[1].split("\n      - ", 1)[0]
    assert re.search(r"severity:\s*CRITICAL\s*$", step, re.M)
    assert re.search(r'exit-code:\s*"1"', step)
    assert re.search(r"ignore-unfixed:\s*true", step)
    assert "upload-sarif@" in scan


def test_only_the_scan_job_may_write_security_events():
    for name, job in _jobs().items():
        if name == "scan":
            assert "security-events: write" in job
        else:
            assert "security-events" not in job, name
    assert "security-events" not in _workflow().split("\njobs:\n", 1)[0].split("\nname: ci", 1)[1]


def test_sbom_is_spdx_and_attached_to_the_release():
    assert "format: spdx-json" in _jobs()["scan"]
    release = _jobs()["release"]
    assert "hostwatch-sbom" in release
    assert "hostwatch.spdx.json" in release


def test_smoke_job_runs_the_agent_read_only_and_never_echoes_secrets():
    smoke = _jobs()["smoke"]
    assert "HOSTWATCH_OBSERVE_URL=" in smoke and "HOSTWATCH_INGEST_KEY=" in smoke
    assert "--tmpfs /data" in smoke and "--read-only" in smoke and "--cap-drop ALL" in smoke
    assert "python -m hostwatch healthcheck" in smoke
    assert "0.0.0.0" not in smoke and "-p 8090" not in smoke
    assert 'echo "::add-mask::$ingest_key"' in smoke
    for line in smoke.splitlines():
        if re.match(r"\s*echo\b", line) and "::add-mask::" not in line:
            assert not re.search(r"\$\{?ingest_key\b", line), line
    assert "set -x" not in smoke and "bash -x" not in smoke


def test_release_job_is_gated_on_version_tags():
    jobs = _jobs()
    release = jobs["release"]
    assert "if: startsWith(github.ref, 'refs/tags/v')" in release
    assert "contents: write" in release
    for name in ("test", "build", "scan", "smoke", "image"):
        assert "contents: write" not in jobs[name], name
    assert 'tags: ["v*"]' in _workflow()


def test_image_publish_passes_version_and_revision_and_keeps_edge():
    image = _jobs()["image"]
    assert "type=edge,branch=master" in image
    assert "type=semver,pattern={{version}}" in image
    assert "VERSION=${{ steps.meta.outputs.version }}" in image
    assert "REVISION=${{ github.sha }}" in image
    assert "needs: [test, scan, smoke]" in image
