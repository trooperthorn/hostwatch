"""Fixtures build fake sysfs/procfs trees so collectors are tested against
known values without real hardware."""

from __future__ import annotations

from pathlib import Path

import pytest


def write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


@pytest.fixture
def fs(tmp_path):
    sysfs, procfs = tmp_path / "sys", tmp_path / "proc"
    sysfs.mkdir(); procfs.mkdir()
    return sysfs, procfs, write


@pytest.fixture(autouse=True)
def _agent_platform_is_not_the_test_host(request, monkeypatch):
    """The agent tests build fake Linux trees. Without this, an Agent built on a Windows developer
    machine detects the platform windows and reports the Linux sources not present. A test that
    wants the Windows agent passes platform="windows" explicitly."""
    if request.node.get_closest_marker("real_platform"):
        return
    import hostwatch.agent as agent_module
    monkeypatch.setattr(agent_module, "detect_platform", lambda *args, **kwargs: "x86")


def pytest_configure(config):
    config.addinivalue_line("markers", "real_platform: use the real detect_platform instead of the Linux stand-in")


@pytest.fixture(autouse=True)
def _control_file_owner_is_the_test_user(monkeypatch):
    """control.toml must be root-owned in production. Tests write it as the current user, so that
    user is trusted here. The owner tests set the trusted list back to root alone."""
    import os
    if os.name != "posix":
        return
    import hostwatch.control.config as control_config
    monkeypatch.setattr(control_config, "TRUSTED_UIDS", (0, os.getuid()))
