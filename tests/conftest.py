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


def trust_the_test_user_as_control_file_owner(monkeypatch, probe):
    """Trust whoever owns `probe` as the owner of control.toml. On Windows with pywin32 importable the real
    owner SID of the probe is added to the trusted list. Without pywin32 the check is advisory and there
    is nothing to widen. POSIX trusts the current uid. The owner check itself is untouched."""
    import os
    import hostwatch.control.config as control_config
    if os.name == "posix":
        monkeypatch.setattr(control_config, "TRUSTED_UIDS", (0, os.getuid()))
        return
    try:
        sid = control_config._windows_owner_sid(probe)
    except OSError:
        return
    if sid is not None:
        monkeypatch.setattr(control_config, "WINDOWS_TRUSTED_SIDS", (*control_config.WINDOWS_TRUSTED_SIDS, sid))


@pytest.fixture(autouse=True)
def _control_file_owner_is_the_test_user(monkeypatch, tmp_path_factory):
    """control.toml must be root-owned (SYSTEM or Administrators on Windows) in production. Tests write
    it as the current user, so that user is trusted here by adding to the trusted list. The owner check
    itself is untouched, and the owner tests set the trusted list back to the production value."""
    trust_the_test_user_as_control_file_owner(monkeypatch, tmp_path_factory.getbasetemp())
