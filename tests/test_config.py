"""Config defaults and the read-only property of the compose mounts."""

from __future__ import annotations

from pathlib import Path

from hostwatch.config import Config

COMPOSE = Path(__file__).resolve().parent.parent / "deploy" / "docker-compose.yml"
ENV_EXAMPLE = COMPOSE.parent / ".env.example"


def _volumes() -> list[str]:
    """Return the list items under the service volumes key, without a YAML parser."""
    items, inside = [], False
    for line in COMPOSE.read_text().splitlines():
        if line.startswith("    volumes:"):
            inside = True
            continue
        if inside:
            stripped = line.strip()
            if stripped.startswith("- "):
                items.append(stripped[2:].strip())
            elif stripped and not stripped.startswith("#"):
                break
    return items


def test_event_source_defaults(monkeypatch):
    for name in ("HOSTWATCH_JOURNAL", "HOSTWATCH_JOURNAL_VOLATILE", "HOSTWATCH_PSTORE", "HOSTWATCH_RASDAEMON_DB"):
        monkeypatch.delenv(name, raising=False)
    cfg = Config()
    assert cfg.journal == Path("/host/journal")
    assert cfg.journal_volatile == Path("/host/journal-volatile")
    assert cfg.pstore == Path("/host/pstore")
    assert cfg.rasdaemon_db == Path("/host/rasdaemon/ras-mc_event.db")


def test_event_source_overrides(monkeypatch):
    monkeypatch.setenv("HOSTWATCH_JOURNAL", "/x/j")
    monkeypatch.setenv("HOSTWATCH_PSTORE", "/x/p")
    monkeypatch.setenv("HOSTWATCH_RASDAEMON_DB", "/x/r.db")
    cfg = Config()
    assert (cfg.journal, cfg.pstore, cfg.rasdaemon_db) == (Path("/x/j"), Path("/x/p"), Path("/x/r.db"))


def test_every_host_mount_is_read_only():
    bind = [v for v in _volumes() if v.startswith("/")]
    sources = {v.split(":")[0] for v in bind}
    assert {"/sys", "/var/log/journal", "/run/log/journal", "/sys/fs/pstore", "/var/lib/rasdaemon"} <= sources
    for v in bind:
        assert v.endswith(":ro"), v


def test_host_proc_is_not_mounted():
    for v in _volumes():
        source = v.split(":")[0]
        assert source != "/proc", v
        assert not source.startswith("/proc/"), v


def test_mount_points_match_config_defaults(monkeypatch):
    for name in ("HOSTWATCH_JOURNAL", "HOSTWATCH_JOURNAL_VOLATILE", "HOSTWATCH_PSTORE", "HOSTWATCH_RASDAEMON_DB"):
        monkeypatch.delenv(name, raising=False)
    targets = {v.split(":")[1] for v in _volumes() if v.startswith("/")}
    cfg = Config()
    assert cfg.journal.as_posix() in targets
    assert cfg.journal_volatile.as_posix() in targets
    assert cfg.pstore.as_posix() in targets
    assert cfg.rasdaemon_db.parent.as_posix() in targets


def test_no_privileged_or_capabilities_added():
    text = COMPOSE.read_text()
    assert "privileged" not in text.replace("no-new-privileges", "")
    assert "cap_add" not in text


def test_env_example_lists_event_variables():
    text = ENV_EXAMPLE.read_text()
    for name in ("HOSTWATCH_JOURNAL", "HOSTWATCH_JOURNAL_VOLATILE", "HOSTWATCH_PSTORE", "HOSTWATCH_RASDAEMON_DB"):
        assert name in text
