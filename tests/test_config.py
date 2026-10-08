"""Config defaults, validation and the read-only property of the compose mounts."""

from __future__ import annotations

from pathlib import Path

import pytest

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


def _group_add() -> list[str]:
    items, inside = [], False
    for line in COMPOSE.read_text().splitlines():
        if line.startswith("    group_add:"):
            inside = True
            continue
        if inside:
            stripped = line.strip()
            if stripped.startswith("- "):
                items.append(stripped[2:].strip())
            elif stripped and not stripped.startswith("#"):
                break
    return items


def test_group_add_has_journal_gid_and_host_mounts_stay_read_only():
    assert any("HOSTWATCH_JOURNAL_GID" in item for item in _group_add())
    host_mounts = [v for v in _volumes() if v.startswith("/")]
    assert host_mounts
    assert all(v.endswith(":ro") for v in host_mounts)


def test_env_example_documents_journal_gid():
    text = ENV_EXAMPLE.read_text()
    assert "HOSTWATCH_JOURNAL_GID" in text and "getent group systemd-journal" in text


def test_dockerfile_creates_owned_data_dir():
    text = (Path(__file__).resolve().parent.parent / "Dockerfile").read_text()
    assert "mkdir /data" in text and "chown 10001:10001 /data" in text
    assert text.index("chown 10001:10001 /data") < text.index("USER hostwatch")


def test_compose_tests_do_not_depend_on_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert COMPOSE.is_file() and ENV_EXAMPLE.is_file()


# Settings for Observe.

URL = "http://observe.test"


def _valid(**kw) -> Config:
    base = dict(observe_url=URL, ingest_key="k" * 24)
    base.update(kw)
    return Config(**base)


def test_a_complete_configuration_validates():
    _valid().validate()


@pytest.mark.parametrize("url", ["", "ftp://observe.test", "observe.test", "http://"])
def test_a_missing_or_malformed_url_is_refused(url):
    with pytest.raises(ValueError, match="HOSTWATCH_OBSERVE_URL"):
        _valid(observe_url=url).validate()


def test_a_missing_ingest_key_is_refused_and_named():
    with pytest.raises(ValueError, match="HOSTWATCH_INGEST_KEY"):
        _valid(ingest_key="").validate()


def test_an_unknown_format_is_refused():
    with pytest.raises(ValueError, match="HOSTWATCH_OTLP_FORMAT"):
        _valid(otlp_format="xml").validate()
    _valid(otlp_format="json").validate()


def test_the_url_comes_from_the_preferred_name_then_the_alias_and_loses_a_trailing_slash(monkeypatch):
    monkeypatch.delenv("HOSTWATCH_OBSERVE_URL", raising=False)
    monkeypatch.delenv("HOSTWATCH_HUB_URL", raising=False)
    assert Config().observe_url == ""
    monkeypatch.setenv("HOSTWATCH_HUB_URL", "http://alias.test/")
    assert Config().observe_url == "http://alias.test"
    monkeypatch.setenv("HOSTWATCH_OBSERVE_URL", "https://preferred.test")
    assert Config().observe_url == "https://preferred.test"


def test_format_and_compression_defaults(monkeypatch):
    monkeypatch.delenv("HOSTWATCH_OTLP_FORMAT", raising=False)
    monkeypatch.delenv("HOSTWATCH_OTLP_GZIP", raising=False)
    cfg = Config()
    assert cfg.otlp_format == "json" and cfg.otlp_gzip is True
    monkeypatch.setenv("HOSTWATCH_OTLP_FORMAT", " JSON ")
    monkeypatch.setenv("HOSTWATCH_OTLP_GZIP", "off")
    cfg = Config()
    assert cfg.otlp_format == "json" and cfg.otlp_gzip is False


def test_the_key_never_appears_in_the_repr():
    assert "kkkkkkkkkkkkkkkkkkkkkkkk" not in repr(_valid())


BOOL_VARS = (("HOSTWATCH_OTLP_GZIP", "otlp_gzip"), ("HOSTWATCH_TRUENAS_INSECURE", "truenas_insecure"))


@pytest.mark.parametrize("var,attr", BOOL_VARS)
@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "Yes", "on", "ON", " true "])
def test_bool_true_spellings(monkeypatch, var, attr, raw):
    monkeypatch.setenv(var, raw)
    assert getattr(Config(), attr) is True


@pytest.mark.parametrize("var,attr", BOOL_VARS)
@pytest.mark.parametrize("raw", ["0", "false", "FALSE", "No", "off", "OFF", ""])
def test_bool_false_spellings(monkeypatch, var, attr, raw):
    monkeypatch.setenv(var, raw)
    assert getattr(Config(), attr) is False


@pytest.mark.parametrize("var,attr", BOOL_VARS)
def test_bool_invalid_value_names_variable(monkeypatch, var, attr):
    monkeypatch.setenv(var, "maybe")
    with pytest.raises(ValueError, match=var):
        Config()


def test_env_example_documents_spellings():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    for word in ("true", "yes", "on", "false", "no", "off"):
        assert word in text
