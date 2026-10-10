# Changelog

Entries are grouped by version and describe what changed and why. Dates are the day the change landed.

## 0.2.0 (2026-10-10)

- New control action `agent.update` for hostwatch-control on Linux. `component` is `agent`, `control` or `all`.
  `agent` pulls `ghcr.io/trooperthorn/hostwatch:edge` and, when the image id changed, recreates the
  `hostwatch-agent` container with the Observe installer's arguments read back from `docker inspect` (the env
  file is given by path, so the ingest key never passes through the daemon), keeping the old container as
  `hostwatch-agent-prev` until the new one runs and restoring it when the new one fails. An unchanged image is
  reported `done` with `already current`. `control` pip-upgrades the daemon's venv from git, reports the old and
  new versions, and has systemd restart the unit five seconds after the result is reported. The result output
  is JSON with `component`, `old_image_id`, `new_image_id`, `old_version`, `new_version` and `note`.
- `control.toml` gains the `[update]` stanza with `agent` and `control` flags; both default to false, and a
  refusal names the flag that is false.
- `render_sudoers` renders the docker, pip and systemd-run rules for the update only when the matching flag is
  true, with sudo's escapes for the image tag and the pip spec. `deploy/hostwatch-control.sudoers` and the
  example config now show them, and `deploy/hostwatch-control.service` opens the venv in `ReadWritePaths`
  for the pip run.
- `ActionResult` gains `after_report`, a step the daemon runs once the result has been queued and sent. Only
  the control update uses it.
- The Windows control executor refuses `agent.update` with a plain reason; the services there are updated by
  the installers.
- Package version 0.2.0.
