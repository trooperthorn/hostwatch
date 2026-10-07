# hostwatch: working contract for AI-assisted development

Read this file first. It is the authoritative guide for work in this repo.
`PLAN.md` holds the phased plan, `UNVERIFIED.md` the open assumptions, and
`docs/HANDOFF.md` the history and decisions behind the current state.

## What this project is

A host agent that collects power, crash, RAID and disk health from a host and sends it to Observe as
OpenTelemetry (OTLP) metrics and logs. The agent serves nothing and has no database of its own. One image
and one role. The hostwatch hub, its web UI, login, API keys, audit log, Home Assistant, Orion and Prometheus
outputs and the old batch wire format are retired: there is no migration path, and the owner destroys and
redeploys. `hostwatch-control` is a separate daemon, unchanged by that conversion.

## Current state

- The OTLP conversion is code complete and unit-tested (`pytest`): `hostwatch/otel_map.py` maps every collector
  to the names, units and attributes in the Observe data API design (sections 3.1 to 3.3 and 3.9),
  `hostwatch/otlp.py` is the hand-written protobuf and JSON encoder, `hostwatch/tiers.py` and
  `hostwatch/agent.py` schedule collectors by polling tier with rates fetched from Observe, send events at
  once as logs, and deliver from a durable outbox with `Idempotency-Key`s, partial success handling and
  dead-lettering. **Not yet deployed or verified against a running Observe or on real hardware**; see
  `UNVERIFIED.md`.
- The collectors and event sources (md, ZFS, TrueNAS, NUT, Scrutiny, hwmon, RAPL, rpi, thermalctl, the Windows
  set, boot classification, journal, pstore, rasdaemon, WHEA) are code complete and unit-tested. None is
  verified on TrueNAS-SVR, ai-pi or a Windows host.
- Environment: `HOSTWATCH_OBSERVE_URL` (alias `HOSTWATCH_HUB_URL`), `HOSTWATCH_INGEST_KEY` and
  `HOSTWATCH_HOST_NAME` are the settings every host needs.
- Next: deploy on MediaIn-SVR with a new ingest key, confirm the heartbeat and the sources in Observe, run the
  four boot and RAID scenarios in the README, and work through the open items in `UNVERIFIED.md`.

## Rules

1. **Never state a fact you have not looked up or measured.** Sysfs paths, API
   response shapes, driver names, and kernel behavior must be confirmed on the
   host before code depends on them. If you cannot confirm something, add it to
   `UNVERIFIED.md` with the exact command that would confirm it. Remove entries
   only after confirmation, and note what confirmed them in the commit message.
2. **Unavailable beats wrong.** A missing or unreadable source is reported
   unavailable with a reason. Never substitute zero or a guessed value.
3. **Run `pytest` before calling any change done.** New code paths need tests
   built on fake sysfs/procfs trees (see `tests/conftest.py`).
4. **Label security controls honestly.** In docs and comments, distinguish
   enforced controls from advisory or cosmetic ones. Do not present a bind
   address or obscurity as authentication.
5. **Destructive or system-changing scripts** default to read-only, support
   `--dry-run`, state consequences plainly, and confirm before acting
   (see `scripts/host-prep.sh`).
6. **House style for committed files:** complete sentences, explain why as well
   as what, no em dashes, no attribution footers or generation notices, no
   model names, no real credentials. Hostnames of the owner's own lab hosts are
   acceptable in `UNVERIFIED.md` and `docs/`.
7. **Open no port.** The agent only dials out. Do not add a listener, a debug endpoint or a status page.
   The ingest key goes only in the `Authorization` header and is never logged, stored in the outbox or put in
   a reason. The liveness check reads a marker file, not a socket.
8. **Do not mount the host `/proc`** into the container. The files read are
   system-wide from the container's own `/proc`.

## Commands

```
pip install -e '.[test]' && pytest                     # tests
python -m hostwatch collect-once                       # one pass, nothing sent (set HOSTWATCH_SYSFS=/sys outside Docker)
./scripts/host-prep.sh [--json]                        # Phase 0 check
cd deploy && sudo docker compose up -d --build         # deploy
```

## Target hosts

| Host | Facts confirmed on hardware |
|---|---|
| MediaIn-SVR | Debian 13, kernel 6.12 amd64; ASUS P8Z77-V LE PLUS, i5-3570K (Ivy Bridge); NCT6779D Super I/O via `nct6775` (loaded from `/etc/modules-load.d/hostwatch.conf`); iTCO_wdt watchdog, systemd `RuntimeWatchdogSec=30s`; efi_pstore backend; rasdaemon active; md127 RAID1 (sda + sdc, WD Red 1TB); boot SSD sdb (Patriot Blaze); Scrutiny v0.9.5-omnibus on host port 8081; Docker 29.8; kernel cmdline adds `pcie_aspm=off consoleblank=0 acpi_enforce_resources=lax` via `/etc/default/grub.d/hostwatch.cfg` |
| ai-pi | Raspberry Pi 5, Debian, arm64. Phase 0 not run. The `rpi` collector and the agent deploy in `deploy/agent/` exist but are unverified on the Pi; owner checks are in `UNVERIFIED.md`. |
| TrueNAS-SVR | TrueNAS 26.0.0-BETA.3, kernel 6.18 amd64; AMD Ryzen 5 3600, MSI MS-7C02, no ECC; ZFS pools Apps, Stash, Vault, boot-pool (no md); hwmon nvme, k10temp, drivetemp; RAPL zones present but `energy_uj` root-only; SP5100 TCO watchdog present but not armed (`RuntimeWatchdogUSec=0`); pstore empty; no rasdaemon; journal group `systemd-journal` gid 102; Docker 29.0.4; Scrutiny v0.9.5-omnibus on host port 31054; TrueNAS JSON-RPC API available (`pool.query`, `disk.query`, `disk.temperatures`, `alert.list`, `system.info`). The Phase 1 image ran `collect-once` read-only there on 2026-10-02. Support follows the Debian exit tests. |
