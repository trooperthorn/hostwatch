# hostwatch: working contract for AI-assisted development

Read this file first. It is the authoritative guide for work in this repo.
`PLAN.md` holds the phased plan, `UNVERIFIED.md` the open assumptions, and
`docs/HANDOFF.md` the history and decisions behind the current state.

## What this project is

A containerized monitor that collects power, crash, RAID, and disk health from
a host and serves it behind a login, with API access for Home Assistant and
SolarWinds Orion (API Poller). One image, three roles (`HOSTWATCH_ROLE=all|hub|agent`).

## Current state

- Phase 0 (host prep): complete on MediaIn-SVR. ai-pi deferred by the owner.
- Phase 1 (collector core): code complete and unit-tested (`pytest`).
  **Not yet deployed or verified on real hardware.**
- Phase 2 (event engine): code complete and unit-tested, including the
  read-only journal, pstore and rasdaemon mounts and `journalctl` in the image.
  **Not yet deployed or verified on real hardware.**
- Next: deploy on MediaIn-SVR, confirm all six sources, run the 24h gap test,
  then run the four Phase 2 exit scenarios.

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
7. **Do not widen exposure ahead of the plan.** The hub binds to 127.0.0.1 until
   Phase 3 adds login, scoped API keys, and TLS.
8. **Do not mount the host `/proc`** into the container. The files read are
   system-wide from the container's own `/proc`.

## Commands

```
pip install -e '.[test]' && pytest                     # tests
python -m hostwatch collect-once                       # one cycle, no hub (set HOSTWATCH_SYSFS=/sys outside Docker)
./scripts/host-prep.sh [--json]                        # Phase 0 check
cd deploy && sudo docker compose up -d --build         # deploy
```

## Target hosts

| Host | Facts confirmed on hardware |
|---|---|
| MediaIn-SVR | Debian 13, kernel 6.12 amd64; ASUS P8Z77-V LE PLUS, i5-3570K (Ivy Bridge); NCT6779D Super I/O via `nct6775` (loaded from `/etc/modules-load.d/hostwatch.conf`); iTCO_wdt watchdog, systemd `RuntimeWatchdogSec=30s`; efi_pstore backend; rasdaemon active; md127 RAID1 (sda + sdc, WD Red 1TB); boot SSD sdb (Patriot Blaze); Scrutiny v0.9.5-omnibus on host port 8081; Docker 29.8; kernel cmdline adds `pcie_aspm=off consoleblank=0 acpi_enforce_resources=lax` via `/etc/default/grub.d/hostwatch.cfg` |
| ai-pi | Raspberry Pi 5, Debian, arm64. Phase 0 not run. Deferred. |
| TrueNAS-SVR | TrueNAS 26.0.0-BETA.3, kernel 6.18 amd64; AMD Ryzen 5 3600, MSI MS-7C02, no ECC; ZFS pools Apps, Stash, Vault, boot-pool (no md); hwmon nvme, k10temp, drivetemp; RAPL zones present but `energy_uj` root-only; SP5100 TCO watchdog present but not armed (`RuntimeWatchdogUSec=0`); pstore empty; no rasdaemon; journal group `systemd-journal` gid 102; Docker 29.0.4; Scrutiny v0.9.5-omnibus on host port 31054; TrueNAS JSON-RPC API available (`pool.query`, `disk.query`, `disk.temperatures`, `alert.list`, `system.info`). The Phase 1 image ran `collect-once` read-only there on 2026-10-02. Support follows the Debian exit tests. |
