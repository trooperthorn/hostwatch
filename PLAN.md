# hostwatch: phased plan

hostwatch collects power, crash, RAID, and disk health from a host and serves
it behind a login, with API access for Home Assistant and SolarWinds Orion.

## Architecture

- **Hub** (Docker, OS-agnostic): authentication, REST API, web UI, event
  storage (SQLite), Home Assistant MQTT discovery, Orion API Poller endpoints.
- **Agents**: platform collectors that push one shared metric and event schema
  to the hub. The Linux agent can run in the same container as the hub.
- The container reads the host read-only (`/sys`, `/proc`, journal, pstore).
  No `--privileged`. One writable volume for its own database.

## Test hosts

| Host | Arch | Role | Notable differences |
|---|---|---|---|
| MediaIn-SVR | amd64 | Primary target, hub | RAPL, mdadm RAID1, Scrutiny, UEFI pstore, iTCO watchdog |
| ai-pi | arm64 | Second validation host, agent | No RAPL (vcgencmd throttle flags instead), no RAID, no UEFI pstore |

## Phases

Each phase has an exit test. A phase is not done until its exit test passes on
every listed host.

| Phase | Goal | Exit test |
|---|---|---|
| 0 Host prep | Host produces the evidence later phases need | `scripts/host-prep.sh` reports no FAIL on both hosts |
| 1 Collector core | Metrics into SQLite with source auto-detection; agent-to-hub schema defined | 24h without gaps; values match turbostat, `/proc/mdstat`, Scrutiny UI; missing sources reported as unavailable, not zero |
| 2 Event engine | Heartbeat boot classifier, journal watchers, pstore and rasdaemon ingestion, thresholds | Watchdog hang, clean reboot, power pull, and test-array `mdadm --fail` each produce the correct event on both hosts |
| 3 API and auth | Login (argon2, sessions, lockout, optional mTLS client certs), scoped hashed API keys, audit log | No endpoint answers without a session or key; revoked key rejected immediately; every access audited |
| 4 Integrations | HA MQTT discovery and events; Orion API Poller endpoints with 0/1/2 status codes; optional Prometheus | HA device and entities appear; Orion poller alerts on a forced warning; both survive restarts |
| 5 Web UI | Status tiles, event timeline, history charts, key management | Degraded or crash state obvious within 5 seconds |
| 6 Power witnesses | NUT client module; HA smart plug as power-loss witness | Simulated outage logs on-battery; post-outage boot classified as confirmed power loss |
| 7 Hardening and release | Non-root, read-only rootfs, SBOM, image scanning, multi-arch builds, docs, threat model | Fresh deploy from README in under 15 minutes |
| 8 Windows agent | Native service: Event Log (41, 6008, 1001, WHEA), Storage Spaces, smartctl, LibreHardwareMonitor | Same exit tests as Phase 2 using Windows event sources |

## Phase 0 detail

Run on each host:

```
./scripts/host-prep.sh                  # read-only check
sudo ./scripts/host-prep.sh --apply --dry-run
sudo ./scripts/host-prep.sh --apply     # confirms each change
./scripts/host-prep.sh --json           # for automation and Claude Code
```

Items not fixed automatically, by design:
- Watchdog device missing: driver choice is hardware-specific.
- hwmon Super I/O driver: requires interactive `sensors-detect`.
- Docker install: out of scope for this script.
- Pi kernel command line: `/boot/firmware/cmdline.txt` is left alone.
- BIOS Restore AC Power Loss: cannot be read from the OS (MANUAL).

Phase 0 is complete when both hosts report `FAIL: 0` and the MANUAL item has
been confirmed in the BIOS.

Status: complete on MediaIn-SVR (2026-10-02). ai-pi deferred.

## Phase 1 detail

One image, three roles selected by `HOSTWATCH_ROLE`: `all` (hub plus local
agent, used on MediaIn-SVR), `hub`, and `agent`. In `all` mode the agent still
posts to the hub over loopback HTTP, so the wire schema is exercised exactly as
a remote agent would use it.

Sources: `cpu` (utilization, load, frequency, idle residency, throttle
counters), `memory`, `rapl`, `hwmon` (raw values; rail calibration pending),
`mdraid`, `scrutiny`. A source that is absent or unreadable is reported
unavailable with a reason, never as zero.

Exit test on MediaIn-SVR: all six sources available, `/internal/v1/gaps`
reports 0 gaps over 24 hours for `rapl/watts` and `mdraid/degraded`, and
values agree with turbostat, `/proc/mdstat`, `sensors`, and the Scrutiny UI.
