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
| TrueNAS-SVR | amd64 | Agent after Debian passes | ZFS instead of md (pool state from `/proc/spl/kstat/zfs`, per-disk errors and alerts from the TrueNAS JSON-RPC API with a READONLY_ADMIN key), no rasdaemon, watchdog not armed, deploy as a TrueNAS custom app with a Post Init script for RAPL |

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

## Phase 3 status

Code complete and unit-tested; not yet verified on hardware. The exit test is
`tests/test_phase3_exit.py` (default deny, immediate key revocation, an audit
row per request). Controls and their labels:

| Control | Label |
|---|---|
| Session or key required on every route except health | Enforced in `hub.py`, tested |
| argon2id password hashes, lockout, uniform login failure | Enforced |
| Server-side sessions, `HttpOnly` and `SameSite=Strict` cookie, CSRF token | Enforced; the `Secure` flag follows `HOSTWATCH_TLS` |
| Scoped, hashed API keys, revoked on the next request | Enforced |
| Audit log of every authenticated access and every auth failure | Enforced at the application layer; not tamper-proof against file access |
| Refusal of a non-loopback bind without TLS | Enforced, with an explicit insecure override |
| TLS serving through uvicorn | Enforced when a certificate is configured; behaviour in the container unverified |
| Client certificate login | Optional, off by default; the peer allowlist and binding are enforced, the proxy configuration is advisory |
| Legacy shared ingest token | Enforced as ingest only; deprecated until disabled |
| Operator CLI | Boundary is shell access to the data directory, not the network |

Open items for Phase 3:

- The audit log has no retention. It is append-only by trigger, so pruning needs a
  deliberate design (for example archiving then rotating the file). Source denials are
  aggregated per peer per minute, which bounds that one source of growth but not the
  log as a whole.

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

## Phase 2 detail

Linux only. A heartbeat file in the data volume classifies each boot as a
clean shutdown, a watchdog-caught hang, a kernel panic (pstore), or power
loss. Journal watchers, pstore and rasdaemon ingestion, and threshold events
(for example md degraded) feed a new additive `events` table, migrated from
the Phase 1 schema, and are served by `/internal/v1/events`. Every source is
read-only and is reported unavailable with a reason when absent.

Deployment adds only read-only mounts to `deploy/docker-compose.yml`:
`/var/log/journal`, `/run/log/journal`, `/sys/fs/pstore` and
`/var/lib/rasdaemon`. The image installs `journalctl`. Privileged mode,
capabilities, and writable host mounts are not added.

Exit test on MediaIn-SVR: a watchdog hang, a clean reboot, a power pull, and a
test-array `mdadm --fail` each produce the correct event. ai-pi is deferred.
