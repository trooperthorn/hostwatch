# hostwatch

Host health, power, and crash monitoring with authenticated API access for
Home Assistant and SolarWinds Orion. See `PLAN.md` for the phased plan and
`UNVERIFIED.md` for assumptions not yet confirmed on real hardware.

Current phase: **7 (hardening and release)**, code and documents complete and not yet deployed or verified on real hardware. Phase 0 is complete on MediaIn-SVR. The security design is in `docs/THREAT-MODEL.md`.

## Layout

| Path | Purpose |
|---|---|
| `hostwatch/schema.py` | Agent-to-hub wire schema, version 1, with an optional events list |
| `hostwatch/collectors/` | One module per source: `cpu`, `memory`, `rapl`, `hwmon`, `mdraid`, `zfs`, `scrutiny`, `nut`, `truenas`, `rpi`, `thermalctl`, plus the Windows-only `win_cpu`, `win_memory`, `win_storage` (which holds the `win_storage` and `win_smartctl` sources) and `win_thermalsuite` |
| `hostwatch/windows/service.py`, `deploy/windows/` | The Windows agent run mode (`python -m hostwatch windows run`), the `hostwatch-agent` service host (pywin32 imported lazily) and the install and uninstall scripts |
| `hostwatch/windows/` | Windows platform seam: protocols for the event log, CIM, a status pipe and a command runner, with real readers that run PowerShell (`Get-WinEvent`, `Get-CimInstance`, `ConvertTo-Json`) under a timeout using only the standard library (each script forces UTF-8 output and the output is decoded as UTF-8 with replacement); tests use the fakes in `tests/fakes_windows.py` and never construct a real reader. `hostwatch/events/winevent.py` classifies Windows boots and crashes from the System event log (Kernel-Power 41, EventLog 6006 and 6008, BugCheck 1001) and turns WHEA-Logger records into `hardware_error` events. Its bookmark is saved only with the outbox batch that carries the events, a read is oldest first and capped so a burst is delivered over several cycles, and a corrupt or future bookmark falls back to a seven day lookback. `hostwatch/collectors/win_cpu.py` and `win_memory.py` collect CPU utilization and memory on Windows through the seam, replacing the Linux `cpu` and `memory` collectors only when the platform is Windows. `hostwatch/collectors/win_storage.py` adds Windows physical disk, Storage Spaces pool and virtual disk health (with reliability counters when the host exposes them) and optional `smartctl -j` readings, which are absent when smartctl is not installed; a degraded or unhealthy one raises a threshold event. No installer or service exists yet |
| `hostwatch/agent.py` | Detect, collect, push to hub; durable outbox while the hub is down; writes the boot heartbeat |
| `hostwatch/outbox.py` | Durable agent outbox (`outbox.db` in the data directory): batches stay until the hub answers 2xx, 400 and 422 dead-letter the batch, a 5xx never dead-letters and the batch waits with capped backoff, an undecodable row is dead-lettered with its error, a corrupt `outbox.db` is renamed to `outbox.db.corrupt-<timestamp>` and a fresh outbox started, overflow drops the oldest samples first and keeps events, and source progress markers commit in the same transaction as the batch |
| `hostwatch/events/boot.py` | Heartbeat writer and boot classifier (clean shutdown, agent stopped, watchdog reset from journal messages or the watchdog bootstatus, kernel panic using only pstore records from the configured `HOSTWATCH_PSTORE` root that are newer than the previous boot's start and not already counted in an earlier boot event; shutdown hints come from the journal of the heartbeat's own boot id, unknown_unclean for an abrupt end without a witness, unknown; evidence is ranked by an explicit precedence table and contradictions are reported in the event detail) |
| `hostwatch/events/pstore.py` | Read-only pstore ingestion (`HOSTWATCH_PSTORE`, default `/host/pstore`): crash records become deduplicated events classified by explicit markers, unreadable stores are reported unavailable, and records are never deleted |
| `hostwatch/events/rasdaemon.py` | Read-only rasdaemon database ingestion (`HOSTWATCH_RASDAEMON_DB`, default `/host/rasdaemon/ras-mc_event.db`): `mc_event`, `aer_event` and `mce_record` rows become `hardware_error` events, each table only if present; progress survives restarts, a recreated database is detected by checking the timestamp of the last row read, an undecodable value is stored as hex, a row that cannot be converted is skipped and counted in the source reason, and zone-less timestamps are read as UTC and flagged |
| `hostwatch/events/journal.py` | Read-only journal watcher (`HOSTWATCH_JOURNAL`, default `/host/journal`): runs `journalctl --directory` on a worker thread with a saved cursor (first read bounded to two boots, falls back to `HOSTWATCH_JOURNAL_VOLATILE`), recovers from a rotated-out cursor with a `journal.cursor_reset` event, marks a capped first read as `journal.backlog_truncated`, names unreadable journal files in the source reason, reports unreadable journals as unavailable, and turns watchdog, md degraded, e1000e, MCE, I/O error, ata link reset and thermal throttle messages into events |
| `hostwatch/events/thresholds.py` | Edge-triggered threshold events from samples (md degraded, md sync change, source flip, Scrutiny device_status growth, UPS on battery, low battery and back on line), seeded from stored events |
| `hostwatch/integrations/summary.py` | Shared host health summary for the Home Assistant, Orion and Prometheus outputs: unavailable values are None with a reason, and `status_for` maps component state to 0 ok, 1 warning, 2 critical |
| `hostwatch/truenas/client.py` | Read-only TrueNAS JSON-RPC client over WebSocket (`HOSTWATCH_TRUENAS_URL`, `HOSTWATCH_TRUENAS_API_KEY_FILE`, `HOSTWATCH_TRUENAS_CA`, `HOSTWATCH_TRUENAS_INSECURE`, `HOSTWATCH_TRUENAS_TIMEOUT_S`): logs in with `auth.login_with_api_key`, sends only an allowlist of query methods (any other raises before a frame is written), verifies TLS by default, converts `{"$date": ms}` to epoch seconds, and reports any failure as unavailable with a reason. The key is read from a file and never logged. It is not yet wired to a collector |
| `deploy/truenas/` | TrueNAS custom app `compose.yaml` (agent role, read-only root, cap_drop ALL, non-root, read-only `/sys` and journal mounts, data on a dataset) and `rapl-postinit.sh`, a Post Init script that is a dry run unless given `--apply`. Steps are in `docs/deploy-truenas.md` |
| `hostwatch/witness/homeassistant.py` | Hub-side Home Assistant smart plug witness (`HOSTWATCH_HA_URL`, `HOSTWATCH_HA_TOKEN_FILE`, `HOSTWATCH_POWER_WITNESS` as `host=entity_id` pairs): reads the entity state history over the REST API with the token from a file and TLS verification on, and returns outage intervals (unavailable, unknown, off) in epoch UTC, or unavailable with a reason when Home Assistant cannot be asked |
| `hostwatch/hub.py` | Internal ingest and read API (session, scoped key or legacy ingest token on every route but health, audited, loopback only) |
| `hostwatch/web/` | Static web UI shell (`index.html`, `app.css`, `app.js`, the vendored Tabler `icons/`, no build step) served by the hub at `/` and `/static/`, showing a status banner and host panels worst first from `GET /api/v1/hosts/summary/grouped` in a Simple, Expanded or Expert view (chosen in the header and saved per user through `/api/v1/me/preferences`), with a Customise panel to choose and reorder the groups (a Reset to default order button, and a "hidden group needs attention" marker on any host whose hidden group is warning or critical, while the host status and banner still count it), and refreshing every 15 seconds, an event timeline with host, source, kind and time filters and paging from `GET /internal/v1/events`, a History view with an SVG line chart, a range selector, gap shading and a text table, and, for administrators only, an API keys screen (list, create with a one-time secret, revoke after a confirmation) and a read-only audit log view with kind, actor and time filters, status badges and compact detail text (all filter forms use stacked labels in an even grid, and all tables have sticky headers, row shading and an empty state); it ships as package data so the wheel and the Docker image include it |
| `hostwatch/auth.py` | Auth building blocks (the hub uses the key and session lookups and the login endpoint calls `check_login`): argon2id password hashing with cost from config, login lockout with a dummy verify for unknown users, scope validation, and API key and session token generation that stores only digests |
| `hostwatch/store.py` | SQLite: raw samples, hourly rollups, source availability, versioned schema with additive events, batch id and auth tables (users, sessions, API keys, audit log) |
| `scripts/host-prep.sh` | Phase 0 host check and fixes |
| `scripts/pstore-access.sh` | Grant read-only pstore access to the same dedicated group, with a boot-time unit ordered after `sys-fs-pstore.mount` (see its header: crash dumps can hold kernel memory fragments) |
| `scripts/rapl-access.sh` | Grant RAPL read access to a dedicated group (see its header for the security trade-off) |
| `deploy/` | Compose file and `.env.example` |
| `deploy/agent/` | Remote agent compose file and `.env.example` for the Raspberry Pi and any Debian agent (see `docs/deploy-agents.md`) |

The `rpi` source reads the Raspberry Pi firmware throttled bitmask (default the sysfs `get_throttled` file under `soc:firmware`, or the path in `HOSTWATCH_RPI_THROTTLED_PATH`) and the `cpu-thermal` zone. Under-voltage now is critical, capped or throttled now is a warning, and the has-occurred bits stay a warning until a reboot. On a Pi without the file it is unavailable with the `vcgencmd get_throttled` alternative named, and on any other host it is reported not present only on positive evidence: a model file that was read and names no Pi, or missing model files with no throttled file or configured path. An unreadable model file never makes a Pi absent. The bit meanings and file location are unconfirmed; see `UNVERIFIED.md`.

The `thermalctl` source reads the status file written by the thermalctl fan controller (default `/run/thermalctl/status.json`, or the path in `HOSTWATCH_THERMALCTL_STATUS`). It reports zone temperature and load, and the duty and rpm of each header, which appear in the Fans group labelled with the header state, mode and failsafe reasons. A header in failsafe is a warning, because the controller is then running the fan at full speed by design. The source is unavailable when the file is unreadable, is not valid JSON or is older than 60 seconds, and it is reported not present only when the directory that would hold the file is readable and the file is missing, or the directory is missing from a readable parent.

The `win_thermalsuite` source (Windows only) reads the read-only status of the Thermal Control Suite service through its `ThermalControlSuite.Ipc` named pipe. It sends the one documented `GetStatusReadOnly` request with a 3 second timeout and nothing else, and accepts status payload `schemaVersion` 1 only. It reports zone temperature, load and duty and, for each fan, the applied duty, the computed target and the rpm, using the same metric and label names as `thermalctl` plus `dry_run` and `firmware_controlled` labels. The fans appear in the Fans group, and a fan in fail-safe is a warning. A fan in dry run or under firmware control has no duty value, because the service reports an actual of 0 there that is not a measurement. The source is unavailable on a timeout, a bad payload, an unknown schema version, or a last control pass older than 60 seconds, and it is reported not present only when the pipe does not exist. It is verified only with fakes; see `UNVERIFIED.md`.

## What Phase 1 does and does not do

Enforced:
- Every hub endpoint except `/internal/v1/health` requires a credential, and
  each access and each authentication failure is appended to the audit log
  (never the secret). Accepted credentials are a session cookie, a scoped
  bearer API key, and the deprecated shared ingest token, which may only
  ingest. `latest`, `sources` and `gaps` need `read:metrics`, `events` needs
  `read:events`, `ingest` needs `ingest`. A revoked key is rejected on its next
  request. Optional client certificate login
  (`HOSTWATCH_MTLS_MODE=off|proxy`, default off; `uvicorn` is refused at startup
  because the pinned uvicorn does not expose the verified certificate) maps a certificate
  subject or SAN through the `cert_bindings` table to a user with read scopes
  only. In `proxy` mode the identity headers are honoured only from peers listed
  in `HOSTWATCH_MTLS_TRUSTED_PROXIES`; that peer check is enforced here, but
  whether the proxy really verifies certificates and strips client supplied
  headers is the proxy configuration's job and is not checked by hostwatch.
  Smart card (YubiKey/PIV) behaviour is unverified, see `UNVERIFIED.md`.
- The hub binds to 127.0.0.1 by default. The bind address is exposure control,
  not authentication. A non-loopback `HOSTWATCH_HUB_BIND` is refused at start
  unless `HOSTWATCH_TLS_CERT` and `HOSTWATCH_TLS_KEY` are set (the hub then
  serves TLS itself; `HOSTWATCH_TLS_CLIENT_CA` optionally asks clients for a
  certificate without requiring one) or `HOSTWATCH_ALLOW_INSECURE_BIND=1`
  is set, which logs a warning and sends credentials in clear text.
  Without TLS the hub may also bind to one specific host address (never
  `0.0.0.0` or `::`) when `HOSTWATCH_ALLOWED_CLIENTS` lists individual client
  IPv4 or IPv6 addresses (no CIDR ranges or hostnames). Requests from any other
  socket peer get 403 and an audit row before authentication runs; loopback is
  always allowed. Scoped IPv6 entries (with a %zone) are refused, at least one
  entry must be a unicast, non-loopback address a remote client can use, and
  multicast or broadcast bind addresses are refused. Denials are aggregated:
  the first denial per peer is audited, then at most one summary row per peer
  per minute carries the count, and stored request paths are stripped of
  control characters and capped at 256 characters. The audit log has no
  retention yet. This allowlist is exposure control, not authentication:
  allowed clients still need a session or API key, and traffic is unencrypted.
  It relies on `network_mode: host` so the hub sees real client addresses;
  behind NAT or a proxy, list the proxy's address. TLS deployments may use the
  allowlist too.
  In the all role the local agent posts over loopback, so with a specific-address
  bind the hub listens on that address and on 127.0.0.1; if either cannot be
  bound, startup fails with a message naming the address. The hub role binds
  only the configured address. In summary, a non-loopback bind is accepted for
  TLS, for a specific address with a source allowlist, or with the explicit
  insecure override; otherwise it is refused.
  The container runs as UID 10001, read-only root
  filesystem, all capabilities dropped, `no-new-privileges`.
- `/sys` is mounted read-only. The host `/proc` is not mounted.
- Phase 2 adds only read-only mounts: the journal, `/sys/fs/pstore`, and
  `/var/lib/rasdaemon`. There is no privileged mode, no added capability, and
  no writable host mount.

- Browser login: `POST /api/v1/login` with a JSON username and password sets an
  `HttpOnly`, `SameSite=Strict` session cookie (`Secure` when the hub serves TLS or `HOSTWATCH_TLS=1`,
  lifetime `HOSTWATCH_SESSION_TTL_S`, default 28800). Every failure (unknown
  user, wrong password, locked account) returns the same 401; the reason is in
  the audit log only. `POST /api/v1/logout` revokes the session server side. A
  cookie-authenticated POST, PUT, PATCH or DELETE must send the `X-CSRF-Token`
  header, whose value the login response returns, or it is refused with 403.
  The cookie is marked `Secure` whenever `HOSTWATCH_TLS_CERT` and
  `HOSTWATCH_TLS_KEY` are set (enforced). `HOSTWATCH_TLS=1` does not start a TLS
  listener; it declares a TLS proxy in front and marks the cookie `Secure`
  (advisory, the hub cannot verify the proxy). The audit log never stores the
  text of a username that matches no account, only a keyed HMAC kept with a key
  in the data directory, and a rejected API key is recorded by its non-secret
  prefix (only when it matches a stored key) and a reason.

Operator commands (run inside the container or with the data directory set;
they open the database directly, so shell access to the data directory is the
trust boundary, not a network control):

```
python -m hostwatch bootstrap-admin               # only when no users exist; prints a random password once
python -m hostwatch user create|disable|unlock|passwd|grant-admin|revoke-admin NAME   # password from a prompt, or one line on stdin
python -m hostwatch key create --scopes read:metrics,read:events [--owner NAME] [--host NAME]   # prints the key once
python -m hostwatch key list
python -m hostwatch key revoke ID                 # rejected on the key's next request
python -m hostwatch source forget HOST SOURCE      # declare a removed source deliberate (audited)
python -m hostwatch cert bind SUBJECT USER        # map a certificate subject or san:<entry> to a user
python -m hostwatch cert list
python -m hostwatch cert revoke SUBJECT           # rejected on the next request
```

Passwords are never taken from arguments. Key secrets and the bootstrap
password go to stdout once and cannot be shown again, because only hashes are
stored. Every command, including a refused one, writes an audit row of kind
`cli`.

The hub serves read-only SolarWinds Orion API Poller endpoints under
`/api/v1/orion`, behind a key with the `read:metrics` scope: `hosts`,
`hosts/{host}/summary` and `hosts/{host}/{cpu|memory|power|temperatures|raid|pools|disks|sources}`.
Each answers flat JSON with numeric values and a numeric status per group (0 ok,
1 warning, 2 critical). An unavailable value is left out and the group reports
`<group>_available` 0 with a `<group>_reason`. An unknown host answers 404.

`GET /api/v1/hosts/{host}/history?source=&metric=&since=&until=&step=` returns min,
average and maximum per step bucket, one series per label set, behind a
`read:metrics` key. A range of two days or less reads raw samples; a longer range
reads the hourly rollups plus hourly aggregates of the newest raw samples, so its step is a whole number of hours and recent data is never missing. A range is at
most 366 days and at most 1000 points per series; a request outside those bounds
answers 422 with the usual `detail` body. An unknown metric answers an empty
series list.

`overall_status` is at least 1 while any expected group is unmeasured (its source
never reported, is unavailable or is stale); `overall_unmeasured` counts those
groups. A source that is absent by design (no md arrays on a ZFS host, no RAPL zone, no hwmon
devices, no Scrutiny URL) is not unmeasured: its group reports `<group>_present` 0 and status 0 and
raises no warning. An unreadable source is not absent and stays a warning. A source that was reported present and available and later reports not present is critical (`disappeared`, status 2) until an operator runs `source forget HOST SOURCE`. A host silent for longer than `HOSTWATCH_SILENT_AFTER_S` (default three agent intervals) is critical with its last report time as the reason. A boot event classified kernel panic, watchdog reset, unknown unclean or power loss, or a pstore panic or oops record, keeps the host critical until `python -m hostwatch event ack ID` or `HOSTWATCH_CRASH_HOLD_S` (default 86400) passes; a clean shutdown or an agent stop does not. A host with no data at all reports `overall_status` 2 with the reason
"no data". The `hosts` list keys each entry by a slug of the host name
(`host_<slug>_name`, `host_<slug>_status`), so a new host never renames existing
keys; names whose slugs collide get a short hash suffix. To monitor a host in
the Orion API Poller, create one poller per host with the URL
`https://HUB:8090/api/v1/orion/hosts/HOSTNAME/summary` and a `read:metrics` key,
and read `$.overall_status` and the per-group `*_status` fields. Use the `hosts`
list only to discover host names and slugs.

An optional Prometheus endpoint, `GET /metrics`, is off unless `HOSTWATCH_PROMETHEUS=1` is set
(it answers 404 otherwise). When on, it needs a key with the `read:metrics` scope and returns the
text exposition format. A value that is unavailable has no sample; the `hostwatch_source_up` gauge
(1 or 0 per source) says whether it is being measured, and the separate `hostwatch_source_present`
gauge is 0 for a source the agent established is absent by design.

Not yet present (later slices and phases): the remaining Home Assistant work.
The read examples below that use the shared token answer 403; use a key with
the matching scope, created with `key create`.

## Quick start

This takes a fresh Debian 13 host to a working, logged-in dashboard. The target is under 15
minutes, with the image pull being the longest wait. It assumes Docker Engine and the Compose
plugin are already installed (installing Docker is out of scope), that you have `sudo`, and that
the host has `git`, `curl` and `openssl`. The 15-minute claim is an owner check that has not been
done yet; see `UNVERIFIED.md`. The expected output below is taken from what the code prints, not
from a recorded run, so treat small differences in wording as normal and report them.

1. **Get the code.** The compose file, the scripts and the example settings live in the repository.

   ```
   git clone https://github.com/trooperthorn/hostwatch.git ~/repos/hostwatch
   cd ~/repos/hostwatch
   ```

   Expected: a `hostwatch` directory containing `deploy/` and `scripts/`.

2. **Check the host.** This is read-only and changes nothing.

   ```
   ./scripts/host-prep.sh
   ```

   Expected: one line per item marked PASS, FAIL, WARN, SKIP or MANUAL, ending with `FAIL: 0`.
   If a FAIL appears, run `sudo ./scripts/host-prep.sh --apply --dry-run` to see what would be
   changed before you apply anything.

3. **Allow the container to read CPU power (RAPL).** Since kernel 5.10 the energy counters are
   root-only because of the PLATYPUS side channel, and this step trades that protection for power
   readings. Read the header of the script and `docs/THREAT-MODEL.md` first, and keep interactive
   accounts out of the new group. Preview, then apply:

   ```
   sudo ./scripts/rapl-access.sh --dry-run
   sudo ./scripts/rapl-access.sh
   ```

   Expected: the last lines read `Set this in deploy/.env:` followed by `HOSTWATCH_RAPL_GID=` and a
   number. Note the number.

   Then allow the same group to read the kernel crash records in `/sys/fs/pstore`. Crash dumps can
   contain fragments of kernel memory, which is why the directory is root-only, so the grant is
   limited to that one group, which only the container uses, and it is read-only:

   ```
   ./scripts/pstore-access.sh --dry-run
   sudo ./scripts/pstore-access.sh
   ```

   Expected: the dry run lists only `chgrp` and `chmod g+r` lines for `/sys/fs/pstore` paths plus the
   group, the unit and `systemctl`. After a reboot `ls -ld /sys/fs/pstore` shows group `hostwatch-rapl`
   with `r-x` for the group. The unit is skipped, not failed, on a host where pstore is not a separate mount unit. On TrueNAS the Post Init script `deploy/truenas/rapl-postinit.sh` does both.

4. **Create the settings file.** Copy the example, then set the two group ids.

   ```
   cp deploy/.env.example deploy/.env
   getent group systemd-journal | cut -d: -f3
   nano deploy/.env
   ```

   Expected: the `getent` command prints one number. In `deploy/.env` set `HOSTWATCH_RAPL_GID` to
   the number from step 3 and `HOSTWATCH_JOURNAL_GID` to the number just printed. Leave
   `HOSTWATCH_ROLE=all`. Leave `HOSTWATCH_HUB_BIND` at its default of `127.0.0.1`. If Scrutiny is
   not on `http://127.0.0.1:8081`, set `HOSTWATCH_SCRUTINY_URL`. Do not commit this file.

5. **Pull the image and start it.**

   ```
   cd deploy
   sudo docker compose pull
   sudo docker compose up -d
   ```

   Expected: `pull` downloads `ghcr.io/trooperthorn/hostwatch:edge`, and `up -d` reports the
   `hostwatch` container as started. Compose refuses to start with a message naming
   `HOSTWATCH_RAPL_GID` or `HOSTWATCH_JOURNAL_GID` if either is empty.

6. **Wait for the container to be healthy.**

   ```
   sudo docker inspect --format '{{.State.Health.Status}}' hostwatch
   curl -s http://127.0.0.1:8090/internal/v1/health
   ```

   Expected: `starting` for the first seconds, then `healthy`. The `curl` answer reports status
   `ok` and the version. This endpoint is a liveness probe and not an authentication check.

7. **Create the first administrator.** This works only while no user exists.

   ```
   sudo docker exec hostwatch python -m hostwatch bootstrap-admin
   ```

   Expected: the line `Created user 'admin'. The password below is shown once and is not stored:`
   and then the password on its own line. Copy it now, because it cannot be shown again. Create
   named users later with `python -m hostwatch user create NAME`.

8. **Create keys for Home Assistant and Orion.** Each consumer gets its own key with only the
   scopes it needs, so either can be revoked alone.

   ```
   sudo docker exec hostwatch python -m hostwatch key create --scopes read:metrics,read:events --owner homeassistant
   sudo docker exec hostwatch python -m hostwatch key create --scopes read:metrics --owner orion
   sudo docker exec hostwatch python -m hostwatch key list
   ```

   Expected: each `create` prints `Created key id N with scopes ... The secret below is shown
   once:` and then the secret. Store each secret in the consumer that will use it. `key list`
   shows both keys with their owners. To remove one later, run
   `sudo docker exec hostwatch python -m hostwatch key revoke ID`. To turn on the optional
   Home Assistant MQTT publisher, set `HOSTWATCH_MQTT_HOST` in `deploy/.env` and run
   `sudo docker compose up -d` again.

9. **Open the dashboard.** On the host, browse to `http://127.0.0.1:8090/` and sign in as `admin`
   with the password from step 7. To reach it from another computer without exposing the plain
   HTTP port, use an SSH tunnel such as `ssh -L 8090:127.0.0.1:8090 user@host`, or set up TLS with
   `HOSTWATCH_TLS_CERT` and `HOSTWATCH_TLS_KEY` as described below.

   Expected: a sign-in form, then a page listing this host with the worst status first. Within a
   few collection intervals (`HOSTWATCH_INTERVAL`, default 15 seconds, minimum 5) the sources show values or
   an "unavailable" reason; they never show a made-up zero.

### Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `docker compose` stops with a message naming `HOSTWATCH_RAPL_GID` or `HOSTWATCH_JOURNAL_GID` | The group id is empty in `deploy/.env` | Repeat steps 3 and 4, then run `sudo docker compose up -d` again |
| The health status stays `starting` or becomes `unhealthy` | The hub did not start or the port is taken | Run `sudo docker logs hostwatch` and look for a startup error; check `sudo ss -ltnp` for port 8090 |
| The container exits at startup with a message about the bind | `HOSTWATCH_HUB_BIND` is not loopback and neither TLS nor an allowlist is set | Set it back to `127.0.0.1`, or configure TLS or `HOSTWATCH_ALLOWED_CLIENTS` |
| `bootstrap-admin` says users already exist | An administrator was already created | Use the saved password, or reset it with `python -m hostwatch user passwd admin` |
| The sign-in fails and then locks | Too many wrong passwords (`HOSTWATCH_LOGIN_MAX_FAILURES`) | Run `python -m hostwatch user unlock admin` inside the container |
| The power source shows unavailable | The container group cannot read the RAPL counters, for example after a reboot before the service ran | Check `HOSTWATCH_RAPL_GID`, run `sudo systemctl status hostwatch-rapl.service`, then restart the container |
| The pstore source shows `cannot read /host/pstore: Permission denied` | `/sys/fs/pstore` is root-only and `scripts/pstore-access.sh` has not run or the group id is wrong | Run `sudo ./scripts/pstore-access.sh` (or `sudo bash scripts/pstore-access.sh`), check `ls -ld /sys/fs/pstore` and `sudo systemctl status hostwatch-pstore.service`, then restart the container |
| The journal or boot events show unavailable | `HOSTWATCH_JOURNAL_GID` is wrong or the journal is not persistent | Re-check the group id from step 4; see `UNVERIFIED.md` |
| The RAID source shows absent on a host with no md arrays | This is expected, not a fault | Nothing to do |
| The Scrutiny source shows unavailable | `HOSTWATCH_SCRUTINY_URL` does not point at your Scrutiny | Fix the URL in `deploy/.env` and run `sudo docker compose up -d` |
| `curl` from another computer is refused | The hub listens on loopback only, by design | Use the SSH tunnel in step 9, or configure TLS or an allowlist |

Boolean settings (`HOSTWATCH_TLS`, `HOSTWATCH_LEGACY_TOKEN_DISABLED`,
`HOSTWATCH_ALLOW_INSECURE_BIND`) accept `1`, `true`, `yes`, `on` as true and `0`,
`false`, `no`, `off` or empty as false, in any letter case. Any other value stops
startup with an error naming the variable (enforced).

## Create the first admin and API keys

The hub denies every route except health until a caller presents a session or a
scoped key. Create the first administrator on an empty database. Enforced: the
command refuses to run when any user exists. The password is printed once to
standard output and only its argon2id hash is stored.

```
sudo docker exec -it hostwatch python -m hostwatch bootstrap-admin
sudo docker exec -it hostwatch python -m hostwatch user create alice
```

Create, list and revoke scoped API keys. Valid scopes are `read:metrics`,
`read:events`, `ingest` and `admin`. An `ingest` key must be created with `--host NAME` and
can then post only batches for that host (enforced, 403 and an audit row otherwise). A read key
given `--host` can read only that host; read keys without it read every host. The secret is shown
once and cannot be recovered. A revoked key is rejected on its next request.

```
sudo docker exec hostwatch python -m hostwatch key create --scopes read:metrics,read:events --owner homeassistant
sudo docker exec hostwatch python -m hostwatch key create --scopes ingest --host TrueNAS-SVR --owner agent-truenas
sudo docker exec hostwatch python -m hostwatch key list
sudo docker exec hostwatch python -m hostwatch key revoke 2
```

An administrator can do the same over HTTP: `GET` and `POST /api/v1/admin/keys`,
`POST /api/v1/admin/keys/ID/revoke` and the read-only `GET /api/v1/admin/audit`
(filters `kind`, `actor`, `since`, `until`, `before_id`, `limit`). A new secret is
returned once with `Cache-Control: no-store`, and both changes are audited.

These commands are advisory-protected only: anyone who can run `docker exec` or
write the data volume can use them. Every command is written to the audit log.
For access from other hosts, serve TLS by setting `HOSTWATCH_TLS_CERT` and
`HOSTWATCH_TLS_KEY`; the hub refuses a non-loopback bind otherwise unless
`HOSTWATCH_ALLOW_INSECURE_BIND=1` is set. In the examples below, set `TOKEN`
to a key secret instead of the legacy shared token.

## Verify

```
# What the agent sees, one cycle, no hub involved:
sudo docker exec hostwatch python -m hostwatch collect-once

# Source availability and latest values through the hub:
TOKEN=$(grep ^HOSTWATCH_INGEST_TOKEN deploy/.env | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8090/internal/v1/sources | python3 -m json.tool
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8090/internal/v1/latest | python3 -m json.tool

# Recent events, filtered by host, kind, source, and a unix timestamp (limit defaults to 100).
# A full page sets the X-Next-Before and X-Next-Before-Id response headers; pass them back as
# before and before_id to read the next, older page:
curl -s -H "Authorization: Bearer $TOKEN"   "http://127.0.0.1:8090/internal/v1/events?kind=md.degraded&source=mdraid&since=1700000000&limit=20"

# Event sources are mounted read-only; each reports unavailable with a reason if absent:
sudo docker exec hostwatch ls /host/journal /host/pstore /host/rasdaemon
sudo docker exec hostwatch which journalctl
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8090/internal/v1/sources | python3 -m json.tool

# Phase 2 exit tests on MediaIn-SVR (owner-run). After each, read the newest boot event:
#   curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8090/internal/v1/events?source=boot&limit=1" | python3 -m json.tool
# 1. Clean reboot: run `sudo systemctl reboot`. Expect kind boot.clean_shutdown.
# 2. Watchdog hang: stop the watchdog feeder or hang the host so the watchdog resets it.
#    Expect boot.watchdog_reset.
# 3. Power pull: remove power with the host running. Expect boot.unknown_unclean, because
#    a power cut cannot be separated from a hang without a witness. With the Home Assistant
#    plug witness configured (or a UPS on-battery event stored) and an outage overlapping the
#    window (HOSTWATCH_WITNESS_SKEW_S, default 120), expect boot.power_loss as well.
# 4. Test-array failure: `sudo mdadm /dev/<test-array> --fail /dev/<member>`. Expect an
#    md.degraded event (query with kind=md.degraded).

# Phase 1 exit test, after 24 hours (expect gap_count 0):
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/internal/v1/gaps?host=MediaIn-SVR&source=rapl&metric=watts&hours=24"
```

Cross-check against the host: `sudo turbostat --quiet --show PkgWatt --interval 15`
for `rapl`, `cat /proc/mdstat` for `mdraid`, `sensors` for `hwmon`, and the
Scrutiny UI for `scrutiny`.

### Unused hwmon inputs

Super I/O chips such as the NCT6779 on MediaIn-SVR report unused inputs with nonsense values
(AUXTIN0 to AUXTIN2 above 98 C, the PCH_* inputs at 0 C). The CPU temperature limits (80 C warning,
90 C critical) apply only to the chips `coretemp`, `k10temp`, `zenpower` and `cpu_thermal`, the
Raspberry Pi SoC, and any `chip:sensor` glob you list in `HOSTWATCH_HWMON_CPU_SENSORS` (hub side,
for example `nct6779:CPUTIN`). All other hwmon temperatures are shown with their value and no
threshold, so a floating input cannot make the host read critical.

### Fans and the grouped summary

`GET /api/v1/hosts/summary/grouped` (a login session or a `read:metrics` key) returns every host,
worst first, with an ordered list of component groups: `cpu`, `memory`, `power`, `temperatures`,
`fans`, `pools`, `raid`, `disks`, `ups`, `pi_power`, `alerts` and `sources`. Each group carries its
label, an icon name, an aggregate status of `good`, `warning`, `critical` or `unknown` (the worst
warning or critical member; unknown when any member is unmeasured and none is worse, with the summary
naming it), a one-line plain-language summary and its member readings with
id (the machine name), label and text (both built on the server in plain words, with rounded numbers),
value, unit, labels, source, status, reason and timestamp. The page shows only the label and text; Expert
view shows the id in a muted column. A group is left out on a host that has no
members for it and no present source behind it. The `banner` is one short sentence naming the worst host, its status and its single worst
problem, and counts hosts and groups per status; it never repeats a group summary. Every group, hidden or not, counts toward the host status, so a host is Good
only when no group is warning, critical or unknown. The `alerts` group includes active and dismissed
TrueNAS alerts, the last boot classification and warning or critical events from the last
`HOSTWATCH_ALERT_WINDOW_S` seconds (default 86400).

`GET /api/v1/me/preferences` and `PUT /api/v1/me/preferences` (login session only, the PUT needs the CSRF token) read and save the signed-in user's dashboard view (`simple`, `expanded` or `expert`) and the order and visibility of the component groups. The PUT body may carry only `view`, only `groups`, or `{"reset": true}`; a field left out keeps its stored value, an empty `groups` list gives 422, and `reset` restores the default group order with every group shown. The page sends groups only after the preferences loaded, shows a notice and retries when they did not, so a failed load cannot overwrite the saved order. Each user has one row and cannot reach another's; API keys are refused.

Fans come from the hwmon `fan` readings. A fan at 0 RPM is informational (an unused header reads 0),
so it never raises an alarm unless you list it in `HOSTWATCH_HWMON_REQUIRED_FANS` on the hub as
comma-separated `chip:sensor` globs, for example `nct6779:fan2`. A listed fan at 0 RPM is critical.
An invalid entry stops the service at start with a message naming the variable.

To remove an input completely, set `HOSTWATCH_HWMON_IGNORE` on the agent to comma-separated
`chip:sensor` globs. A MediaIn-SVR example is
`HOSTWATCH_HWMON_IGNORE=nct6779:AUXTIN*,nct6779:PCH_*`. An invalid entry stops the service at
start with a message naming the variable. The alternative is an `ignore` line in a file under
`/etc/sensors.d/` (for example `ignore temp7` inside a `chip "nct6779-*"` block), which hides the
input from the `sensors` tool; that does not change what the kernel exposes in sysfs, so use the
hostwatch variable for the agent.

## Windows agent (Phase 8)

A native Windows host runs the agent as the `hostwatch-agent` service, with no container. It is the same agent loop as on Linux, wired to the Windows seam, the Event Log reader and the Windows collectors, and it pushes the unchanged wire schema to a receiver URL. Today that receiver is the hostwatch hub. The destination is only a setting (`HOSTWATCH_HUB_URL`), and it is expected to move to watchpost later, which will ingest this same schema, so nothing agent-side depends on the hub.

```
python -m hostwatch windows run                # foreground, for a console check
.\deploy\windows\install.ps1 -HubUrl https://hub.example.lan:8090   # elevated; add -DryRun to preview
```

The durable outbox lives in `C:/ProgramData/hostwatch` (`HOSTWATCH_DATA_DIR`), so batches survive a restart or a hub outage and replay oldest first. The credential is the same `HOSTWATCH_INGEST_KEY` (a host-bound key, preferred) or `HOSTWATCH_INGEST_TOKEN` as on Linux. The installer reads it as a secure string, never prints it, and writes it to `agent.env` in the data directory with an ACL that grants only SYSTEM and Administrators. The service runs as LocalSystem, starts after boot, restarts after a failure (after 5, 30 and 60 seconds, with the count reset after a day), and on a clean stop makes one last delivery attempt so queued batches are not left behind. The `pywin32` package is declared only as the Windows-marked `windows` extra and is not in `requirements.lock`. None of this has run on a real Windows host yet; see `UNVERIFIED.md`.

## Web UI

Open the hub address in a browser and sign in with a hub user. The page lists hosts with the worst
status first, in colour and in text, with a banner at the top naming the worst host. Enforced: every
data call needs the session login and the source allowlist, state-changing calls carry a CSRF token,
and every response carries a strict Content Security Policy. The API keys and Audit log screens are
for administrators only; the enforced check is on the server, and hiding the tabs is cosmetic. Grant
or remove the role with `python -m hostwatch user grant-admin NAME` or `revoke-admin NAME`. Browser
rendering, contrast and the 5-second criterion have not been verified in a real browser; see
`UNVERIFIED.md`.

## MQTT settings (Phase 4, off by default)

The Home Assistant publisher stays off until `HOSTWATCH_MQTT_HOST` is set. Related settings:
`HOSTWATCH_MQTT_PORT` (1883), `HOSTWATCH_MQTT_USERNAME` with `HOSTWATCH_MQTT_PASSWORD_FILE`
(preferred) or `HOSTWATCH_MQTT_PASSWORD`, `HOSTWATCH_MQTT_TLS`, `HOSTWATCH_MQTT_TLS_CA`,
`HOSTWATCH_MQTT_TLS_CERT` with `HOSTWATCH_MQTT_TLS_KEY`, `HOSTWATCH_MQTT_TLS_INSECURE`,
`HOSTWATCH_MQTT_DISCOVERY_PREFIX` (homeassistant), `HOSTWATCH_MQTT_BASE_TOPIC` (hostwatch) and
`HOSTWATCH_MQTT_EVENTS_INTERVAL` (10 seconds between checks for new events).
Half-set credentials or missing files stop startup with a message naming the setting. The
password is never logged.

With MQTT configured the hub publishes one Home Assistant device per monitored host:
sensors for CPU, memory, package power, temperatures, RAID array and disk health, binary
sensors for each data source, and problem binary sensors (device class `problem`). Discovery
messages are retained and republished after every reconnect, when Home Assistant publishes its
birth message on `<discovery prefix>/status`, and after a hub restart. A value that cannot be
known is shown by Home Assistant as unavailable, never as zero. Boot classifications and
hardware events (pstore, rasdaemon, threshold and journal) go to `<base topic>/events` as
non-retained JSON, once each, with a cursor kept in the database so a restart neither replays
nor drops them, including events stored while the broker was unreachable at first start; the
first tick starts at the newest existing event. Entities that are no longer produced have their
retained discovery config cleared after being marked unavailable, using a list of published
entities kept in the data directory. Host names that differ only in case or punctuation get a
short hash suffix on their device identifier and topics, with a warning in the log. Each pool becomes one
diagnostic sensor, the worse of the kstat state and the TrueNAS API health (0 ok, 1 warning, 2 critical), so an ONLINE kstat row cannot hide an API warning. When the TrueNAS API is configured, the `truenas` source adds a
per pool health (a corrected checksum error is a warning naming the disk and serial, a DEGRADED or FAULTED pool is critical),
per device error counts, per disk temperatures, and every TrueNAS alert, dismissed ones included, as a `truenas.alert` event (a dismissed alert is reported as info with `dismissed` true, whatever its level). Any device state other than ONLINE, including CANT_OPEN and UNKNOWN, is at least a warning. The client connects directly and ignores proxy environment variables, so the API key login frame never goes through a proxy.

## Power witnesses (Phase 6, off by default)

Two witnesses let an abrupt end be classified as `boot.power_loss` instead of `boot.unknown_unclean`.
Without them the result is unchanged, and a witness that is missing or unreachable is reported
unavailable with a reason, never read as proof that no outage happened.

NUT UPS client (agent side). Set `HOSTWATCH_NUT_HOST` and `HOSTWATCH_NUT_UPS`; the port defaults
to 3493. `HOSTWATCH_NUT_USER` and `HOSTWATCH_NUT_PASSWORD_FILE` are optional and only needed if your
`upsd` demands a login. The client sends read-only `LIST VAR` requests, never `SET`, `INSTCMD` or
`FSD`. It stores `ups.status`, battery charge and runtime, input voltage and load as samples and
raises `ups.on_battery`, `ups.low_battery` and `ups.on_line` events. A failed poll is retried every
cycle, and the UPS name and user may not contain spaces or control characters.

Home Assistant smart plug (hub side). Create a long-lived access token in your Home Assistant
profile, save it to a file readable only by the container user, and mount that file read-only.
Then set `HOSTWATCH_HA_URL`, `HOSTWATCH_HA_TOKEN_FILE` (the path inside the container) and
`HOSTWATCH_POWER_WITNESS` as comma separated `host=entity_id` pairs, for example
`MediaIn-SVR=switch.rack_plug`. The plug must be on the same circuit as the host. The token is read
from the file at call time and never logged. A period where the plug was unavailable, unknown or
off that overlaps the window from the host's last heartbeat to its next boot, widened by
`HOSTWATCH_WITNESS_SKEW_S` (default 120 seconds), counts as evidence. A stored UPS on-battery event
in the same window counts too. An outage counts only if it began no later than the boot plus the
allowance and ended no earlier than the last heartbeat minus the allowance; one that began after
that is recorded under `non_confirming` and proves nothing. `unknown_unclean`, an abrupt
`agent_stopped` and `unknown` boots are all assessed. When a witness was unavailable and nothing
confirmed an outage, the hub asks again with a growing delay for `HOSTWATCH_WITNESS_RETRY_S` seconds
(default 86400, 0 turns retries off) and once at every hub start; `python -m hostwatch boot reassess
HOST BOOT_ID` asks again on demand and is written to the audit log. UPS events are selected in SQL
by kind and window with no row cap, and a record cut short is marked incomplete. The original boot event is kept and every piece of evidence is in the
detail of the new `boot.power_loss` event. The exit test is `tests/test_phase6_exit.py`; the real
plug pull and UPS checks are owner checks listed in `UNVERIFIED.md`.

Z-Wave plug and wall power. A host may have several entities, written `host=entity1|entity2`, and
each has a role: `switch` (outage when `unavailable`, `unknown` or `off`), `node_status` (a Z-Wave
node status entity; outage when `dead`, `unavailable` or `unknown`, while `alive`, `awake` and
`asleep` are not outages) or `power` (a watt reading). Write the role as a prefix, for example
`MediaIn-SVR=node_status:sensor.plug_node_status|power:sensor.plug_electric_consumption_power`.
Without a prefix the role is inferred: an id ending in `_node_status` is a node status, a `sensor`
id ending in `_power` is a power reading, anything else is a switch. A Z-Wave plug cannot report its
own power loss, so its node status is what shows a dead period. Evidence from several entities is
combined, so an outage on any of them counts; an entity that cannot be read is named in the reason
and does not hide the others. The power entity is read by the hub on each summary build (a reading
under 10 seconds old is reused) and stored as a `wall_watts` sample for the host. It is shown next
to package power in the web UI, in the Orion power group as `wall_power_w`, in Prometheus as
`hostwatch_wall_power_watts` and as the Home Assistant sensor `wall_power`. A power entity that is
unavailable, unknown, not a number or in a unit other than W or kW stays unavailable with a reason
and is never shown as zero.

Z-Wave detection lag. The Z-Wave controller marks a node dead only after it has failed to reach
the node for some time, so an outage shorter than that is not witnessed. Such a boot stays
`unknown_unclean` instead of becoming `boot.power_loss`. Pair a Z-Wave plug with a UPS event or a
second entity where that matters. The detection time on the real controller is an owner check in
`UNVERIFIED.md`.

## Audit log retention

The hourly maintenance task prunes audit rows older than
`HOSTWATCH_AUDIT_RETENTION_DAYS` (default 400; 0 keeps rows forever). Each prune
that removes rows appends one `audit_prune` row with the count and the cutoff.
Pruning is the only deletion the audit log allows, and history beyond the window
is not recoverable, so export rows first if you need a longer record. This is an
application-layer control, not tamper-proofing.

## Container health and image labels

The image declares a `HEALTHCHECK` that runs `python -m hostwatch healthcheck` every 30 seconds.
The command requests `/internal/v1/health` on the configured port, over HTTPS when TLS is
configured, using only the Python standard library, and exits 0 only when it answers HTTP 200 with
status ok. Over TLS it does not verify the certificate, because the certificate is issued for a
public name and not for the loopback address. The endpoint is unauthenticated and returns only a
status and a version, so this is a liveness probe and not an authentication control. In the agent
role there is no endpoint, so the command reports that and exits 0. Check the result with
`sudo docker inspect --format '{{.State.Health.Status}}' hostwatch`.

The image carries OCI labels for source, version, revision and licenses. Set them at build time
with `--build-arg VERSION=...`, `--build-arg REVISION=...` and `--build-arg LICENSES=...`. The
licenses label defaults to `NOASSERTION` because the repository does not declare a license yet.
The base image is pinned by digest; the Dockerfile comment explains how to update it.

## CI, SBOM, scanning and releases

The `ci` workflow runs the tests, builds the amd64 image once, and then runs two checks on that
same image in parallel. The scan job writes an SPDX SBOM (`hostwatch.spdx.json`, kept as a
workflow artifact) and scans the image with trivy. It fails on any CRITICAL vulnerability that has
a fix available, and uploads the SARIF result to code scanning. The smoke job runs the image on
the runner bound to 127.0.0.1 with a generated token and a tmpfs data directory, bootstraps an
admin, logs in, creates a `read:metrics` key and reads `/api/v1/orion/hosts`; secrets are masked
and never printed. The multi-arch image is published only after both pass. Every action is pinned
to a full commit SHA. Pushing a tag that starts with `v` also publishes semver image tags
(`1.2.3` and `1.2`), passes the version and revision to the image labels, and creates a GitHub
release with the SBOM attached. The `edge` tag still follows `master`. The workflow has not run
yet; see `UNVERIFIED.md`.

## Dependency lock

The container image installs its runtime dependencies from `requirements.lock`, which pins every
package with `==` and at least one SHA-256 hash. The Dockerfile runs
`pip install --require-hashes --no-cache-dir -r requirements.lock` and then installs hostwatch
itself with `--no-deps`, so a substituted package fails the build. Regenerate the lock after
changing the dependencies in `pyproject.toml`:

```
uv pip compile pyproject.toml --generate-hashes --universal --python-version 3.12 -o requirements.lock
```

## Tests

```
pip install -e '.[test]' && pytest
```
