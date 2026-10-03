# hostwatch

Host health, power, and crash monitoring with authenticated API access for
Home Assistant and SolarWinds Orion. See `PLAN.md` for the phased plan and
`UNVERIFIED.md` for assumptions not yet confirmed on real hardware.

Current phase: **2 (event engine)**, code complete and not yet deployed. Phase 0 is complete on MediaIn-SVR.

## Layout

| Path | Purpose |
|---|---|
| `hostwatch/schema.py` | Agent-to-hub wire schema, version 1, with an optional events list |
| `hostwatch/collectors/` | One module per source: `cpu`, `memory`, `rapl`, `hwmon`, `mdraid`, `scrutiny` |
| `hostwatch/agent.py` | Detect, collect, push to hub; durable outbox while the hub is down; writes the boot heartbeat |
| `hostwatch/outbox.py` | Durable agent outbox (`outbox.db` in the data directory): batches stay until the hub answers 2xx, 400 and 422 dead-letter the batch, a 5xx never dead-letters and the batch waits with capped backoff, an undecodable row is dead-lettered with its error, a corrupt `outbox.db` is renamed to `outbox.db.corrupt-<timestamp>` and a fresh outbox started, overflow drops the oldest samples first and keeps events, and source progress markers commit in the same transaction as the batch |
| `hostwatch/events/boot.py` | Heartbeat writer and boot classifier (clean shutdown, agent stopped, watchdog reset from journal messages or the watchdog bootstatus, kernel panic using only pstore records from the configured `HOSTWATCH_PSTORE` root that are newer than the previous boot's start and not already counted in an earlier boot event; shutdown hints come from the journal of the heartbeat's own boot id, unknown_unclean for an abrupt end without a witness, unknown; evidence is ranked by an explicit precedence table and contradictions are reported in the event detail) |
| `hostwatch/events/pstore.py` | Read-only pstore ingestion (`HOSTWATCH_PSTORE`, default `/host/pstore`): crash records become deduplicated events classified by explicit markers, unreadable stores are reported unavailable, and records are never deleted |
| `hostwatch/events/rasdaemon.py` | Read-only rasdaemon database ingestion (`HOSTWATCH_RASDAEMON_DB`, default `/host/rasdaemon/ras-mc_event.db`): `mc_event`, `aer_event` and `mce_record` rows become `hardware_error` events, each table only if present; progress survives restarts, a recreated database is detected by checking the timestamp of the last row read, an undecodable value is stored as hex, a row that cannot be converted is skipped and counted in the source reason, and zone-less timestamps are read as UTC and flagged |
| `hostwatch/events/journal.py` | Read-only journal watcher (`HOSTWATCH_JOURNAL`, default `/host/journal`): runs `journalctl --directory` on a worker thread with a saved cursor (first read bounded to two boots, falls back to `HOSTWATCH_JOURNAL_VOLATILE`), recovers from a rotated-out cursor with a `journal.cursor_reset` event, marks a capped first read as `journal.backlog_truncated`, names unreadable journal files in the source reason, reports unreadable journals as unavailable, and turns watchdog, md degraded, e1000e, MCE, I/O error, ata link reset and thermal throttle messages into events |
| `hostwatch/events/thresholds.py` | Edge-triggered threshold events from samples (md degraded, md sync change, source flip, Scrutiny device_status growth), seeded from stored events |
| `hostwatch/integrations/summary.py` | Shared host health summary for the Home Assistant, Orion and Prometheus outputs: unavailable values are None with a reason, and `status_for` maps component state to 0 ok, 1 warning, 2 critical |
| `hostwatch/hub.py` | Internal ingest and read API (session, scoped key or legacy ingest token on every route but health, audited, loopback only) |
| `hostwatch/web/` | Static web UI shell (`index.html`, `app.css`, `app.js`, no build step) served by the hub at `/` and `/static/`, showing status tiles worst first from `GET /api/v1/ui/status` and refreshing every 15 seconds; it ships as package data so the wheel and the Docker image include it |
| `hostwatch/auth.py` | Auth building blocks (the hub uses the key and session lookups and the login endpoint calls `check_login`): argon2id password hashing with cost from config, login lockout with a dummy verify for unknown users, scope validation, and API key and session token generation that stores only digests |
| `hostwatch/store.py` | SQLite: raw samples, hourly rollups, source availability, versioned schema with additive events, batch id and auth tables (users, sessions, API keys, audit log) |
| `scripts/host-prep.sh` | Phase 0 host check and fixes |
| `scripts/rapl-access.sh` | Grant RAPL read access to a dedicated group (see its header for the security trade-off) |
| `deploy/` | Compose file and `.env.example` |

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
python -m hostwatch key create --scopes read:metrics,read:events [--owner NAME]   # prints the key once
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
reads the hourly rollups, so its step is a whole number of hours. A range is at
most 366 days and at most 1000 points per series; a request outside those bounds
answers 422 with the usual `detail` body. An unknown metric answers an empty
series list.

`overall_status` is at least 1 while any expected group is unmeasured (its source
never reported, is unavailable or is stale); `overall_unmeasured` counts those
groups. A source that is absent by design (no md arrays on a ZFS host, no RAPL zone, no hwmon
devices, no Scrutiny URL) is not unmeasured: its group reports `<group>_present` 0 and status 0 and
raises no warning. An unreadable source is not absent and stays a warning. A source that was reported present and available and later reports not present is critical (`disappeared`, status 2) until an operator runs `source forget HOST SOURCE`. A host with no data at all reports `overall_status` 2 with the reason
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

## Deploy on MediaIn-SVR

```
sudo ./scripts/rapl-access.sh --dry-run
sudo ./scripts/rapl-access.sh              # prints HOSTWATCH_RAPL_GID
cp deploy/.env.example deploy/.env
openssl rand -hex 32                       # optional legacy HOSTWATCH_INGEST_TOKEN; the all role mints its own ingest key.
                                           # A remote agent should use HOSTWATCH_INGEST_KEY (scoped key) instead.
                                           # Once agents use keys, set HOSTWATCH_LEGACY_TOKEN_DISABLED=1.
nano deploy/.env                           # also set HOSTWATCH_RAPL_GID and HOSTWATCH_JOURNAL_GID
                                           # (journal gid: getent group systemd-journal | cut -d: -f3)
cd deploy && sudo docker compose up -d --build
```

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
`read:events`, `ingest` and `admin`. The secret is shown once and cannot be
recovered. A revoked key is rejected on its next request.

```
sudo docker exec hostwatch python -m hostwatch key create --scopes read:metrics,read:events --owner homeassistant
sudo docker exec hostwatch python -m hostwatch key create --scopes ingest,read:events --owner agent-truenas
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
#    a power cut cannot be separated from a hang without a witness (Phase 6).
# 4. Test-array failure: `sudo mdadm /dev/<test-array> --fail /dev/<member>`. Expect an
#    md.degraded event (query with kind=md.degraded).

# Phase 1 exit test, after 24 hours (expect gap_count 0):
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/internal/v1/gaps?host=MediaIn-SVR&source=rapl&metric=watts&hours=24"
```

Cross-check against the host: `sudo turbostat --quiet --show PkgWatt --interval 15`
for `rapl`, `cat /proc/mdstat` for `mdraid`, `sensors` for `hwmon`, and the
Scrutiny UI for `scrutiny`.

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
short hash suffix on their device identifier and topics, with a warning in the log. Pool health arrives in a
later release.

## Tests

```
pip install -e '.[test]' && pytest
```
