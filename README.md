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
| `hostwatch/hub.py` | Internal ingest and read API (session, scoped key or legacy ingest token on every route but health, audited, loopback only) |
| `hostwatch/auth.py` | Auth building blocks (the hub uses the key and session lookups; login and lockout are not yet exposed over HTTP): argon2id password hashing with cost from config, login lockout with a dummy verify for unknown users, scope validation, and API key and session token generation that stores only digests |
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
  request. An mTLS identity hook exists but is not wired to a TLS listener yet.
- The hub binds to 127.0.0.1. The container runs as UID 10001, read-only root
  filesystem, all capabilities dropped, `no-new-privileges`.
- `/sys` is mounted read-only. The host `/proc` is not mounted.
- Phase 2 adds only read-only mounts: the journal, `/sys/fs/pstore`, and
  `/var/lib/rasdaemon`. There is no privileged mode, no added capability, and
  no writable host mount.

Not yet present (later slices and phases): login endpoints, the CLI that
creates users and keys, TLS serving, Home Assistant and Orion endpoints. Until
the CLI lands there is no supported way to mint a key, so the read examples
below that use the shared token now answer 403; they need a key with the
matching scope. Do not expose port
8090 off-host before Phase 3.

## Deploy on MediaIn-SVR

```
sudo ./scripts/rapl-access.sh --dry-run
sudo ./scripts/rapl-access.sh              # prints HOSTWATCH_RAPL_GID
cp deploy/.env.example deploy/.env
openssl rand -hex 32                       # paste into HOSTWATCH_INGEST_TOKEN
nano deploy/.env                           # also set HOSTWATCH_RAPL_GID and HOSTWATCH_JOURNAL_GID
                                           # (journal gid: getent group systemd-journal | cut -d: -f3)
cd deploy && sudo docker compose up -d --build
```

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

## Tests

```
pip install -e '.[test]' && pytest
```
