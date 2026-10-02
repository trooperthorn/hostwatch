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
| `hostwatch/outbox.py` | Durable agent outbox (`outbox.db` in the data directory): batches stay until the hub answers 2xx, a 4xx other than 401, 408 and 429 dead-letters the batch, overflow drops the oldest samples first and keeps events, and source progress markers commit in the same transaction as the batch |
| `hostwatch/events/boot.py` | Heartbeat writer and boot classifier (clean shutdown, watchdog reset, kernel panic, power loss, unknown) |
| `hostwatch/events/pstore.py` | Read-only pstore ingestion (`HOSTWATCH_PSTORE`, default `/host/pstore`): crash records become deduplicated events classified by explicit markers, unreadable stores are reported unavailable, and records are never deleted |
| `hostwatch/events/rasdaemon.py` | Read-only rasdaemon database ingestion (`HOSTWATCH_RASDAEMON_DB`, default `/host/rasdaemon/ras-mc_event.db`): `mc_event`, `aer_event` and `mce_record` rows become `hardware_error` events, each table only if present |
| `hostwatch/events/journal.py` | Read-only journal watcher (`HOSTWATCH_JOURNAL`, default `/host/journal`): runs `journalctl --directory` with a saved cursor and turns watchdog, md degraded, e1000e, MCE, I/O error, ata link reset and thermal throttle messages into events |
| `hostwatch/events/thresholds.py` | Edge-triggered threshold events from samples (md degraded, md sync change, source flip, Scrutiny device_status growth), seeded from stored events |
| `hostwatch/hub.py` | Internal ingest and read API (token-protected, loopback only in Phase 1) |
| `hostwatch/store.py` | SQLite: raw samples, hourly rollups, source availability, versioned schema with additive events and batch id tables |
| `scripts/host-prep.sh` | Phase 0 host check and fixes |
| `scripts/rapl-access.sh` | Grant RAPL read access to a dedicated group (see its header for the security trade-off) |
| `deploy/` | Compose file and `.env.example` |

## What Phase 1 does and does not do

Enforced in Phase 1:
- Every hub endpoint except `/internal/v1/health` requires the ingest bearer token.
- The hub binds to 127.0.0.1. The container runs as UID 10001, read-only root
  filesystem, all capabilities dropped, `no-new-privileges`.
- `/sys` is mounted read-only. The host `/proc` is not mounted.
- Phase 2 adds only read-only mounts: the journal, `/sys/fs/pstore`, and
  `/var/lib/rasdaemon`. There is no privileged mode, no added capability, and
  no writable host mount.

Not yet present (later phases): user login, scoped API keys, TLS, Home
Assistant and Orion endpoints. Do not expose port
8090 off-host before Phase 3.

## Deploy on MediaIn-SVR

```
sudo ./scripts/rapl-access.sh --dry-run
sudo ./scripts/rapl-access.sh              # prints HOSTWATCH_RAPL_GID
cp deploy/.env.example deploy/.env
openssl rand -hex 32                       # paste into HOSTWATCH_INGEST_TOKEN
nano deploy/.env                           # also set HOSTWATCH_RAPL_GID
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
