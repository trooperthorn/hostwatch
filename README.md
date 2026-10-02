# hostwatch

Host health, power, and crash monitoring with authenticated API access for
Home Assistant and SolarWinds Orion. See `PLAN.md` for the phased plan and
`UNVERIFIED.md` for assumptions not yet confirmed on real hardware.

Current phase: **1 (collector core)**. Phase 0 is complete on MediaIn-SVR.

## Layout

| Path | Purpose |
|---|---|
| `hostwatch/schema.py` | Agent-to-hub wire schema, version 1, with an optional events list |
| `hostwatch/collectors/` | One module per source: `cpu`, `memory`, `rapl`, `hwmon`, `mdraid`, `scrutiny` |
| `hostwatch/agent.py` | Detect, collect, push to hub; bounded queue while the hub is down |
| `hostwatch/hub.py` | Internal ingest and read API (token-protected, loopback only in Phase 1) |
| `hostwatch/store.py` | SQLite: raw samples, hourly rollups, source availability, versioned schema with an additive events table |
| `scripts/host-prep.sh` | Phase 0 host check and fixes |
| `scripts/rapl-access.sh` | Grant RAPL read access to a dedicated group (see its header for the security trade-off) |
| `deploy/` | Compose file and `.env.example` |

## What Phase 1 does and does not do

Enforced in Phase 1:
- Every hub endpoint except `/internal/v1/health` requires the ingest bearer token.
- The hub binds to 127.0.0.1. The container runs as UID 10001, read-only root
  filesystem, all capabilities dropped, `no-new-privileges`.
- `/sys` is mounted read-only. The host `/proc` is not mounted.

Not yet present (later phases): user login, scoped API keys, TLS, Home
Assistant and Orion endpoints, events and crash detection. Do not expose port
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

# Recent events, filtered by host, kind, and a unix timestamp (limit defaults to 100):
curl -s -H "Authorization: Bearer $TOKEN"   "http://127.0.0.1:8090/internal/v1/events?kind=md.degraded&since=1700000000&limit=20"

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
