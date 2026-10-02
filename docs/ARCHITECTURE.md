# Architecture

This document describes how hostwatch is put together so that new work fits
the existing shape. `PLAN.md` holds the phase goals and exit tests, and
`CLAUDE.md` holds the working rules.

## Processes and roles

One Python package and one container image. `HOSTWATCH_ROLE` selects the role:

- `agent` runs collectors on a fixed interval and posts a `Batch`
  (`hostwatch/schema.py`) to a hub over HTTP with a bearer token.
- `hub` is a FastAPI app (`hostwatch/hub.py`) served by uvicorn. It validates
  batches, stores them through `hostwatch/store.py` (SQLite on the `/data`
  volume), and serves read endpoints.
- `all` runs both in one process. The agent still posts over loopback HTTP, so
  the wire schema is exercised exactly as a remote agent would use it.

## Collectors

Each collector in `hostwatch/collectors/` subclasses the base in `base.py`,
detects whether its source exists on this host, and returns samples. A source
that is absent or unreadable is reported in `SourceStatus` as unavailable with
a reason. A sample whose value is `None` is stored as unavailable, never as
zero. Collectors read from roots given in config (`HOSTWATCH_SYSFS`,
`HOSTWATCH_PROCFS`) so tests can point them at fake trees built in
`tests/conftest.py`.

## Data flow

```
collectors -> agent -> POST /internal/v1/ingest -> hub -> store (SQLite)
                                                      -> read API, later UI,
                                                         HA MQTT, Orion poller
```

Later phases add an event engine between the store and the outputs: it turns
samples, journal entries, pstore records, rasdaemon records and the boot
heartbeat into typed events stored in their own table.

## Storage

SQLite in `/data`. Raw samples are kept for `HOSTWATCH_RAW_RETENTION_DAYS`,
rollups for `HOSTWATCH_ROLLUP_RETENTION_DAYS`, pruned by an hourly maintenance
task in the hub. Schema changes must be additive, versioned, and migrated with
guards, with a test that upgrades a database built by the previous version.

The schema version is stored in `PRAGMA user_version`. Phase 1 databases never
set it, so a database with version 0 is adopted as version 1. `Store._migrate()`
applies numbered steps in a transaction, each created with `IF NOT EXISTS` so a
repeat run changes nothing. Version 2 adds the `events` table (unique per host
on `dedup_key`) and the `boot_state` heartbeat table; existing tables are never
altered. If the stored version is newer than the code supports, the store
refuses to start with `SchemaTooNewError` rather than risk damaging data.

## Security model

Current (enforced): the hub binds to 127.0.0.1 by default, every endpoint
except health requires the ingest bearer token compared in constant time, the
container runs non-root with a read-only rootfs, all capabilities dropped, and
`no-new-privileges`. The host `/sys` is mounted read-only. The host `/proc` is
never mounted.

Planned (Phase 3): user login with argon2 hashes, sessions, lockout, optional
mTLS client certificates, scoped hashed API keys, and an audit log. The bind
address must not widen before that work lands.

## Isolation for tests and agents

Nothing in the test suite touches real hardware. Collectors take their sysfs
and procfs roots from config, HTTP clients are mocked with `httpx` transports,
and the database lives in a pytest temporary directory. The program is only
exercised through the test suite on development machines; real-hardware checks
happen when the owner deploys the container on MediaIn-SVR.

## Platforms

Linux (Debian 13 amd64) first. The Raspberry Pi (arm64), TrueNAS SCALE, and a
native Windows agent follow once the Linux path passes its exit tests. Windows
agents will push the same `Batch` schema.
