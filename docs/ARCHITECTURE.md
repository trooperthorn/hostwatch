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

## Events on the wire

A batch may carry an optional `events` list (kind, severity, source, ts, title,
detail, dedup_key). The field defaults to empty and is additive, so the wire
`SCHEMA_VERSION` stays at 1: v1 agents without the field are accepted
unchanged. The hub stores events through `Store.add_events`, which keeps one row
per host and `dedup_key`, so a resent batch does not duplicate events. Events
are read with `GET /internal/v1/events` (host, since, kind, limit), behind the
same bearer token as the other internal endpoints. Event sources are reported in
the batch `sources` list like any collector, with `available` false and a reason
when the source is absent, and appear in `/internal/v1/sources`.

Later phases add an event engine between the store and the outputs: it turns
samples, journal entries, pstore records, rasdaemon records and the boot
heartbeat into typed events stored in their own table.

## Boot classifier

`hostwatch/events/boot.py` holds the heartbeat writer and the classifier. Each
agent cycle atomically rewrites `heartbeat.json` in the data directory (temp
file, fsync, rename) with the current `boot_id`, a timestamp, and
`clean_shutdown: false`. On stop (SIGTERM) the agent writes the same file with
the flag true and stops updating it. At start, the agent reads `boot_id` from
`<procfs>/sys/kernel/random/boot_id`; if it differs from the previous
heartbeat, `classify` returns one of `clean_shutdown`, `kernel_panic` (flag not
set and pstore under `<sysfs>/fs/pstore` is non-empty), `watchdog_reset`,
`power_loss`, or `unknown`, with the evidence in the event detail. A missing or
malformed heartbeat gives `unknown`. The watchdog and power loss hints come from
journal watchers that a later slice adds, so until then those boots are
`unknown`. The event kind is `boot.<class>` with dedup key `boot:<boot_id>`,
queued for the next batch. The source `boot` is reported unavailable when the
boot_id cannot be read.

## pstore ingestion

`hostwatch/events/pstore.py` reads the directory named by `HOSTWATCH_PSTORE`
(default `/host/pstore`) read-only. Every regular file becomes one event:
`pstore.kernel_panic` or `pstore.kernel_oops` for `dmesg-*` files whose text
carries a panic or oops marker, otherwise `pstore.record`. The dedup key is
`pstore:<file name>:<first 16 hex of the content sha256>`, so re-reading gives
the same key and a rewritten record gives a new one. Files are never deleted or
modified. A missing or unreadable directory yields source `pstore` unavailable
with a reason and no events; an empty directory is available with no events.
The reader is not yet called from the agent cycle; wiring and the compose mount
come in later slices.

## rasdaemon ingestion

`hostwatch/events/rasdaemon.py` opens the database named by
`HOSTWATCH_RASDAEMON_DB` (default `/host/rasdaemon/ras-mc_event.db`) with a
`file:` URI and `mode=ro`, so SQLite refuses writes. The tables `mc_event`,
`aer_event` and `mce_record` are each read only when they exist. Rows become
`hardware_error` events with the dedup key `rasdaemon:<table>:<row id>`. Severity
is `warning` for corrected errors, `critical` for uncorrected or fatal errors and
for every machine check record. The reader keeps a high-water row id per table in
memory and reads at most 500 rows per table per call. A missing database, or a
database with none of the three tables, yields source `rasdaemon` unavailable
with a reason; a single missing table is skipped and named in the reason of an
otherwise available source. A row whose timestamp cannot be parsed keeps the raw
text in the detail and is stamped with the read time, flagged by
`ts_is_read_time`. The reader is not yet called from the agent cycle, and the
compose mount comes in a later slice.

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
