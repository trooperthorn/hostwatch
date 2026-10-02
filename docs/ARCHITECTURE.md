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
are read with `GET /internal/v1/events` (host, since, kind, source, before, before_id, limit), behind the
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
held in the outbox as a pending event and committed at once, so an agent restart
before delivery does not lose it. The next batch carries it and clears the
pending marker in the same transaction. The source `boot` is reported unavailable
when the boot_id cannot be read.

## pstore ingestion

`hostwatch/events/pstore.py` reads the directory named by `HOSTWATCH_PSTORE`
(default `/host/pstore`) read-only. Every regular file becomes one event; symlinks are skipped.
Only `dmesg-*` files are classified, and only by explicit markers: `Kernel panic - not syncing` or a `Panic#N` header gives `pstore.kernel_panic`; an `Oops#N` header or a line starting with `BUG:` or `Oops:` gives `pstore.kernel_oops`; everything else is `pstore.record`. The dedup key is
`pstore:<file name>:<first 16 hex of the sha256 of the whole file>`, hashed in chunks, so re-reading gives
the same key and a rewritten record gives a new one. For a file over 1 MiB the excerpt comes from the head, the marker scan covers the head and the tail, and `detail.truncated` is true. Files are never deleted or
modified. A missing or unreadable directory yields source `pstore` unavailable
with a reason and no events; an empty directory is available with no events. If records exist but none could be read, the source is unavailable with a reason; if some failed, it stays available and the reason carries the failed count.
The agent reads it every cycle and sends each record once per process.

## rasdaemon ingestion

`hostwatch/events/rasdaemon.py` opens the database named by
`HOSTWATCH_RASDAEMON_DB` (default `/host/rasdaemon/ras-mc_event.db`) with a
`file:` URI and `mode=ro`, so SQLite refuses writes. The tables `mc_event`,
`aer_event` and `mce_record` are each read only when they exist. Rows become
`hardware_error` events with the dedup key `rasdaemon:<table>:<row id>:<timestamp text>`, so a recreated database that reuses ids does not collide with old rows. Severity
is `warning` for corrected errors, `critical` for uncorrected or fatal errors and
for every machine check record. The reader keeps a high-water row id per table as
a progress marker and reads at most 500 rows per table per call, so a larger backlog drains over successive cycles and a restart resumes from the committed marker. If a table's maximum id is lower than its marker, the database was recreated: the marker resets to zero and the new events carry `database_recreated` in the detail. A missing database, or a
database with none of the three tables, yields source `rasdaemon` unavailable
with a reason; a single missing table is skipped and named in the reason of an
otherwise available source. A timestamp with an explicit offset is parsed exactly; one without a zone is read as UTC, independent of the process time zone, and flagged `ts_uncertain` in the detail. A row whose timestamp cannot be parsed keeps the raw
text in the detail and is stamped with the read time, flagged by
`ts_is_read_time`. The agent reads it every cycle. The high-water ids are progress markers that
commit with the batch carrying the rows (see the outbox section).

## Journal watching

`hostwatch/events/journal.py` runs `journalctl --directory=<HOSTWATCH_JOURNAL>
-o json --no-pager --after-cursor <cursor>` (default directory `/host/journal`)
through a pluggable reader, which tests replace with a fake that yields JSON
lines. Journal access is read-only. The last `__CURSOR` seen is saved in
`journal.cursor` in the data directory, so a restart resumes after it and does
not repeat entries. A table of patterns maps message text to the kinds
`watchdog.event`, `md.degraded`, `net.e1000e_hardware_error`, `hardware.mce`,
`disk.io_error`, `disk.ata_link_reset` and `thermal.throttle`; the first match
wins and unmatched lines give no events. The dedup key is `journal:<cursor>`.
A missing directory, a missing `journalctl` binary or a failing run yields
source `journal` unavailable with a reason, and so does a directory that holds
no readable `*.journal` file. When `journalctl` exits 0 with empty output and
an error on stderr (for example a permission problem) that stderr text is the
unavailable reason, because a quiet healthy journal prints no error. When the
persistent directory has no readable journal files, the watcher reads
`HOSTWATCH_JOURNAL_VOLATILE` (default `/host/journal-volatile`) instead. The
first read with no saved cursor is bounded: `--boot=0` and `--boot=-1`, each
with `-n 5000`; a missing previous boot is tolerated. Later reads use
`--after-cursor`. The `journalctl` call runs on a worker thread
(`BackgroundJournal`) with its own 60 second limit, so a slow journal never
delays a sample cycle: each agent cycle collects the previous worker's result,
parses it and starts the next read. Parsing and cursor staging stay on the
agent thread so the cursor remains tied to the events it produced. The
`ataN: SATA link up` message counts as a link reset only after a reset on the
same port was seen, and RAID `[U_]` status needs an `mdN` or `md/raid` context.
The cursor is a progress marker that commits
with the batch carrying the entries read, so a crash after a read re-reads the
entries instead of skipping them. An older `journal.cursor` file is imported once
when no marker exists.

## Durable outbox

`hostwatch/outbox.py` keeps `outbox.db` (SQLite, synchronous FULL) in the data
directory, which is the `hostwatch-data` volume. Each cycle the agent writes the
batch to the outbox and then tries to send from the oldest. A batch is removed
only after the hub answers 2xx. The hub also deduplicates by `batch_id`, so a
resend after a lost answer is harmless.

- A 5xx answer or a network failure leaves the batch queued and is logged.
- A 401 leaves the batch queued, because a corrected token makes it deliverable.
  408 and 429 are treated the same way because they are transient.
- Any other 4xx can never succeed. The batch moves to the `dead_letters` table
  with the status (the last 1000 are kept), an error is logged, and the next
  batch is sent. The outbox source status names the count.
- The cap is 240 batches. Past it, the oldest batch loses its samples, which are
  counted, and its events move into the next batch, which gets a new `batch_id`
  because the hub may have acknowledged the old one. Events are never dropped
  by the cap. A warning is logged and the source `outbox` is reported
  unavailable, with the dropped count in the reason, until the queue drains.

Progress markers (`journal.cursor`, `rasdaemon.high_water.<table>`,
`pstore.sent_keys` and `boot.pending_events`) are rows in the `markers` table.
Event sources read them with `get` and stage new values with `stage`. Staged
values are visible at once but become durable only when `enqueue` writes the
batch, in the same transaction. A crash before that point repeats the read and
the hub deduplicates by key; a crash after it resumes after the queued events.

## Threshold events

`hostwatch/events/thresholds.py` evaluates rules on every collected cycle, after
the sources have been read. Rules are edge-triggered, with one event on entry and
one on recovery: `md.degraded` and `md.degraded_cleared` (mdraid `degraded` above
0 and back to 0), `md.sync_changed` (the `sync_action` label changed),
`source.unavailable` and `source.available` (a source that was seen available
went away or came back), and `scrutiny.status_raised` and
`scrutiny.status_cleared` (Scrutiny `device_status` grew, or returned to 0). A
steady state gives no repeat events. A sample value of None is unknown: it never
triggers a rule and never counts as a recovery, so an unreadable source cannot
look like a recovered array. A source that is unavailable from the start is not a
flip and gives no event. The first value seen for an array's sync state is a
baseline, not a change.

State is held in memory. When the agent starts it asks the hub for the host's
stored events (`GET /internal/v1/events`) and seeds the state from the rule key
and state in each `thresholds` event's detail, so a restart does not repeat an
open condition. If the hub cannot be reached, the state starts empty and one
event may repeat. Threshold events use source `thresholds` and a dedup key made
of the kind, rule key and event time.

The agent wires every source into the same batch: the boot classification,
pstore, rasdaemon, the journal watcher and the threshold events all ride in
`Batch.events`. Event sources are plain callables in `Agent.event_sources`, and
each one's status is reported in `Batch.sources`. A source that raises is
reported unavailable with the error as the reason.

A batch may also carry an optional `batch_id` (a uuid string). The agent sets
it once when it builds the batch and the queued batch keeps it on every resend.
`Store.ingest_batch` writes the samples, source status, agent row, events and
the id in one transaction, so a failure in any step leaves nothing behind. If the
id is already recorded for that host, the hub answers 200 with
`"duplicate": true` and stores nothing. Batches without an id behave as before.

`GET /internal/v1/events` pages backwards. When a page is full, the response
carries `X-Next-Before` and `X-Next-Before-Id` headers; passing them back as
`before` and `before_id` returns the next older page (the id keeps rows that
share a timestamp from being skipped). The body stays a plain list. The
`source` filter and the cursor are bound SQL parameters. The agent seeds
threshold state with `source=thresholds` and reads every page, and it logs an
HTTP 401 as a rejected token, distinct from an unreachable hub.

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
altered. Version 3 adds the `batch_ids` table (unique per host and batch id) the same way;
maintenance prunes ids older than the raw retention. If the stored version is newer than the code supports, the store
refuses to start with `SchemaTooNewError` rather than risk damaging data.

## Security model

Current (enforced): the hub binds to 127.0.0.1 by default, every endpoint
except health requires the ingest bearer token compared in constant time, the
container runs non-root with a read-only rootfs, all capabilities dropped, and
`no-new-privileges`. The host `/sys` is mounted read-only. The host `/proc` is
never mounted. The Phase 2 event sources are read-only bind mounts and nothing
else was widened (no privileged mode, no added capability, no writable host mount):

| Host path | Container path | Config variable |
|---|---|---|
| `/var/log/journal` | `/host/journal` | `HOSTWATCH_JOURNAL` |
| `/run/log/journal` | `/host/journal-volatile` | `HOSTWATCH_JOURNAL_VOLATILE`; read only when the persistent directory has no readable journal files |
| `/sys/fs/pstore` | `/host/pstore` | `HOSTWATCH_PSTORE` |
| `/var/lib/rasdaemon` | `/host/rasdaemon` | `HOSTWATCH_RASDAEMON_DB` (file `ras-mc_event.db`) |

The image installs `journalctl` from the `systemd` package. Reading the journal
may need the `systemd-journal` group, which is recorded in `UNVERIFIED.md`.

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
