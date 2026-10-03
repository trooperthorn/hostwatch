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

### TrueNAS collector (`truenas`)

The `truenas` collector reads pool, device, temperature and alert state from the TrueNAS
JSON-RPC API through the read-only client in `hostwatch/truenas/client.py`. It is off unless
`HOSTWATCH_TRUENAS_URL` is set; unconfigured it is reported not present. Each cycle it calls
`pool.query`, `disk.query`, `disk.temperatures` and `alert.list`. If any call fails the whole
source is unavailable for that cycle with the reason, because a device count without its disk
name or a temperature without its serial would be a guess. The agent loop is synchronous, so the
collector runs the async client on one private event loop and keeps one WebSocket open. Like
`nut`, it sets `retry_each_cycle`.

Samples: `pool_health` (0 ok, 1 warning, 2 critical, with the status, status code, scan state
and a `reason` label), `pool_healthy`, `pool_warning`, `pool_scan_errors`, per leaf device
`vdev_read_errors`, `vdev_write_errors`, `vdev_checksum_errors` and `vdev_self_healed_bytes`
(labels pool, class, group, vdev, disk, serial), and `disk_temp_c` (labels disk, serial, model,
pool). Health rules: a DEGRADED, FAULTED, UNAVAIL, SUSPENDED or REMOVED pool is critical;
`healthy` true together with `warning` true is a warning, because TrueNAS keeps a pool healthy
after a corrected error; any non-zero read, write or checksum count on a device is at least a
warning that names the disk and its serial; a leaf device in any state other than ONLINE
(CANT_OPEN and UNKNOWN included; a spare may also be AVAIL or INUSE), or a scan that
found errors, is a warning. The summary merges the kstat `zfs` row and the `truenas` row of the
same host and pool into one `pool.<name>` component whose state is the worse of the two. An
unmeasured part outranks ok, so one readable source never claims health the other could not
measure. The component keeps both sources' details as labels prefixed `zfs_` and `truenas_`
and a `source` label (`zfs`, `truenas` or `zfs+truenas`). Prometheus emits one
`hostwatch_pool_status` series per pool with that `source` label, and Home Assistant and Orion
publish one entity or item per pool. The WebSocket client passes `proxy=None`, so an
`HTTPS_PROXY` or `ALL_PROXY` variable in the container never carries the login frame.

Alerts are events of kind `truenas.alert` from a second event source, `truenas_alerts`, read
after the collectors in the same cycle. Dismissed alerts are included but are always info, with `dismissed` true in the detail. Otherwise levels map to severity:
INFO and NOTICE to info, WARNING to warning, ERROR, CRITICAL, ALERT and EMERGENCY to critical,
and an unknown level to warning. The dedup key is the alert uuid plus its `last_occurrence`, so
the agent sends an occurrence once and the hub keeps one row per key across restarts.

### NUT client (`nut`)

The `nut` collector asks a Network UPS Tools server for UPS state so a UPS can
witness a power loss. It is off unless `HOSTWATCH_NUT_HOST` and
`HOSTWATCH_NUT_UPS` are both set; unconfigured it is reported not present, not
unavailable. `HOSTWATCH_NUT_PORT` (default 3493), `HOSTWATCH_NUT_USER` and
`HOSTWATCH_NUT_PASSWORD_FILE` are optional, and the password is read from the
file and never logged or placed in an error reason. Enforced in code: the client
sends only `USERNAME`, `PASSWORD`, `LIST`, `GET` and `LOGOUT`, so it cannot
switch the UPS off or run an instant command. Each cycle sends one `LIST VAR`
and emits `ups_status_flag` (labels `flag` and `status`; `OL`, `OB` and `LB`
always, other flags while present), `battery_charge_pct`, `battery_runtime_s`,
`input_voltage_v` and `ups_load_pct`. A variable the server omits is stored as
unavailable, and an unreachable server, a timeout or an `ERR` reply makes the
source unavailable with the reason. The threshold engine turns the `OL`, `OB` and
`LB` flags into the events `ups.on_battery` (warning), `ups.low_battery` (critical)
and `ups.on_line` (info); see Threshold events.

Three hardening rules apply to this source. First, `NutClient._send` refuses any
line containing a CR or LF, and config validation refuses a `HOSTWATCH_NUT_UPS`
or `HOSTWATCH_NUT_USER` containing whitespace or control characters, so a value
cannot smuggle a second protocol line past the command allow-list. Second, a
failed poll does not wait for the next re-detection: the agent polls a configured
`nut` source every cycle (the collector sets `retry_each_cycle`), marks it
unavailable for the cycle that failed, and marks it available again as soon as a
poll succeeds, so an on-battery transition in between is not missed. Third, the
credentials held in `Config` (`ingest_token`, `ingest_key`, `mqtt_password`) use
the `Secret` string type, whose repr is redacted, so a printed or logged `Config`
never shows them. The NUT password, the Home Assistant token and the MQTT
password file are held only as file paths. The redaction covers repr only; code
that formats a secret with `str()` still gets the value.

### Home Assistant plug witness (`hostwatch/witness/homeassistant.py`)

A smart plug on the same circuit as a host drops off the network when the power
fails, so its history can confirm an outage the host cannot see. The hub reads
it; the agent does not. It is off unless `HOSTWATCH_HA_URL`,
`HOSTWATCH_HA_TOKEN_FILE` and `HOSTWATCH_POWER_WITNESS` (`host=entity_id` pairs
separated by commas) are set. The long-lived token is read from the file at call
time, sent only as a bearer header, and never logged or placed in a reason. TLS
verification is always on. `outages(host, start, end)` asks the REST history
endpoint for the entity and returns intervals, in epoch UTC and clipped to the
window, where the state was `unavailable`, `unknown` or `off`. An unreachable
server, a 401 or 403, another HTTP error, an empty history (a missing entity) or
an unexpected shape returns `available=False` with a reason. An empty interval
list is returned only when Home Assistant did answer with history, so a missing
witness is never read as proof of no outage. The hub applies this reader to unclean boots; see Witness-confirmed power loss.

A host may list several entities (`host=entity1|entity2`), each with a role: `switch`, `node_status`
or `power`, given as a prefix or inferred from the entity id. A Z-Wave plug cannot report its own
power loss, so a `node_status` entity counts `dead`, `unavailable` and `unknown` as outage while
`alive`, `awake` and `asleep` do not. `outages` asks each switch and node status entity separately and
combines the intervals, each carrying its `entity_id`; it is available when at least one entity
answered, and the entities that did not are named in the reason. The controller's detection time
means an outage shorter than it is not witnessed and the boot stays `unknown_unclean`.

A `power` entity is not history. `read_power(host)` reads `/api/states/<entity>` and gives watts
(W or kW), or an unavailable reading with a reason, reused for 10 seconds. The hub's `summarize`
helper calls `read_wall_power` before every summary build (UI, Orion, Prometheus) and the Home
Assistant publisher calls the same function before its own build. It stores a `wall_watts` sample
under the source `wall`, with a NULL value and the reason in the labels when unavailable.
`HostSummary.wall_power` is built from that sample and is absent for a host with no power entity. It
does not affect the host's overall status or the unmeasured groups.

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
`agent_stopped_cleanly: false`. On stop (SIGTERM) the signal handler only sets a stop flag and takes no lock,
because the signal can arrive while a heartbeat write holds the heartbeat lock.
The run loop writes the same file with the flag true on its way out and stops
updating it. The flag says only that the agent
stopped, because stopping the container is not a host shutdown. Heartbeats
written with the old `clean_shutdown` name are still read.

At start, the agent reads `boot_id` from `<procfs>/sys/kernel/random/boot_id`;
if it differs from the previous heartbeat, `classify` returns one of
`clean_shutdown` (journal evidence of a completed host shutdown from the
previous boot; the agent stop flag is recorded but not required), `kernel_panic` (a fresh pstore record), `agent_stopped` (flag
set, no host shutdown evidence), `watchdog_reset`, `unknown_unclean`, or `unknown`.
Only pstore records read from the configured `HOSTWATCH_PSTORE` root (the same root pstore ingestion uses) whose mtime is later than the previous boot's start (`first_ts` in the heartbeat, the earliest heartbeat time for that boot id) and that no earlier boot event counted (`pstore_classified.json`) count as evidence. A heartbeat without `first_ts` falls back to the last heartbeat time minus
60 seconds; older ones are listed in `detail.pstore_stale`. A
pstore directory that cannot be read is reported in `detail.pstore` as
unavailable, never as no records. A missing or malformed heartbeat gives
`unknown`. The journal hints come from `journalctl --directory=<dir> _BOOT_ID=<32 hex of the heartbeat's boot id> -n 200 -o json` (not `-b -1`, which may be another boot; an invalid id or an id absent from the journal makes the hint source unavailable with a reason),
run through `JournalWatcher.previous_boot` with a pluggable reader (a callable taking
the directory), only when the boot_id changed. A shutdown target, "Journal stopped",
"Shutting down." or systemd-shutdown message gives `host_shutdown` only when systemd
PID 1 or systemd-shutdown wrote it (`_PID=1`, or `_COMM` or `SYSLOG_IDENTIFIER` of
`systemd` or `systemd-shutdown`); the same text from another service or a mid-boot
journald restart does not count. A watchdog message gives `watchdog`, a watchdog message gives `watchdog`, and entries with no
shutdown message give `abrupt_end`. If the previous boot's journal cannot be read or is
empty, no hints are passed and `detail.journal_previous_boot` holds the reason. The
agent also reads `<sysfs>/class/watchdog/watchdog0/bootstatus`; the
`WDIOF_CARDRESET` bit (0x20) is hardware watchdog evidence and the value is recorded in
`detail.watchdog_bootstatus`. An abrupt end with no other evidence is `unknown_unclean`,
not a power loss: a power cut and a hang cannot be told apart without a witness, which
Phase 6 adds (see Witness-confirmed power loss). Kinds are never inferred from absence of evidence.

Precedence when evidence contradicts, strongest first (`boot.PRECEDENCE`):
fresh pstore panic record, then watchdog bootstatus `card_reset`, then a
journal shutdown sequence that completed, then a journal watchdog message with
no completed shutdown, then `unknown_unclean` (the journal was read and ended
abruptly, even when the agent stopped cleanly, because a container stop before a
power cut is not a clean host stop), then agent stopped (only when the journal could
not be read), then `unknown`. A watchdog message inside a completed shutdown tail is therefore
`clean_shutdown`, because the watchdog is normally disarmed during an orderly
stop. Hardware bootstatus is not overridden by a clean agent stop. When the
winning class disagrees with other evidence, `detail.contradiction` names each
disagreement and `detail.evidence_seen` lists every piece of evidence. The
`unknown` reason states what was actually read (journal unavailable, hints read
but inconclusive, or journal not checked).

### Witness-confirmed power loss (`hostwatch/witness/power.py`)

When the hub stores a `boot.unknown_unclean` or `boot.unknown` event (or a `boot.agent_stopped`
event whose journal hints show an abrupt end), it asks the witnesses about the window from the previous
heartbeat minus a skew allowance to the boot time plus the allowance. The boot time is the
event's `detail.detected_at`, when the agent noticed the new boot. The allowance is
`HOSTWATCH_WITNESS_SKEW_S` (default 120 seconds) and absorbs clock differences between the
host, the hub and Home Assistant. The work runs after the ingest response, so a slow Home
Assistant never delays the agent. The witnesses are the plug history of the host's configured
entity and the stored UPS events `ups.on_battery` and `ups.low_battery` of the same host.

If a plug outage interval (`unavailable`, `unknown` or `off`) overlaps the window, or a UPS
on-battery or low-battery event falls inside it, the hub stores a new `boot.power_loss` event
(critical) with the same `boot_id` and the dedup key `boot:<boot_id>:power_loss`. Its detail is
the original detail plus `power_witness`: the window, the skew used, each plug interval, the
UPS events, and `supersedes`. The original event is kept and gets the same `power_witness`
with `superseded_by`. Otherwise the original event stays and `detail.power_witness` records
what was asked and why there was no confirmation. A witness that is not configured, refuses the
token or cannot be reached is recorded as unavailable with its reason, never as no outage.
An event that already has `power_witness` is not assessed again by a resend, so a resend adds
nothing.

An outage confirms only if it began no later than the boot time plus the allowance and ended no
earlier than the last heartbeat minus the allowance. The witnesses are asked one hour beyond the
window (`LOOKAHEAD_S`), and an outage found there is kept under `non_confirming` for both the plug
and the UPS, because a host that was already back is not evidence of a power cut. UPS events are
read with one SQL query by kind and time window and no row limit, so newer unrelated events
cannot hide one. At most 50 are recorded in the detail; when more matched, `ups.total` holds the
count and `ups.incomplete` is true.

When any witness was unavailable and nothing confirmed an outage, the evidence carries
`incomplete` and `retry_pending` with a `retry` record (first attempt, attempts, next attempt and
expiry). The hub loop checks every 60 seconds, retries when the backoff (60 seconds doubling to
one hour) has passed, retries every pending event once at hub start, and stops at
`HOSTWATCH_WITNESS_RETRY_S` (default 86400, 0 disables) by setting `retry_expired`. A retry that
finds an outage adds `boot.power_loss` as above. `python -m hostwatch boot reassess HOST BOOT_ID`
assesses again regardless of the period and writes an audit row of kind `cli`.

Precedence of the final classification, strongest first:

| Rank | Class | Basis |
|------|-------|-------|
| 1 | `kernel_panic` | fresh pstore record; an overlapping outage is only noted in `detail.power_witness` |
| 2 | `watchdog_reset` | bootstatus card reset; an overlapping outage is only noted |
| 3 | `clean_shutdown` | journal shutdown sequence completed |
| 4 | `watchdog_reset` | journal watchdog message with no completed shutdown |
| 5 | `power_loss` | unclean end plus an overlapping plug outage or UPS on-battery event |
| 6 | `unknown_unclean` | unclean end with no overlapping witness outage |
| 7 | `agent_stopped`, `unknown` | as above |

`power_loss` is critical while held with the same rules as the other crashes: it is an open
crash condition until `python -m hostwatch event ack ID` or `HOSTWATCH_CRASH_HOLD_S` passes. The
summary hides the `unknown_unclean` event of a boot that has a `power_loss` event, even after the
power loss is acknowledged, so one outage is not two open conditions. Without any witness the
result is unchanged.

When more than one boot passed while the agent was down, `JournalWatcher.list_boots`
runs `journalctl --list-boots -o json` through a pluggable reader. The heartbeat's boot
is classified from its own journal as above, and each boot strictly between it and the
current boot gets a `boot.unknown` event with dedup key `boot:<its boot id>`, its own
journal hints in `detail.journal_previous_boot` or `detail.journal_hints`, and no
guessed cause. If the list cannot be read, only the main event is emitted.

The event kind is `boot.<class>` with dedup key `boot:<boot_id>`. Its `ts` is
the previous heartbeat time (last known alive), `detail.detected_at` is when the
agent noticed, and the `events.boot_id` column holds the new boot's id. The
event is held in the outbox as a pending event and committed at once, so an
agent restart before delivery does not lose it. The next batch carries it and
clears the pending marker in the same transaction. The source `boot` is reported
unavailable when the boot_id cannot be read or a heartbeat write fails, and
returns to available on the next successful heartbeat write.

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
a progress marker and reads at most 500 rows per table per call, so a larger backlog drains over successive cycles and a restart resumes from the committed marker. The reader also stores the timestamp text of the last row read (`rasdaemon.last_ts.<table>`). If the row at the marked id is missing or has a different timestamp, the database was recreated, even when it has since grown past the old id: the marker resets to zero and the new events carry `database_recreated` in the detail. A missing database, or a
database with none of the three tables, yields source `rasdaemon` unavailable
with a reason; a single missing table is skipped and named in the reason of an
otherwise available source. A timestamp with an explicit offset is parsed exactly; one without a zone is read as UTC, independent of the process time zone, and flagged `ts_uncertain` in the detail. A row whose timestamp cannot be parsed keeps the raw
text in the detail and is stamped with the read time, flagged by
`ts_is_read_time`. A byte value that is not valid UTF-8 is stored as hex text. A row that cannot be converted is skipped, its id is still passed, and the number skipped is stated in the source reason, so one odd row cannot stop the others. The agent reads it every cycle. The high-water ids are progress markers that
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
wins and unmatched lines give no events. The `hardware.mce` pattern needs an error report (a hardware error marker, "Machine check events logged" or an MCE error line), and `watchdog.event` needs a reset, timeout or lockup message, so ordinary boot lines such as machine check init and watchdog driver load lines give no events. The dedup key is `journal:<cursor>`.
A missing directory, a missing `journalctl` binary or a failing run yields
source `journal` unavailable with a reason, and so does a directory that holds
no readable `*.journal` file. When `journalctl` exits 0 with empty output and
an error on stderr (for example a permission problem) that stderr text is the
unavailable reason, because a quiet healthy journal prints no error. When the
persistent directory has no readable journal files, the watcher reads
`HOSTWATCH_JOURNAL_VOLATILE` (default `/host/journal-volatile`) instead. The
first read with no saved cursor is bounded: `--boot=0` and `--boot=-1`, each
with `-n 5000`; a missing previous boot is tolerated. Later reads use
`--after-cursor`. If `journalctl` rejects the saved cursor (for example because
the entry was rotated out), the watcher drops the cursor, repeats the bounded
first read, emits a `journal.cursor_reset` warning event (dedup key from the
rejected cursor) and stays available. A first read that reaches the cap adds a
`journal.backlog_truncated` marker to the source reason, and journal files that
cannot be opened (partial permission) are named in the reason while the source
stays available. The container needs the host `systemd-journal` group through
`group_add` (`HOSTWATCH_JOURNAL_GID` in `deploy/.env`), and the image creates
`/data` owned by UID 10001 so a fresh named volume is writable. The `journalctl` call runs on a worker thread
(`BackgroundJournal`) with its own 60 second limit, so a slow journal never
delays a sample cycle: each agent cycle collects the previous worker's result,
parses it and starts the next read. Parsing and cursor staging stay on the
agent thread so the cursor remains tied to the events it produced. When a cycle
fails after the journal read, the staged cursor is discarded and the background
reader is rewound, so the next read starts from the last committed cursor and
the same entries are read again and delivered once. The
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

- A network failure, any 5xx answer or any 4xx other than 400 and 422 leaves
  the batch queued and is logged. A 5xx describes the hub, not the batch, so it
  never dead-letters. The run loop then waits before the next delivery attempt,
  doubling from the cycle interval up to five minutes, while cycles keep
  collecting. The outbox source status reports how long delivery has been
  stalled and how many batches are kept.
- 400 and 422 can never succeed. The batch moves to the `dead_letters` table
  with the status (the last 1000 are kept), an error is logged, and the next
  batch is sent. The outbox source status names the count.
- A row whose payload cannot be decoded can never be sent. It moves to
  `dead_letters` with status 0 and the decode error, is exempt from the
  1000-row trim, and the queue moves on. The outbox source status reports the
  count.
- If SQLite reports `outbox.db` as not a database or malformed, it is renamed,
  with any `-wal`, `-shm` or `-journal` file, to `outbox.db.corrupt-<timestamp>`, an error is logged, and a fresh outbox is
  started. The outbox source status names the renamed file, because the queued
  batches and markers in it are lost. Locked or I/O errors are not treated as
  corruption: the file is left alone and the error is raised.
- Each agent cycle runs inside a guard. An exception is logged, markers staged
  by that cycle are discarded so nothing is skipped, the source `agent` is
  reported unavailable with the reason, and the next cycle runs normally.
- Threshold state is seeded from the hub with retry and backoff. Threshold
  events are not emitted until the seed has succeeded, so an open condition is
  not announced again after a restart during a hub outage. While the seed is
  failing, the source `thresholds` is reported unavailable with that reason.
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

UPS events read the `nut` `ups_status_flag` samples. The state is `OL`, `OB` or
`LB` (low battery wins), kept under rule key `ups.power|ups` and seeded like the
other rules. A cycle in which any of the three flags is unknown changes nothing.
A UPS first seen on line is a baseline; first seen on battery raises
`ups.on_battery`. Low battery that clears while the UPS is still on battery
updates the state without an event. The host summary gains a `ups` group: on
battery is a warning, low battery is critical, and an unavailable or stale `nut`
source makes the group unmeasured (overall status at least 1). When NUT is not
configured the source is not present and the group adds no warning; a host with
no `nut` row is treated the same way. The Orion and Home Assistant outputs do not
yet publish this group, but its status counts toward the host's overall status.

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

## Grouped summary

`summary.py` also builds the grouped view that the dashboard draws. `group_documents` decides the
membership of each group (`cpu`, `memory`, `power`, `temperatures`, `fans`, `pools`, `raid`, `disks`,
`ups`, `pi_power`, `alerts`, `sources`, in that order) and its aggregate status once on the server, so
the page never re-derives either. The aggregate is the worst member; it is unknown only when every
member is unknown. A group with no members is omitted unless one of its sources is present on the host.
The alerts group holds unacknowledged crash events, a silent host and open threshold conditions.
TrueNAS API alerts are not collected yet, so they are not in this group. Fans are `fan.*` components
from the hwmon `fan` readings. A 0 RPM fan is informational unless it matches
`HOSTWATCH_HWMON_REQUIRED_FANS` (hub side `chip:sensor` globs), where it is critical. Hosts are sorted
worst first by `grouped_document`, which also builds the banner text and the per-status counts, and
`GET /api/v1/hosts/summary/grouped` serves it behind the same scope as `/api/v1/ui/status`.

Dashboard preferences are stored per user in `user_preferences` (schema version 11, additive). `GET /api/v1/me/preferences` returns the view (`simple`, `expanded` or `expert`, default `expanded`) and the full ordered group list with a visible flag for each group. `PUT /api/v1/me/preferences` replaces them. Both work only for a login session, and the PUT needs the CSRF token like every other session write; API keys and certificate identities get 403. An unknown view or group id gives 422. Duplicate ids keep the first entry, and groups the request omits are appended in the default order, so a group added by a later release appears without a migration. The row is chosen from the session, never from the request, so a user can read and change only their own.

## Host health summary

`hostwatch/integrations/summary.py` holds the one model that the Home Assistant,
Orion and Prometheus outputs read, so they cannot disagree about a host.
`build_host_summary(store, host, now)` reads `Store.latest`, `Store.sources` and
the last day of `thresholds` events, and returns a `HostSummary` with CPU
utilization, memory used percent, package power, temperatures (hwmon and
Scrutiny drive temperatures), md array health, Scrutiny disk health, per-source
availability, five problem flags (`md_degraded`, `disk_failing`,
`source_unavailable`, `temperature_high`, `memory_low`) and the open threshold
conditions. `now` is passed in, so tests never depend on a clock.

Every value is a `Component` with a value, unit, state and reason. A value that
cannot be known is `None` with a reason, never zero. That covers a source the
agent reports unavailable, a source with no report for 180 seconds, a sample
older than 180 seconds, a null sample, and a metric that was never reported. A
problem flag whose inputs are all unknown is `None`, neither true nor false.

`status_for(component)` is the only mapping from state to a number: ok is 0,
warning is 1, critical is 2, and an unknown state returns `None`. The integration
outputs publish `None` as unavailable (Home Assistant) or omit the value and
status (Orion). Rules: a CPU temperature at 80 C warns and 90 C is critical (drives 50
and 60 C). The CPU limits apply only to the hwmon chips `coretemp`, `k10temp`, `zenpower` and
`cpu_thermal`, the Raspberry Pi SoC temperature, and any `chip:sensor` glob listed in
`HOSTWATCH_HWMON_CPU_SENSORS` on the hub. Every other hwmon temperature is reported with its value,
status 0 and the note "informational", because the Super I/O chip on MediaIn-SVR reports unused
inputs at over 100 C. The agent can also drop readings entirely with `HOSTWATCH_HWMON_IGNORE`
(comma-separated `chip:sensor` globs, matched case-sensitively); both variables are validated at
start and an entry without a chip and a sensor is rejected. Further rules: memory used at 90 percent warns and 97 is critical, an md array with
`degraded` above 0 is critical and one that is syncing warns, a Scrutiny
`device_status` other than 0 is critical, and an unavailable or stale source
warns. These limits are defaults, listed in `UNVERIFIED.md`. `HostSummary.status`
is the worst known component status, or `None` when nothing is known.

Two host-level conditions also make `overall_status` 2, because a crash must be obvious at a
glance. A host silent for longer than `HOSTWATCH_SILENT_AFTER_S` seconds (default three agent
intervals) reads critical with the time of its last report as the reason; the last report is the
newest of the agent batch time and any source report. A boot event classified `kernel_panic`,
`watchdog_reset`, `unknown_unclean` or `power_loss`, or a pstore `kernel_panic` or `kernel_oops` record, is an
open crash condition until an operator runs `python -m hostwatch event ack ID` or
`HOSTWATCH_CRASH_HOLD_S` seconds (default 86400) have passed. The acknowledgement is stored in
the `event_acks` table (schema version 9) and appends an audit row of kind `cli`. `clean_shutdown`
and `agent_stopped` are never critical. The logic lives only in `summary.py`, so the UI banner,
Orion, Prometheus and Home Assistant show both conditions without code of their own.

## Orion API Poller endpoints

`hostwatch/integrations/orion.py` renders the shared `HostSummary` as flat JSON
and `hub.py` serves it under `/api/v1/orion`, read-only, each route behind
`require_scope("read:metrics")` so the Phase 3 source allowlist and
authentication apply unchanged. Routes: `GET /api/v1/orion/hosts`,
`/hosts/{host}/summary` and `/hosts/{host}/{group}` for the groups `cpu`,
`memory`, `power`, `temperatures`, `raid`, `pools`, `disks` and `sources`. A host
is known if it has an agent row or a source row; otherwise the answer is 404, as
it is for an unknown group.

## History endpoint

`GET /api/v1/hosts/{host}/history` (scope `read:metrics`) is served by
`Store.history`. The store picks the table from the range alone: a range of
`HISTORY_RAW_MAX_S` (two days) or less reads `samples`, a longer one reads
`rollup_hourly`, which keeps hour resolution and averages weighted by the sample
count. Rollups lag the raw data, so a long range also aggregates raw samples
newer than the newest stored rollup hour into hourly rows on the fly and
combines them with the stored rollups. The newest hours and days are therefore
never missing, and no hour is counted twice. Buckets are `floor(ts / step) * step`, grouped per label set, and
unavailable (NULL) samples never enter the math. The hub bounds the range to 366
days and the result to 1000 points per series, and rejects violations with a 422
whose body is the same `{"detail": ...}` shape as every other error. The gaps endpoint (`GET /internal/v1/gaps`) uses the same rule: for a window
longer than two days it finds holes in that combined hourly series (points are
hour starts), otherwise in the raw samples. Because raw
samples are pruned after the raw retention window, a short range older than that
window is empty rather than served from rollups. All SQL is parameterized and no
schema change was needed.

Documents are one level deep. Keys are snake_case and stable: item keys are built
from slugged labels (`temp_k10temp_tctl_c`, `md_md0_degraded_devices`,
`disk_<wwn>_device_status`, `source_<name>_up`). Every group has
`<group>_status` (0, 1 or 2) and `<group>_available` (1 or 0). When nothing in a
group is known, the value keys are omitted, `<group>_available` is 0, the group
status is 1 (the same warning the summary gives an unavailable source) and
`<group>_reason` says why. The `pools` group is fed by the `zfs` collector, one item per pool
(`pool_<slug>_health` is 0 online or 2 critical); it reports unavailable while no pool has been
reported and is not expected at all on a host whose agent never sent a `zfs` row. Nothing is stored by this layer, so a restart or a recreated
app on the same database gives the same answers.

The overall status is not the worst known component alone. The expected groups
are `cpu`, `memory`, `power`, `temperatures`, `raid` and `disks`, each fed by one
source (`cpu`, `memory`, `rapl`, `hwmon`, `mdraid`, `scrutiny`). A group is
unmeasured when its source is unavailable, stale or has never reported, or when
none of its components has a known value. While any group is unmeasured,
`overall_status` is at least 1, `overall_unmeasured` counts the groups and
`overall_reason` names them, so a host that never reported its RAID state does
not read as healthy. A host with no data at all has `overall_status` 2 and
`overall_reason` "no data". Prometheus follows the same rule through
`hostwatch_host_status` and `hostwatch_host_unmeasured_groups`.

A source that is absent by design is not unmeasured. `SourceStatus` carries an optional
`present` field that defaults to true, so agents that never send it are read as present. A
collector sets it false only when the place where the source would live was readable and shows
nothing there: `mdraid` when `/proc/mdstat` is readable and lists no arrays (or does not exist
while `/proc` is readable, which is the case on a ZFS host such as TrueNAS-SVR where the md module
is not loaded), `rapl` when the powercap directory is readable and has no `intel-rapl` zone,
`zfs` when `/proc/spl/kstat/zfs` is readable and holds no pools (or does not exist while `/proc` is
readable, the zfs module not being loaded), `hwmon` when `/sys/class/hwmon` is readable and empty, and `scrutiny` when no URL is configured.
An unreadable path stays present and unavailable, which is unmeasured and keeps the warning. The
group of an absent source is listed in `HostSummary.not_present`, contributes no warning, and is
reported as not present by each consumer: Orion writes `<group>_present` 0, `<group>_available` 0,
`<group>_status` 0 and the reason "not present" (and `overall_not_present` counts them), Home
Assistant creates no entity for it and retires one it had published, and Prometheus adds the
`hostwatch_source_present` gauge. `hostwatch_source_up` keeps its meaning and is 0 for an absent
source. A not-present report older than the staleness window is treated as stale, so a silent
agent still reads as unmeasured.

Absence is only by design if the host never had the source. The hub keeps a `source_seen` row per
host and source with the times it was first and last reported present and available. A source that
then reports `present` false is state `disappeared`: its component is critical (status 2) with a
reason naming when it was last seen, the group is neither not present nor unmeasured, the host's
`overall_status` is 2 with the reason "sources disappeared", and for `mdraid` the `md_degraded`
problem flag is true. This closes the case where md arrays fail to assemble at boot and leave a
readable, empty `/proc/mdstat`. Orion reports the group at status 2, Prometheus keeps
`hostwatch_source_present` at 1 with `hostwatch_source_up` 0, and Home Assistant keeps the entities
and shows the problem sensor on. The threshold engine raises `source.disappeared` (critical) once
on the transition and `source.returned` when the source is present and available again, and it
does not also raise `source.unavailable`. Only the operator can declare a removal deliberate with
`python -m hostwatch source forget HOST SOURCE`, which sets `forgotten_at`, appends an audit row of
kind `cli`, and makes `present` false read as absent again until the source is next seen present
and available. A source that is present but unreadable is still unmeasured, not disappeared.

The `hosts` document keys each entry by a slug of the host name, for example
`host_media_svr_name` and `host_media_svr_status`, not by position, so adding a
host never renames another host's keys. The slug is the Home Assistant rule:
lowercase ASCII with other runs replaced by an underscore, and names whose slugs
collide each get a short hash suffix of the exact name.

## Prometheus endpoint

`hostwatch/integrations/prometheus.py` renders the shared `HostSummary` in the
Prometheus text exposition format (0.0.4) by hand, so no dependency is added.
`GET /metrics` is registered only when `HOSTWATCH_PROMETHEUS` is true, so a
disabled endpoint is an ordinary 404 and the default is off. When registered it
sits behind `require_scope("read:metrics")`, so the source allowlist, key checks
and audit log apply unchanged. Metrics: `hostwatch_cpu_utilization_percent`,
`hostwatch_memory_used_percent`, `hostwatch_package_power_watts`,
`hostwatch_temperature_celsius`, `hostwatch_md_degraded_devices`,
`hostwatch_disk_device_status`, `hostwatch_host_status`,
`hostwatch_host_unmeasured_groups` and `hostwatch_source_up`. A value that is unavailable produces no sample, never a
zero; `hostwatch_source_up` is 0 for a source that is unavailable or stale and
carries that fact instead. Label values are escaped (backslash, double quote and
newline). Nothing is stored by this layer.

## MQTT client (Phase 4)

`hostwatch/integrations/mqtt_client.py` is the transport layer for the Home Assistant
publisher. It is off unless `HOSTWATCH_MQTT_HOST` is set. `Config.validate` checks the
settings: username and password (or `HOSTWATCH_MQTT_PASSWORD_FILE`, preferred) must be set
together, only one password source is allowed, TLS CA, client certificate and key files must
exist and the certificate and key come as a pair, the insecure flag needs TLS, and the topic
prefixes may not contain wildcards. Setting any MQTT option without a host is an error so a
forgotten host cannot silently leave the publisher off.

`MqttClient` holds policy and talks to an `MqttTransport` protocol, so tests use an in-memory
fake and never a broker. On connect it sets a retained last will of `offline` on
`<base topic>/availability` (default base topic `hostwatch`), then publishes a retained
`online`, so Home Assistant marks entities unavailable if the hub dies. Failed connects retry
with exponential backoff (1 s doubling to a 60 s cap, jittered between 50 and 100 percent)
driven by an injected clock: `ensure_connected()` is called from a loop and does nothing until
the retry time has passed. The password is read when connecting and scrubbed from logged
error text. `PahoTransport` adapts paho-mqtt 2.x. After connecting, the client subscribes to
`<discovery prefix>/status` (Home Assistant's birth topic) and counts successful connects in
`epoch`.

### Home Assistant publisher

`hostwatch/integrations/homeassistant.py` turns `build_host_summary` into entities, so Home
Assistant agrees with Orion. `HomeAssistantPublisher.tick()` runs every 30 seconds from a hub
background task (only when MQTT is configured). It connects if due, then for each host
publishes:

- Discovery, retained, on `<prefix>/<sensor|binary_sensor>/hostwatch_<host>/<key>/config`.
  One device per host (`identifiers: ["hostwatch_<host>"]`), a unique id per entity, and an
  `origin` block.
- State, retained, on `<base>/<host>/<key>/state` (binary sensors use `ON` and `OFF`).
- Entity availability, retained, on `<base>/<host>/<key>/availability`.

Each entity lists the hub availability topic (the last will) and its own availability topic
with `availability_mode: all`. A value the summary cannot know gets entity availability
`offline` and no state message, so it is never reported as zero. The source connectivity
sensors list only the hub topic, because a source being down is a real answer. If an entity
that was published earlier, by this process or before a restart, is no longer produced, its
availability is set to `offline` and its retained discovery config is cleared with an empty
retained payload. The published entries per device are kept in `ha_discovery_keys.json` in the
data directory (written atomically), so the cleanup survives restarts.

Host names whose slugs collide (for example `Media-SVR` and `media_svr`) each get a six
character SHA-256 suffix of the exact host name on the device identifier, unique ids and
topics, and a warning names both hosts. Colliding hosts therefore get new identifiers when the
collision first appears.

Discovery is republished when the connection epoch changes (first connect, reconnect, broker
restart), when a `online` birth message arrives (the listener only sets a flag; the next tick
publishes), when an entity definition changes, and after any failed publish. A new hub process
starts with nothing marked as published, so a restart on the same database republishes
everything. Pools publish as one diagnostic sensor per pool named `pool_<slug>`, merged across the zfs and truenas sources.

### Events topic

`hostwatch/integrations/ha_events.py` sends boot classifications and hardware events (store
sources `boot`, `pstore`, `rasdaemon`, `thresholds` and `journal`) to `<base>/events`, one JSON
message per event with the store event id, host, timestamp, kind, severity, source, title,
detail and boot id. Messages are not retained, so a new subscriber is not told about old
events as if they were new. The publisher runs on its own thread, started and stopped from
`__main__` through the hub `on_start` and `on_stop` hooks, and only in the hub and all roles
and only when MQTT is configured. It shares the MQTT client with the discovery publisher; the
client serialises connect, publish and close with a lock.

Progress is the last event id sent, kept in the `publish_cursors` table (schema version 5, an
additive migration guarded by `IF NOT EXISTS`). The cursor moves only after a publish was
accepted, so a restart neither replays nor skips events, and a failed publish retries from the
same event on the next tick. A crash between a publish and the cursor write sends that one
event again, so consumers should deduplicate by `id`. The first tick starts at the newest stored
event instead of replaying history. The cursor is set before the connectivity check, so events
stored while the broker is down at first start are sent once it is reachable. `HOSTWATCH_MQTT_EVENTS_INTERVAL` (seconds, default 10) sets
the poll period.

The Phase 4 exit test, `tests/test_phase4_exit.py`, runs the publisher and the Orion
endpoints together against a fake broker. It shows the device and entities, a forced warning
giving Orion status 1 and the problem sensor on, and recovery after a hub restart and a broker
restart. It uses fakes only; the matching hardware checks are open in `UNVERIFIED.md`.

## Storage

SQLite in `/data`. Raw samples are kept for `HOSTWATCH_RAW_RETENTION_DAYS`,
rollups for `HOSTWATCH_ROLLUP_RETENTION_DAYS`, pruned by an hourly maintenance
task in the hub. The audit log is pruned by the same task after
`HOSTWATCH_AUDIT_RETENTION_DAYS` (default 400, 0 keeps rows forever); see the audit
retention paragraph in the authentication section. Schema changes must be additive, versioned, and migrated with
guards, with a test that upgrades a database built by the previous version.

The schema version is stored in `PRAGMA user_version`. Phase 1 databases never
set it, so a database with version 0 is adopted as version 1. `Store._migrate()`
applies numbered steps in a transaction, each created with `IF NOT EXISTS` so a
repeat run changes nothing. Version 2 adds the `events` table (unique per host
on `dedup_key`) and the `boot_state` heartbeat table; existing tables are never
altered. Version 6 adds the `present` column to `sources` (default 1, added only when missing). Version 7 adds the `source_seen` table (first seen, last seen and forgotten time per host and source). Version 8 adds `users.is_admin` (default 0, added only when missing); the earliest user, which is the one `bootstrap-admin` created, is marked admin by the migration so no deployment loses admin access. Version 9 adds the `event_acks` table (event id, acknowledged time, actor). Version 11 adds the `user_preferences` table (user id, view, groups JSON, updated). Version 3 adds the `batch_ids` table (unique per host and batch id) the same way;
maintenance prunes ids older than the raw retention. If the stored version is newer than the code supports, the store
refuses to start with `SchemaTooNewError` rather than risk damaging data.

Version 4 adds the auth tables `users`, `sessions`, `api_keys`, `cert_bindings`
and `audit_log`, with store methods for each. Password hashes are supplied by the
caller. Session tokens and API keys are random and only their SHA-256 digests
are stored; a full API key is returned once at creation. Revoking a key or
session takes effect on the next lookup. The audit log has no update or delete
method, and SQLite triggers abort UPDATE and DELETE on it. This is an
application-layer control: anyone who can write the database file directly can
drop the triggers or edit rows, so it is not tamper-proofing. The one exception to
"no delete" is `Store.prune_audit`, called by the hourly maintenance task. Inside a single
transaction it drops the delete trigger, deletes rows older than
`HOSTWATCH_AUDIT_RETENTION_DAYS` (default 400, 0 keeps everything), recreates the trigger and
appends one `audit_prune` row (actor `system`) whose detail holds the pruned count, the cutoff
and the window. SQLite DDL is transactional, so a failure rolls back both the deletion and the
trigger change. Nothing is recorded when no row is old enough. The trade-off is that history
beyond the window is gone for good, so an operator who needs a longer record should raise the
window or export rows first. The update trigger is never lifted, so no path edits audit rows.
This remains an application-layer control, and the prune record itself is the only trace of
what was removed. The tables exist
and the hub now enforces them as described under Hub authentication below. The
hub is still bound to 127.0.0.1.

`hostwatch/auth.py` holds the auth primitives; the hub calls the store lookups, while `POST /api/v1/login` calls `check_login`.
Passwords are hashed with argon2id, with time cost, memory and parallelism read
from config so tests can use a low cost; a login with an outdated hash is
rehashed. `check_login` locks a user for `HOSTWATCH_LOGIN_LOCK_S` after
`HOSTWATCH_LOGIN_MAX_FAILURES` consecutive failures, and an unknown, locked or
disabled user triggers a dummy verify so timing does not reveal whether the
account exists. The lock is a fixed window, not an escalating backoff, and it
is per account, so an attacker can lock out a known username (a denial of
service trade-off accepted for now). Scopes are limited to `read:metrics`,
`read:events`, `ingest` and `admin`. Password login and lockout are enforced
over HTTP by the login endpoint described next.

### Login, logout and CSRF (enforced)

`POST /api/v1/login` takes a JSON username and password and calls
`check_login`. On success it creates a server-side session and sets
`hostwatch_session` with `HttpOnly`, `SameSite=Strict`, `Path=/`, a `Max-Age` of
`HOSTWATCH_SESSION_TTL_S` and `Secure` whenever `Config.tls_active` is true: the hub terminates TLS (certificate and key set, enforced) or `HOSTWATCH_TLS=1` declares a TLS proxy (advisory). Without TLS the
cookie travels in clear text, so keep the hub on loopback. Every failure
(unknown user, wrong password, locked, disabled) returns the same 401 body with
no cookie; the reason is written to the audit log as an `auth_failure` row under
the actor `anonymous`. The attempted username is recorded only when it matches an
existing account. Otherwise the row has `unknown_user: true` and `username_hmac`,
an HMAC-SHA256 keyed with a random key generated once and stored in the data
directory as `audit_hmac.key`, because an unknown name may be a mistyped password.
Repeated attempts share an HMAC; the text is not recoverable from the log alone
(whoever can read the data directory can test guesses, so this is privacy
hygiene, not a boundary). A success is a
`login` row and a logout is a `logout` row. Passwords are never logged.

`POST /api/v1/logout` needs a session and marks it revoked in the database, so
a copied cookie stops working at once.

CSRF: `SameSite=Strict` is a second layer, not the control. The enforced control
is a token derived from the session token (SHA-256 with a fixed prefix), returned
in the login body and also set in the script-readable `hostwatch_csrf` cookie.
Any POST, PUT, PATCH or DELETE authenticated by a session cookie must send it in
the `X-CSRF-Token` header, compared in constant time; otherwise the answer is
403 and an audit row records the reason. Safe methods and bearer-key requests
are not subject to it, since a browser does not attach those credentials
automatically. Known limits: the lock is per account, so anyone can lock a
known username for the lock window, and there is no per-address throttle yet.

### Hub authentication (enforced)

Every route except `/internal/v1/health` depends on one `authenticate`
function. It tries, in order: the `hostwatch_session` cookie, a bearer API key
(`hw_` prefix, looked up by digest), the legacy `HOSTWATCH_INGEST_TOKEN`, which grants the
`ingest` scope only and is marked deprecated in the audit detail, and last an
mTLS identity (see below). A
`require_scope` check then applies: `latest`, `sources` and `gaps` need
`read:metrics`, `events` needs `read:events`, `ingest` needs `ingest`. Sessions
carry both read scopes and never `ingest`. `admin` satisfies every scope except
`ingest`. Missing or invalid credentials give 401, a missing scope gives 403.

Admin endpoints sit behind `require_admin` (an administrator session or a key with the `admin` scope).
`GET /api/v1/admin/keys` lists keys without secrets or hashes. `POST /api/v1/admin/keys` takes
`scopes` and `owner`, returns the secret once with `Cache-Control: no-store`, and writes an
`api_key_create` audit row that holds the key id, prefix, scopes and owner but never the secret.
`POST /api/v1/admin/keys/{id}/revoke` writes an `api_key_revoke` row and takes effect on the key's
next request. `GET /api/v1/admin/audit` is read-only and filters by `kind`, `actor`, `since`,
`until` and `before_id`, with `limit` from 1 to 500. State changes made with a session need the CSRF
header like every other POST. These endpoints are enforced by the same checks as the rest of the API.

An HTTP middleware appends one `audit_log` row for each authenticated request
and each 401 or 403, with actor, method, path, status and remote address.
Secrets are never written; a failed attempt is recorded under the actor
`anonymous` with a reason. The row is written in a `finally` block, so a request
whose handler raises leaves a row with status 500. A rejected `hw_` key records
`key_reason` (`unknown`, `revoked` or `bad_secret`) and `key_prefix`, the
non-secret lookup prefix, only when it matches a stored key. If the audit write
fails the request answers 500, so an access is never served unrecorded. Health is
not audited. A 404 or 405 is routed before authentication, so it is audited only
when the request carried a cookie or Authorization header, which keeps
unauthenticated scanner traffic out of the log. A test enumerates `app.routes` and fails if any route other
than health answers without credentials.

Host binding: `api_keys.host` (schema version 10, nullable) names the one host a key is bound to.
Creating an `ingest` key without a host is refused, and an `admin` key cannot be bound. At ingest
a bound key whose batch names another host gets 403 and an audit row holding `key_host` and
`batch_host`, and nothing is stored. A bound key on any read route is limited to its own host:
a request for another host gets 403, and a request naming no host is narrowed to its own, as are
the lists on `/api/v1/ui/status`, the Orion host list and `/metrics`. A bound ingest key may also
read its own host's events so the agent can seed thresholds. Keys that predate the column stay
unbound; their ingests carry `unbound_key` in the audit detail. The internal key minted in the
`all` role is bound to `HOSTWATCH_HOST_NAME`. The legacy shared token is unbound by nature.

Consequence: an agent that has only the shared token can ingest but gets 403
when it seeds threshold state from `/internal/v1/events`. The agent therefore
prefers `HOSTWATCH_INGEST_KEY`, a scoped key with the `ingest` scope bound to its host,
and falls back to `HOSTWATCH_INGEST_TOKEN` only when no key is set. The agent
role accepts either credential. In the `all` role the process mints an internal
key for its local agent at start when none is configured: it is held in memory,
only its digest is stored, it is never logged, and the previous internal key is
revoked on each start.

The legacy token is deprecated and still enforced as `ingest`-only. The first
use in each hub process writes a `deprecation` audit row, and every use is
audited as usual. Setting `HOSTWATCH_LEGACY_TOKEN_DISABLED=1` makes the hub
reject the token with 401 (an enforced control, recorded in the audit reason).
The token is optional for the hub and `all` roles; if set it must be at least
32 characters.

### Client certificate identity (optional, off by default)

`hostwatch/mtls.py` implements `HOSTWATCH_MTLS_MODE`. In `off` mode no
certificate or header is read. `uvicorn` mode is refused at startup:
`Config.validate` raises because the pinned uvicorn does not expose the verified
peer certificate to the application, so the mode could never authenticate
anyone, and the message tells the operator to use proxy mode. The reader for the
ASGI TLS extension (`client_cert_name`) stays in `mtls.py` only so a future
uvicorn can be supported after the check in `UNVERIFIED.md` passes. In `proxy` mode the hub reads
`X-SSL-Client-Verify` (must be `SUCCESS`), `X-SSL-Client-Subject` and
`X-SSL-Client-SAN` (comma separated, e.g. `email:a@b.example`), but only when the
TCP peer address is inside `HOSTWATCH_MTLS_TRUSTED_PROXIES`; otherwise the
headers are ignored as if absent. The subject, then each SAN as `san:<entry>`,
is looked up in `cert_bindings` (unrevoked binding, enabled user). A match
yields a principal with the session read scopes, never `ingest`. A presented
but unmapped name gives 401 and an `auth_failure` audit row with the name.

Enforced: the peer allowlist, the verify header value, the binding lookup and
the audit. Advisory (depends on deployment): that the proxy verifies the
certificate against the intended CA, removes client supplied copies of these
headers, and is the only network path to the hub. Header mode is only as strong
as that configuration. How smart card certificates present their subject is
unverified, see `UNVERIFIED.md`. Bindings are managed with
`python -m hostwatch cert bind SUBJECT USER`, `cert list` and
`cert revoke SUBJECT`. Each run appends a `cli` audit row, including refused
runs. Revoking takes effect on the next request. These commands share the CLI
trust boundary (shell access to the data directory), which is advisory.

### Mixed credentials

A request that carries both a session cookie and a bearer credential is rejected
with 400 before either is checked, because silently preferring one would let a
stale cookie mask a key or the reverse. The audit row has kind `auth_failure`
and names both kinds (`session_cookie` and `bearer`). This is enforced in
`hostwatch/hub.py`. A legacy `HOSTWATCH_INGEST_TOKEN` that starts with `hw_` is
refused by `Config.validate`, because the hub routes any `hw_` bearer to the API
key lookup and such a token could never match.

## Image dependency install

The Dockerfile copies `requirements.lock` and installs it with
`pip install --require-hashes --no-cache-dir -r requirements.lock`, then installs the package with
`--no-deps`. The base image is pinned by its multi-arch index digest. `tests/test_release.py`
parses `pyproject.toml` and the lock and checks that every runtime dependency is pinned with `==`,
that every lock entry carries a sha256 hash, and that the Dockerfile uses `--require-hashes`.

## Container healthcheck and image labels

`python -m hostwatch healthcheck` builds the local health URL from the configuration: the
configured port, https when TLS is configured, and 127.0.0.1 unless the hub role is bound to one
specific address, which is then probed instead because it is the only address that listens. It
uses `urllib.request`, so the image needs no curl, and a five second timeout. It exits 0 only for
HTTP 200 with status ok. The certificate is not verified over TLS because it does not name the
loopback address; the endpoint is unauthenticated and reveals only status and version, so this is a
liveness probe and not an authentication control. The agent role serves nothing, so the command
exits 0 with a message. The Dockerfile `HEALTHCHECK` uses interval 30s, timeout 10s, start period
30s and 3 retries, and sets OCI labels from the build args `VERSION`, `REVISION` and `LICENSES`.
`tests/test_healthcheck.py` covers the command with a mocked transport and checks the Dockerfile.

## CI supply chain and releases

`.github/workflows/ci.yml` has six jobs. `test` runs pytest. `build` produces one amd64 image tar
that `scan` and `smoke` load, so both check the same bytes. `scan` generates an SPDX JSON SBOM with
anchore/sbom-action and runs trivy at severity CRITICAL with `ignore-unfixed` and exit code 1, so a
fixable critical vulnerability fails CI; unfixed ones are not gated because nothing can be done
about them yet. It uploads SARIF to code scanning and is the only job granted `security-events:
write`; the SARIF upload is skipped for pull requests from forks, which get a read-only token.
`smoke` starts the image with `--network host`, `HOSTWATCH_HUB_BIND=127.0.0.1`, a read-only root,
all capabilities dropped and a tmpfs `/data`, then drives the first-run path over HTTP. Passwords,
the CSRF token and keys are masked with `::add-mask::` before use and travel in files or stdin,
never in echoed output. `image` (push only, needs all three) publishes the multi-arch image with
`edge`, `{{version}}`, `{{major}}.{{minor}}` and sha tags and passes `VERSION` and `REVISION` build
args. `release` runs only for `refs/tags/v*`, is the only job with `contents: write`, and attaches
the SBOM. Every action is pinned to a 40 character commit SHA with the release in a comment. The
SBOM describes the amd64 image; the arm64 variant is not scanned. These are CI controls on the
build, not runtime controls. `tests/test_release.py` reads the workflow text (PyYAML is not a
dependency) and checks the pins, the trivy gate, the loopback bind and the tag gate.

## Web UI shell (Phase 5)

The hub serves a static page from `hostwatch/web/`: `GET /` returns `index.html` and
`/static/` serves `app.css` and `app.js`. There is no frontend build step. The files are
package data in `pyproject.toml`, so the wheel and the Docker image, which installs the
package, both contain them. The shell holds no data, so these paths need no credential; every
data call the page makes goes through the authenticated API. The page signs in with
`POST /api/v1/login`, keeps the returned CSRF token in memory, and sends it in the
`X-CSRF-Token` header on state-changing calls. All text from the API is set with
`textContent`, never `innerHTML`.

An outermost middleware adds `Content-Security-Policy` (`default-src 'self'; script-src 'self';
style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'`),
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` to every response,
including allowlist refusals. The source allowlist applies to the UI paths like any other.
Requests for `/` and `/static/` are not audited, because browsers send the session cookie with
every asset request and the rows would hide real access. The CSS uses colour tokens with a
`prefers-color-scheme` dark variant and a visible `:focus-visible` outline. The charts and key
management arrive in later slices. Tests: `tests/test_ui_shell.py`.

### Status tiles

`GET /api/v1/ui/status` (scope `read:metrics`, so the session login and the source allowlist apply)
returns one document built by `hostwatch/integrations/ui_status.py` from `build_host_summary`, the
same summary the Home Assistant, Orion and Prometheus outputs use. It holds the banner (worst host,
its state and reason), `refresh_s`, and the hosts sorted worst overall status first, then by name.
Each host carries its 0/1/2 status and a text label, and for CPU, memory, power, temperatures, RAID,
pools, disks and sources each component's value, state, state text and reason. Pools list each ZFS pool, or read unknown while the zfs source has not reported. Unknown and not present are shown as such, and a disappeared
source is critical. `app.js` only renders this document with `textContent`, keeps the order it is
given, polls at `refresh_s` without a page reload, and holds no threshold logic. State is shown by
colour, a text badge and the text of each line, so it does not rely on colour alone. Tests:
`tests/test_ui_status.py`.

### Dashboard views

The status screen is drawn from `GET /api/v1/hosts/summary/grouped`, which holds the banner with
host and group counts, the hosts worst first, and for each host its groups with an aggregate status,
a one-line summary and the member readings. Grouping, aggregate status and membership are computed
once on the server; `app.js` does not group, compare or sort anything and sets all data with
`textContent`. The header has a three-button view switcher. Simple draws one line per host with the
overall status and one small icon per visible group, each with an accessible name such as "Fans:
Good". Expanded draws group cards with the one-line summary; a host whose status is good starts
collapsed to one line, hosts with a problem start open, and the host and group headers are buttons
with `aria-expanded`, so a click opens the readings. Expert opens every host and group and shows a
table of value, unit, labels, source, status, reason and timestamp, with unavailable values stated as
such. The Customise panel lists every group with a visibility checkbox, a drag handle, and Move up
and Move down buttons that work from the keyboard; each change is saved at once with `PUT
/api/v1/me/preferences` and the CSRF header, and the saved view, visibility and order are loaded
after sign in. The preference document also carries each group's label and icon. A Reset to default
button restores the default order with every group shown. Hiding a group only changes what the page
draws: the host status and the banner come from the server and still count the hidden group. When a
hidden group is warning or critical on a host, the host header shows a marker reading "Hidden group
needs attention" followed by the group name and its status text, with an icon so it is not conveyed by
colour alone.

Icons are the vendored Tabler outline SVGs in `hostwatch/web/icons/` (MIT, `LICENSE` shipped),
listed as package data and served from `/static/icons/`. `app.css` draws them as CSS masks from
relative same-origin URLs so they take the text colour in light and dark schemes, which keeps the
strict content security policy and loads nothing from another origin. Status is shown as one of
four icon shapes (check, triangle, cross, minus) together with the text label and a colour, never by
colour alone. Tests: `tests/test_ui_views.py`.

### Event timeline

The Events view reads `GET /internal/v1/events` (scope `read:events`, so the session login and the
source allowlist apply) and adds no endpoint. The filter form passes `host`, `source`, `kind` and
`since` (a relative range converted to an epoch time in the browser) straight through. Paging
follows the `X-Next-Before` and `X-Next-Before-Id` headers the endpoint sets on a full page and
sends them back as `before` and `before_id`, so rows sharing a timestamp are not skipped. The table
has a caption, column headers with `scope="col"`, labelled filter fields, and arrow key, Home and
End navigation between rows using a roving tabindex. Every cell is set with `textContent`, so a host
name or title containing markup shows as text. Tests: `tests/test_ui_events.py`.

### History charts

The History view lists the series from `GET /internal/v1/latest` and, for the chosen series and range, reads `GET /api/v1/hosts/{host}/history` and `GET /internal/v1/gaps` (scope `read:metrics`, so the session login and the source allowlist apply). It adds no endpoint. The hub decides between raw samples and hourly rollups from the range length, so the range selector only chooses the span: up to 24 hours reads raw samples and longer ranges read rollups, and the response `resolution` field is shown to the reader. The chart is built in `app.js` with `createElementNS`: an average line and a minimum to maximum band per label set, axis labels, and a shaded, dashed rectangle for each interval the gaps endpoint reports, so missing data is visible and never interpolated. The gap threshold is twice the step, at least 120 seconds. The SVG has a title and description, and a table of the same buckets plus a list of the gaps give a text alternative. All labels are set with `textContent`, no style attributes are written, and no third-party origin is referenced. Tests: `tests/test_ui_history.py`.

## Security model

Control summary for Phase 3, each labelled honestly. Enforced means the code
refuses the request and a test proves it. Advisory means it depends on how the
operator deploys it.

| Control | Label | Test |
|---|---|---|
| Default deny: every route except health needs a session, key or certificate identity | Enforced | `tests/test_phase3_exit.py`, `tests/test_auth.py` |
| Revoked key rejected on its next request | Enforced | `tests/test_phase3_exit.py` |
| One audit row per authenticated request and per 401 or 403, none for health | Enforced; append-only at the application layer only | `tests/test_phase3_exit.py` |
| Password lockout, uniform login failure, CSRF token on cookie writes | Enforced | `tests/test_login.py` |
| Non-loopback bind refused without TLS | Enforced, override `HOSTWATCH_ALLOW_INSECURE_BIND=1` | `tests/test_config.py` |
| Specific-IP plain HTTP bind with `HOSTWATCH_ALLOWED_CLIENTS`; other socket peers get 403 and a `source_denied` audit row before authentication | Enforced as exposure control only, not authentication; relies on `network_mode: host` for real client addresses | `tests/test_source_allowlist.py`, `tests/test_config.py` |
| All role with a specific-IP bind also listens on 127.0.0.1 so the local agent delivers; failure to bind either address stops startup | Enforced | `tests/test_config.py` |
| Loopback as the default bind | Advisory: it limits exposure and is not authentication | none |
| Proxy mode client certificates | Peer allowlist and binding lookup enforced; proxy verification and header stripping advisory | `tests/test_mtls.py` |
| Operator CLI | Advisory: protected only by access to the data directory | `tests/test_cli.py` |
| Audit log tamper resistance | Advisory: a person with write access to the database file can edit it | none |

Current (enforced): the hub binds to 127.0.0.1 by default, every endpoint
except health and login requires a session, a scoped API key or the ingest-only legacy token (constant time compare) and is audited, the
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

Boolean environment variables (enforced): every boolean setting is read by one
helper, `parse_bool` in `config.py`. It accepts 1, true, yes, on as true and 0,
false, no, off or empty as false, case-insensitively, and raises a `ValueError`
naming the variable for anything else, so a misspelt value cannot silently
disable `HOSTWATCH_ALLOW_INSECURE_BIND` or `HOSTWATCH_LEGACY_TOKEN_DISABLED`.

TLS serving (enforced): `HOSTWATCH_TLS_CERT` and `HOSTWATCH_TLS_KEY` are passed
to uvicorn as `ssl_certfile` and `ssl_keyfile` by `uvicorn_kwargs` in
`__main__.py`; `HOSTWATCH_TLS_CLIENT_CA` adds `ssl_ca_certs` with client
certificates requested but not required. `Config.validate` refuses a
non-loopback `HOSTWATCH_HUB_BIND` without a certificate and key, unless
`HOSTWATCH_ALLOW_INSECURE_BIND=1`, which logs a warning. The bind check is
exposure control only and is not authentication. Without TLS, a non-loopback bind
is also accepted when `HOSTWATCH_HUB_BIND` is one specific address (not 0.0.0.0, `::`
or any unspecified address) and `HOSTWATCH_ALLOWED_CLIENTS` is a non-empty list of
individual IPv4 or IPv6 addresses (parsed with `ipaddress`; CIDR ranges, hostnames and
empty entries are refused naming the entry); startup logs a warning that traffic is
unencrypted. With TLS the list is optional. When set, a middleware that runs before
authentication compares the socket peer (`request.client.host`, never a forwarded
header, IPv4-mapped IPv6 normalised) with the list and always admits loopback so the
local agent can ingest. Other peers get 403. The first denial per peer is written as an audit row (actor `anonymous`,
kind `source_denied`); later denials from that peer are only counted, and the first one after
60 seconds writes a single summary row whose detail carries `denied_since_last_row`. At most 4096
peers are tracked, with extras sharing one bucket, so a scanner cannot grow the database without
bound. Every audit writer stores the request path with control characters replaced by `?` and
capped at 256 characters (`sanitize_audit_path` in `store.py`). Scoped IPv6 entries (a `%zone`)
are refused in the list and in `HOSTWATCH_HUB_BIND`, the list must contain at least one unicast
address that is not loopback, unspecified, multicast or broadcast, and multicast or broadcast bind
addresses are refused. Audit retention is described in the README. The allowlist is exposure control, not authentication: allowed
clients still need a session or key. It depends on `network_mode: host` so the hub
sees real client addresses; behind NAT or a proxy, list the proxy's address, which then
admits everything that proxy forwards. `HOSTWATCH_TLS=1` does not start
a listener; it only marks cookies `Secure` (advisory), and a configured certificate
and key mark them `Secure` too.

Local agent delivery (enforced): in the all role the agent posts to the hub over
loopback (`local_agent_hub_url` in `__main__.py`). A specific-address bind does not
accept loopback connections, so `listen_addresses` returns the configured address
plus `127.0.0.1` for the all role, and `bind_sockets` binds both before serving them
from one uvicorn server. If either bind fails, startup raises with the address named
rather than letting batches queue silently. The hub role and loopback or wildcard
binds use the single configured address. The three accepted non-loopback cases are
TLS, a specific address with a source allowlist, and the explicit insecure override.
Covered by `tests/test_config.py`.

Operator CLI (enforced by file access, not by the network): `cli.py` provides
`bootstrap-admin`, `user create|disable|unlock|passwd|grant-admin|revoke-admin` and `key create|list|revoke`.
It opens the SQLite database directly, so whoever can write the data directory
can run it; it is not reachable over HTTP. Bootstrap refuses to run when any
user exists. Passwords come from getpass or one stdin line, never from
arguments. Secrets are printed once to stdout and only hashes are stored.
Disabling a user or changing a password revokes that user's sessions. Every
action, including refusals, appends an audit row of kind `cli` with the
operating system user as actor. The audit log is append-only at the
application layer only, as described above; it is not tamper-proof against
someone with write access to the file, which is the same person who can run
the CLI.

## Threat model and quick start documents

`docs/THREAT-MODEL.md` lists assets, trust boundaries, threats and controls, and each control line
carries one of three labels: enforced, advisory or planned. The README quick start is a numbered
list for a fresh Debian 13 host. `tests/test_docs.py` checks that the threat model exists, that
every control line has exactly one label, that the quick start steps are numbered in order, and that
the quick start names only CLI commands the parser defines and `HOSTWATCH_` variables that appear
in the code, the compose file or `deploy/.env.example`. It does not run any command.

## Isolation for tests and agents

Nothing in the test suite touches real hardware. Collectors take their sysfs
and procfs roots from config, HTTP clients are mocked with `httpx` transports,
and the database lives in a pytest temporary directory. The program is only
exercised through the test suite on development machines; real-hardware checks
happen when the owner deploys the container on MediaIn-SVR.

## TrueNAS API client

`hostwatch/truenas/client.py` is a read-only JSON-RPC 2.0 client over WebSocket (the `websockets`
library). The URL comes from `HOSTWATCH_TRUENAS_URL` and the API key from the file named by
`HOSTWATCH_TRUENAS_API_KEY_FILE`, read at connect time. Controls, all enforced in code:

- Method allowlist: `auth.login_with_api_key`, `system.info`, `system.boot_id`, `pool.query`,
  `disk.query`, `disk.temperatures`, `alert.list` and `pool.scrub.query`. The check runs in the one
  function that writes a frame, so any other method raises `MethodNotAllowed` before anything is
  sent. The key given to it should still be a READONLY_ADMIN key, so the server refuses changes too.
- TLS verification is on for `wss://`; `HOSTWATCH_TRUENAS_CA` adds a private CA bundle and
  `HOSTWATCH_TRUENAS_INSECURE` turns verification off explicitly. A plain `ws://` URL is refused
  unless the host is loopback or the insecure flag is set, because the login frame carries the key.
- A timeout (`HOSTWATCH_TRUENAS_TIMEOUT_S`, default 10 seconds) covers connect, login and the call.
  A dropped connection is retried once on a fresh connection with a new login. Every failure
  returns a `Result` with `available` false and a reason built from class names, never a guessed
  value. The key is held in a `Secret` and does not appear in logs, reasons or reprs.
- `{"$date": ms}` values are converted to epoch seconds.

The client is not yet called by a collector; the TrueNAS collector slices build on it.

## TrueNAS deployment

`deploy/truenas/compose.yaml` runs the agent role as a TrueNAS custom app with the same limits as the Debian
compose file: read-only root, all capabilities dropped, no privileged mode, uid 10001, read-only `/sys` and
journal mounts, host networking and the host `/proc` not mounted. The hub URL and ingest key come from an
`env_file` on the data dataset and the TrueNAS API key from a mounted file, so the app definition holds no
secret. `deploy/truenas/rapl-postinit.sh` is registered as a Post Init script because TrueNAS host changes do
not survive updates. It is a dry run unless given `--apply`, needs root to apply, is idempotent, and changes
only the group and mode of `energy_uj` files under the powercap tree and, read-only, of `/sys/fs/pstore` and
its files (advisory control; it widens access to the PLATYPUS side channel and to crash dumps that can
contain kernel memory fragments for members of the group). On Debian `scripts/pstore-access.sh` does the
pstore part with a unit ordered after `sys-fs-pstore.mount`. The hub side uses the specific-address bind with
`HOSTWATCH_ALLOWED_CLIENTS` and a per-agent ingest key. See `docs/deploy-truenas.md`.

## Remote agent deployment

`deploy/agent/docker-compose.yml` runs the agent role on the Raspberry Pi or any Debian host with
the same limits as the other deployments: uid 10001, read-only root filesystem, all capabilities
dropped, no privileged mode, host networking, read-only `/sys` and journal mounts, and the
data volume as the only writable path. The hub URL and the per-agent ingest key come from an
untracked `.env`. `docs/deploy-agents.md` describes the three-host layout and the hub settings
(specific-address bind, `HOSTWATCH_ALLOWED_CLIENTS`, one ingest key per agent). `tests/test_agent_deploy.py`
checks the compose file and the guide.

## Platforms

Linux (Debian 13 amd64) first. The Raspberry Pi (arm64), TrueNAS SCALE, and a
native Windows agent follow once the Linux path passes its exit tests. Windows
agents will push the same `Batch` schema.

## Hub validation

`Sample.ts` and `Event.ts` accept only finite numbers. A batch carrying NaN or
infinity is rejected with status 422 and nothing in it is stored or
acknowledged, so the agent treats it as a permanent rejection. The 422 body
omits the rejected input, because that input cannot be encoded as JSON. Events
are inserted with `ON CONFLICT(host, dedup_key) DO NOTHING`, so only the
uniqueness conflict is ignored and any other constraint failure raises.

### Admin screens

Two tabs, API keys and Audit log, are hidden until the page learns that the session belongs to an administrator. It learns this by calling `GET /api/v1/admin/keys` after sign in and revealing the tabs only when that call succeeds. Hiding the tabs is cosmetic. The enforced control is `require_admin` in `hub.py`, which answers 403 to every non-administrator on all four admin routes, and the tests assert that. The screens add no endpoint and use `GET /api/v1/admin/keys`, `POST /api/v1/admin/keys`, `POST /api/v1/admin/keys/{id}/revoke` and `GET /api/v1/admin/audit`. Every state-changing call goes through the single `apiPost` helper in `app.js`, which sends the `X-CSRF-Token` header, so the existing session CSRF check applies. The secret of a new key is placed in the page once, in an alert region, and is removed from the DOM when the reader dismisses it, switches view, creates another key, signs out or leaves the page. It is not stored anywhere else and the response is marked `Cache-Control: no-store`. Revoking asks for a second, in-place confirmation before the request is sent. The audit view only reads: the hub has no write or delete route for the audit log, and the page offers none. All values, including the audit detail JSON, are set with `textContent`. Tests: `tests/test_ui_admin.py`.

### Phase 5 exit test

`tests/test_phase5_exit.py` asserts what can be proved without a browser: for a hub with healthy,
warning and degraded hosts, `GET /api/v1/ui/status` lists the degraded host first with the text
label Critical and a banner naming it, the banner precedes the host panels in `index.html`, `app.js`
renders the text label and a state class, and the package data in `pyproject.toml` plus the
Dockerfile install step ship the web assets. Rendering, contrast and the 5-second criterion are
owner checks recorded in `UNVERIFIED.md`.

## Phase 6 exit test

`tests/test_phase6_exit.py` runs a fake upsd bound to 127.0.0.1 through the NUT collector and the
threshold engine and asserts `ups.on_battery` then `ups.on_line`. It then delivers the on-battery event
to the hub, posts an abrupt-end boot event for the same host with a mocked Home Assistant plug history
that shows an overlapping outage, and asserts a critical `boot.power_loss` event beside the kept
`boot.unknown_unclean`, with the plug intervals and the UPS event in `detail.power_witness`. A boot
with no witness configured stays `unknown_unclean`. The real UPS and plug pulls are owner checks in
`UNVERIFIED.md`.

### ZFS pool state

The `zfs` collector reads `<procfs>/spl/kstat/zfs/<pool>/state` for every directory that holds a
`state` entry. The file is readable without privilege on TrueNAS-SVR. Each pool yields a
`pool_state` sample with labels `pool` and `state`. The hub maps the text: ONLINE is ok;
DEGRADED, FAULTED, UNAVAIL and SUSPENDED are critical; any other text is unknown and never ok.
A state file that cannot be read gives a sample with no value, which is unmeasured. The source is
reported not present only when the zfs kstat directory is readable and empty, or is missing while
`/proc` is readable. The pool list is a separate group from `raid`, so a host with both md and
ZFS shows both. Pool state events are not part of this slice; the TrueNAS API view is merged into the same pool component as described under the TrueNAS source.

### Raspberry Pi throttling

The `rpi` collector detects a Pi from `<procfs>/device-tree/model` or `<sysfs>/firmware/devicetree/base/model`. It reads the firmware throttled bitmask from `<sysfs>/devices/platform/soc/soc:firmware/get_throttled`, or from the file named by `HOSTWATCH_RPI_THROTTLED_PATH`, and emits one `throttle_flag` sample per decoded bit (under-voltage, frequency capped, throttled and soft temperature limit, each as now and has-occurred), a `throttled_raw` sample and a `soc_temp` sample from the thermal zone of type `cpu-thermal`. A Pi without the bitmask file is unavailable with a reason that names the `vcgencmd get_throttled` alternative, and its flags are never reported as zero. A host is reported not present only on positive evidence: a model file that was read and names no Pi, or model files missing from readable trees with no throttled file and no configured path. An unreadable model file with a throttled file or configured path leaves the source present, detected or unavailable with a reason.

The hub summary adds a `pi_throttling` component: under-voltage now is critical, capped, throttled or soft limit now is a warning, and any has-occurred bit is a warning until a reboot clears it. The SoC temperature joins the temperature list with the CPU thresholds. The `pi` group is optional and appears in `unmeasured` or `not_present` only for hosts whose agent sent an `rpi` row. The Orion, Prometheus and Home Assistant outputs do not yet publish the Pi component separately; it does count toward the overall status.
