# Architecture

This document describes how hostwatch is put together so that new work fits
the existing shape. `PLAN.md` holds the phase goals and exit tests, and
`CLAUDE.md` holds the working rules.

## Process

One Python package and one container image, with one role: the agent. It runs collectors and
event sources on the host it is installed on and sends what it finds to Observe as OpenTelemetry
(OTLP) over HTTP with a bearer ingest key. It listens on no port. Observe stores the data, shows it
and raises the alerts. The hostwatch hub, its web UI, its database, its API keys and its Home
Assistant, Orion and Prometheus outputs were retired with this conversion, and the old batch wire
format went with them: nothing reads a `Batch` or posts to `/internal/v1/ingest` any more. There is
no migration path from the old format; a host is redeployed with the new agent and a new ingest key.

`hostwatch-control` is a separate daemon and is unchanged by the conversion. See the section on its
verification below.

## Collectors

Each collector in `hostwatch/collectors/` subclasses the base in `base.py`,
detects whether its source exists on this host, and returns samples. A source
that is absent or unreadable is reported in `SourceStatus` as unavailable with
a reason. A sample whose value is `None` is dropped by the mapping, never sent as
zero. A collector declares its polling tier (`tier`) and whether the agent also
watches it for events between polls (`event_watch`); see Polling tiers and sending. Collectors read from roots given in config (`HOSTWATCH_SYSFS`,
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
found errors, is a warning. The kstat `zfs` source and the `truenas` source report the same pool
separately, and Observe, not the agent, decides how to present them together. The WebSocket client passes `proxy=None`, so an
`HTTPS_PROXY` or `ALL_PROXY` variable in the container never carries the login frame.

Alerts are events of kind `truenas.alert` from a second event source, `truenas_alerts`, read
after the collectors in the same cycle. Dismissed alerts are included but are always info, with `dismissed` true in the detail. Otherwise levels map to severity:
INFO and NOTICE to info, WARNING to warning, ERROR, CRITICAL, ALERT and EMERGENCY to critical,
and an unknown level to warning. The dedup key is the alert uuid plus its `last_occurrence`, so
the agent sends an occurrence once and Observe keeps one row per key across restarts.

### NUT client (`nut`)

The `nut` collector asks a Network UPS Tools server for UPS state. It is off unless `HOSTWATCH_NUT_HOST` and
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
`nut` source on every read (the collector sets `retry_each_cycle`), marks it
unavailable for the cycle that failed, and marks it available again as soon as a
poll succeeds, so an on-battery transition in between is not missed. Third, the
credential held in `Config` (`ingest_key`) uses the `Secret` string type, whose repr is
redacted, so a printed or logged `Config` never shows it. The NUT password is held only as a
file path. The redaction covers repr only; code that formats a secret with `str()` still gets
the value.

## Data flow

```
collectors  --tier runs-->  otel_map  -->  otlp encoder  -->  outbox  -->  POST /v1/metrics
event sources + watched sources --every 5 s--> otel_map --> otlp --> outbox --> POST /v1/logs
Observe  --GET /internal/v1/agent-config-->  tier rates  --> scheduler
```

The sender is `Agent.flush` in `hostwatch/agent.py`. It posts only to `/v1/metrics` and `/v1/logs`
and reads only `/internal/v1/agent-config`. Each request carries `Authorization: Bearer <ingest key>`,
the content type of the chosen encoding, `Content-Encoding: gzip` unless turned off, and an
`Idempotency-Key`. The resource names the host (`host.name`), which Observe checks against the host
the key is bound to.

## Polling tiers and sending

`hostwatch/tiers.py` holds the tiers and `TierSchedule`. A collector declares its tier in a class
attribute: `device_metrics` (the default: CPU, memory, hwmon, RAPL, UPS, thermal controller),
`storage_health` (md, ZFS, Scrutiny, TrueNAS, Windows storage), `smart` (`win_smartctl`) and
`inventory` (reserved; no collector reads inventory facts yet). The `availability` tier has no
collectors: each run sends the heartbeat (`observe.agent.heartbeat`), the source status of every
source (`observe.source.available` and `observe.source.present`) and the rate in force for each tier
(`observe.agent.poll.interval`, one series per tier, so Observe knows the cadence to expect). An
unavailable source carries its reason, cut to 512 characters, as the attribute `observe.source.reason`
on its `observe.source.available` point. Every tier, not only the availability tier, also sends an
`observe.source.change` log when a source's availability differs from the last one reported, with the
same reason attribute, so a failure on a slow tier is logged when it happens and not up to an hour
later. A source first seen available, or positively absent from the host, is recorded without a log;
the record is held in memory, so a restart reports a source that is still unavailable once more. The
design asks for the tier and its rate to travel with each batch; a separate gauge was chosen over a
resource attribute because a resource attribute that changes with the rate would make a new
resource every time an admin edits a rate. Whether Observe reads that gauge is recorded in
`UNVERIFIED.md`.

Defaults are 30 s, 60 s, 15 min, 1 h and 1 h for the five tiers. At start and every five minutes
the agent calls `GET /internal/v1/agent-config` with the ingest key. Every rate in the answer is
clamped to the lowest and highest value Observe itself accepts for the tier (5 s to 1 h,
10 s to 1 h, 1 min to 24 h, 5 min to 24 h, 10 min to 24 h), so a bad answer can neither make the
host spin nor silence a tier. A tier that is missing, not a number, not finite or a boolean keeps its
current rate. When Observe cannot be reached or refuses the key, the rates in force stay (the
defaults before the first answer) and the agent asks again after one minute, logging only when the
outcome changes. A lowered rate applies at once: no tier waits longer than its new interval.

A tier that is due runs once and is rescheduled one interval after its due time, so a slow collector
does not stretch the cadence, and an agent that fell behind does not burst. One tier run is one
outbox entry: the metrics of the tier and the logs it produced, as separate OTLP requests that share
the entry id.

Events are not a tier. The loop wakes at least every five seconds and, on each wake, reads the
event sources (the pending boot events, pstore, rasdaemon, the journal, TrueNAS alerts, the Windows
event log) and turns what it finds into OTLP logs sent on that pass. Every fifteen seconds it also
reads the cheap local sources whose state changes are events (`event_watch`: md, ZFS and NUT) and the
health probe of each slow storage source (`event_probe`) for threshold events only; their readings go
out on their own tier, not every fifteen seconds. The probe is `probe()` on the collector: the whole
`collect()` where that is one request (Scrutiny, Windows storage health, TrueNAS pools and alerts) and
`smartctl -H` for Windows SMART, which reads only the drive's own verdict. A RAID failure, a degraded
pool, a SMART, Scrutiny, Windows storage or TrueNAS failure, a UPS on battery or a kernel message
therefore leaves the host within about twenty seconds even when the storage tier runs every fifteen
minutes or every hour.

No collector runs on the loop thread. `hostwatch/runner.py` starts each `collect()` and `probe()` on a
worker thread, one at a time per collector, and the loop waits for a started worker only a quarter of a
second (`EVENT_GRACE_S`, `TIER_GRACE_S`). A tier is started on one pass and queued on the pass where all
its collectors have answered, so a slow collector delays only its own tier. A collector that does not
answer within its `time_limit_s` (60 seconds, and 320 seconds for Windows smartctl) is given up on: its
source is reported unavailable with a `CollectorTimeout` reason, its late answer is discarded, and it
is not started a second time while the first call is still running, so a hang costs one thread. The one
wait the loop still makes is the quarter second per pass, and `detect()` still runs on the loop thread
(the Scrutiny and TrueNAS detect calls have their own 10 second timeouts).

Delivery runs after every pass, and also straight after the event read, so events leave before a slow
tier run can hold them back. `flush` sends the outbox log requests first and metrics requests second,
each oldest first, so after an outage the events go before the backlog of readings. It removes a request
only after a 2xx answer:

* A 200 with a partial success (protobuf or JSON, as sent) is acknowledged, because the rejected
  items would be rejected again. The rejected count and Observe's message are logged, counted in the
  outbox and reported in the `outbox` source status.
* 400, 409, 413, 415 and 422 can never succeed for the request that was sent. The request moves to
  the `dead_letters` table with the status and the problem text (the last 1000 are kept), and the
  next request is sent.
* Everything else (a network error, 401, 403, 404, 408, 429 and every 5xx) leaves the request
  queued. The loop waits before the next attempt, doubling from 5 s up to 5 min and never less than
  a `Retry-After` the answer gave (also capped at 5 min), while collection continues. A 401 or 403
  logs that the key or the host binding is wrong. The `outbox` status reports how long delivery has
  been stalled and how many requests are kept.

The credential is added when a request is sent and is never written to the outbox. Observe answers a
repeated `Idempotency-Key` with a 200 and stores nothing, so a request sent twice because an answer
was lost is stored once.

## OTEL mapping (`hostwatch/otel_map.py`)

`hostwatch/otel_map.py` converts collector samples, source statuses and events into OpenTelemetry
points and log records, following section 3 of the Observe data API design. It is pure conversion
with no network access, and the OTLP encoder and sender consume its output. Resource attributes
come from `resource_attributes`, and each collector is its own instrumentation scope named
`hostwatch.collector.<source>`. Percentages become ratios from 0 to 1, units are UCUM, and a sample
with no value is dropped rather than sent as zero, because the source status metrics already say
the source could not be read. Memory and swap usage are split into used and free from the total
and the available reading. A pair the table does not list is sent as
`observe.legacy.<source>.<metric>` with the unit converted where that is obvious, and logged once
per process. Events map to logs named `hostwatch.<kind>`, except boot classifications, which use
`observe.host.boot` with severity 9 or 13 as the design gives them; the original severity stays in
the `observe.severity` attribute. Event detail is flattened under `observe.detail.*` with a cap on
keys and value length. The golden inputs and outputs live in `tests/fixtures/otel/`, one file per
collector plus `events.json`, so Observe can reuse them. The scheduler and the sender in `hostwatch/agent.py` use it, as described under Polling tiers and sending.

## OTLP encoder (`hostwatch/otlp.py`)

`hostwatch/otlp.py` turns mapped points and log records into `ExportMetricsServiceRequest` and
`ExportLogsServiceRequest` bodies. The encoder is hand written, so the agent gains no runtime
dependency. A request is built as an OTLP JSON tree and the protobuf bytes are written from the same
tree with a small field table, so the two encodings cannot drift apart; protobuf is the default and
JSON is an option. Gzip is optional and uses a zero timestamp so a body is reproducible. Limits match
Observe's ingest: 1 MiB on the wire, 4 MiB inflated, an inflate ratio under 100, 5000 points or 500
log records per request, 64 resource attributes, 32 attributes per point or record, keys up to 128
characters and string values up to 1024. A set of points or records that does not fit is split into several requests,
each with the full resource, by count first and then by halving on size. Points Observe would
refuse (a value that is not finite, an over-long name) are skipped and counted, never sent as zero.
Each request's `Idempotency-Key` is `hw-<entry id>-<signal initial><part>`, built only from the
outbox entry id, the signal and the position in the split, so a replay sends the same key and the
same bytes; an id that is not short printable ASCII is replaced by a hash. The builder returns the
path, headers (without credentials) and body of each request and does no network access. Tests
decode the protobuf with an independent decoder in `tests/otlp_decoder.py`. The same module reads an
answer's partial success (`parse_partial_success`), from protobuf or JSON, with the same small
hand-written field reader. The outbox stores the built requests; see Durable outbox.

## Boot classifier

`hostwatch/events/boot.py` holds the heartbeat writer and the classifier. Each
agent loop atomically rewrites `heartbeat.json` every 15 seconds, in the data directory (temp
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
not a power loss: a power cut and a hang cannot be told apart from the host alone, so the
agent never reports `power_loss`; Observe may combine this event with its own evidence. Kinds are
never inferred from absence of evidence.

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

## pstore ingestion

`hostwatch/events/pstore.py` reads the directory named by `HOSTWATCH_PSTORE`
(default `/host/pstore`) read-only. Every regular file becomes one event; symlinks are skipped.
Only `dmesg-*` files are classified, and only by explicit markers: `Kernel panic - not syncing` or a `Panic#N` header gives `pstore.kernel_panic`; an `Oops#N` header or a line starting with `BUG:` or `Oops:` gives `pstore.kernel_oops`; everything else is `pstore.record`. The dedup key is
`pstore:<file name>:<first 16 hex of the sha256 of the whole file>`, hashed in chunks, so re-reading gives
the same key and a rewritten record gives a new one. For a file over 1 MiB the excerpt comes from the head, the marker scan covers the head and the tail, and `detail.truncated` is true. Files are never deleted or
modified. A missing or unreadable directory yields source `pstore` unavailable
with a reason and no events; an empty directory is available with no events. If records exist but none could be read, the source is unavailable with a reason; if some failed, it stays available and the reason carries the failed count.
The agent reads it on every event read (every five seconds) and sends each record once per process.

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
commit with the requests carrying the rows (see the outbox section).

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
delays a sample cycle: each event read collects the previous worker's result,
parses it and starts the next read. Parsing and cursor staging stay on the
agent thread so the cursor remains tied to the events it produced. When a cycle
fails after the journal read, the staged cursor is discarded and the background
reader is rewound, so the next read starts from the last committed cursor and
the same entries are read again and delivered once. The
`ataN: SATA link up` message counts as a link reset only after a reset on the
same port was seen, and RAID `[U_]` status needs an `mdN` or `md/raid` context.
The cursor is a progress marker that commits
with the requests carrying the entries read, so a crash after a read re-reads the
entries instead of skipping them. An older `journal.cursor` file is imported once
when no marker exists.

## Durable outbox

`hostwatch/outbox.py` keeps `outbox.db` (SQLite, synchronous FULL) in the data directory. It holds
encoded OTLP requests, after every string has been cleaned (an unpaired surrogate or a control
character other than tab, newline and carriage return becomes U+FFFD, then the Observe length caps
apply). An item that still cannot be encoded is isolated, left out of its request, logged and counted
in the outbox's `quarantined` counters and in the `outbox` source reason, and the other items of the
entry are queued as usual. The outbox holds the requests (path, headers including the `Idempotency-Key`, body, signal and the number of
points or log records) in the `requests` table, so a replay after a restart sends the same bytes
under the same key. The old `batches` table of earlier versions is dropped when the file is opened.

* **Bounds.** At most 2000 requests and 32 MiB of bodies. A metrics request older than 6 hours is
  dropped; a logs request older than 7 days is dropped. Over a limit, the oldest metrics request goes
  first and a logs request only when no metrics request is left, because a fresh reading replaces a
  lost one and a lost event cannot be replaced. Every drop is counted by signal, a warning is logged
  and the `outbox` source is reported unavailable, with the counts in the reason, until the queue
  drains.
* **Dead letters.** See the list of statuses above. A row whose headers cannot be decoded moves to
  `dead_letters` with status 0 and the error.
* **Corruption.** If SQLite reports `outbox.db` as not a database or malformed, it is renamed, with
  any `-wal`, `-shm` or `-journal` file, to `outbox.db.corrupt-<timestamp>`, an error is logged, and a
  fresh outbox is started. The `outbox` status names the renamed file, because the queued requests
  and markers in it are lost. Locked or I/O errors are not treated as corruption: the file is left
  alone and the error is raised.
* **Guarded work.** Each tier run and each event read runs inside a guard. An exception is logged,
  markers staged by that unit are discarded so nothing is skipped, the threshold state is restored,
  the journal reader is rewound, the source `agent` is reported unavailable with the reason, and the
  next unit runs normally.

Progress markers (`journal.cursor`, `rasdaemon.high_water.<table>`, `pstore.sent_keys`,
`boot.pending_events` and `thresholds.state`) are rows in the `markers` table. Event sources read
them with `get` and stage new values with `stage`. Staged values are visible at once but become
durable only when `enqueue` writes the requests, in the same transaction. A crash before that point
repeats the read and Observe deduplicates by key; a crash after it resumes after the queued events.

## Threshold events

`hostwatch/events/thresholds.py` evaluates rules on the samples of every tier run and of every
watched read, after the sources have been read. Rules are edge-triggered, with one event on entry and
one on recovery: `md.degraded` and `md.degraded_cleared` (mdraid `degraded` above 0 and back to 0),
`md.sync_changed` (the `sync_action` label changed), `source.unavailable` and `source.available` (a
source that was seen available went away or came back), `source.disappeared` and `source.returned`
(a source that was present and available reports present false, critical), and
`scrutiny.status_raised` and `scrutiny.status_cleared` (Scrutiny `device_status` grew, or returned to
0), plus the Windows storage health rules. A steady state gives no repeat events. A sample value of
None is unknown: it never triggers a rule and never counts as a recovery, so an unreadable source
cannot look like a recovered array. A source that is unavailable from the start is not a flip and
gives no event. The first value seen for an array's sync state is a baseline, not a change.

UPS events read the `nut` `ups_status_flag` samples. The state is `OL`, `OB` or `LB` (low battery
wins), kept under rule key `ups.power|ups`. A pass in which any of the three flags is unknown
changes nothing. A UPS first seen on line is a baseline; first seen on battery raises
`ups.on_battery`. Low battery that clears while the UPS is still on battery updates the state
without an event.

State is held in memory and saved in the outbox marker `thresholds.state` in the same transaction as
the requests that carry the events it produced (`ThresholdEngine.dump` and `load`), so a restart does
not repeat an open condition and a failed unit does not lose one. The agent no longer asks a hub for
stored events. Unreadable saved state is ignored, which means one event may repeat after a restart;
Observe keeps one row per dedup key. Threshold events use source `thresholds` and a dedup key made of
the kind, rule key and event time.

Every event source rides in the same logs requests: the boot classification, pstore, rasdaemon, the
journal watcher, the TrueNAS alerts and the threshold events. Event sources are plain callables in
`Agent.event_sources`, and each one's status is reported in the availability tier. A source that
raises is reported unavailable with the error as the reason.

## Image dependency install

The Dockerfile copies `requirements.lock` and installs it with
`pip install --require-hashes --no-cache-dir -r requirements.lock`, then installs the package with
`--no-deps`. The base image is pinned by its multi-arch index digest. `tests/test_release.py`
parses `pyproject.toml` and the lock and checks that every runtime dependency is pinned with `==`,
that every lock entry carries a sha256 hash, and that the Dockerfile uses `--require-hashes`.

## Container healthcheck and image labels

The agent serves nothing, so `python -m hostwatch healthcheck` reads `agent.alive` in the data
directory, which the agent loop rewrites every fifteen seconds with the time, and exits 0 only when
it is less than two minutes old. It says the loop is turning. It does not say Observe is receiving:
delivery trouble is reported by the `outbox` source and its stalled-delivery note. The Dockerfile
`HEALTHCHECK` uses interval 30s, timeout 10s, start period 30s and 3 retries, and sets OCI labels
from the build args `VERSION`, `REVISION` and `LICENSES`. `tests/test_docs.py` checks the command
and the Dockerfile.

## CI supply chain and releases

`.github/workflows/ci.yml` has six jobs. `test` runs pytest. `build` produces one amd64 image tar
that `scan` and `smoke` load, so both check the same bytes. `scan` generates an SPDX JSON SBOM with
anchore/sbom-action and runs trivy at severity CRITICAL with `ignore-unfixed` and exit code 1, so a
fixable critical vulnerability fails CI; unfixed ones are not gated because nothing can be done
about them yet. It uploads SARIF to code scanning and is the only job granted `security-events:
write`; the SARIF upload is skipped for pull requests from forks, which get a read-only token.
`smoke` starts the image with `--network host`, a read-only root, all capabilities dropped and a
tmpfs `/data`, with the agent pointed at an address that answers nothing, and waits for
`python -m hostwatch healthcheck` to pass. That shows the agent starts as the non-root user, finds its
data directory and keeps its loop turning while Observe is unreachable. The key is generated and
masked with `::add-mask::` before use and is never echoed. `image` (push only, needs all three)
publishes the multi-arch image with `edge`, `{{version}}`, `{{major}}.{{minor}}` and sha tags and
passes `VERSION` and `REVISION` build args. `release` runs only for `refs/tags/v*`, is the only job
with `contents: write`, and attaches the SBOM. Every action is pinned to a 40 character commit SHA with
the release in a comment. The SBOM describes the amd64 image; the arm64 variant is not scanned. These
are CI controls on the build, not runtime controls. `tests/test_release.py` reads the workflow text
(PyYAML is not a dependency) and checks the pins, the trivy gate, the smoke job and the tag gate.

## Security model

Enforced by the agent or the container:

* The agent opens no listening port, so it has no inbound surface of its own.
* The ingest key goes only in the `Authorization` header of requests to Observe and is held in memory
  as a `Secret`, whose repr is redacted. It is not written to the outbox, to a log line or to a reason.
* Observe binds the key to one host name and refuses a request whose resource names another host, so
  one host cannot report as another. That check is Observe's, not the agent's; the agent warns when
  `HOSTWATCH_HOST_NAME` differs from Observe's name for the key.
* Redirects are not followed, so a key is never sent to an address the operator did not configure.
* Container limits (non-root uid 10001, read-only root, all capabilities dropped, no privileged mode,
  host mounts read-only, the host `/proc` not mounted) are enforced by Docker from the compose files.
* The TrueNAS API key is read from a file and never logged. The TrueNAS client sends only an
  allowlist of read-only methods.

Advisory only: traffic to Observe is plain HTTP when `HOSTWATCH_OBSERVE_URL` starts with `http://`.
Use `https://` or a trusted LAN segment. The agent verifies the certificate with the default trust
store; a private CA must be added to that store. `docs/THREAT-MODEL.md` has the threats and controls.

## hostwatch-control verification

The `hostwatch/control/` package is the verification half of the per-host command daemon in `docs/CONTROL.md` of
the Observe repository. It is not imported by the collector at import time. The pull loop, results outbox and service
files are described in the section after the executors. Modules:

- `config.py` loads `control.toml` into frozen dataclasses. On POSIX it refuses a file that is not root-owned, a file
  writable by group or others, and a file in a directory writable by group or others (enforced). On Windows it checks
  that the owner is SYSTEM or Administrators only when pywin32 is installed; otherwise the install step must lock the
  file (advisory until a Windows install exists). Service names are limited to plain characters because they reach a command line
  later.
- `identity.py` compares the `host` in `control.toml` with the machine's own name (`socket.gethostname()` and the
  FQDN, each with its short form, lower case, plus COMPUTERNAME on Windows). A different name stops the daemon at
  start with an error naming both. A host whose operating system name differs from its Observe name sets
  `machine_id` in `control.toml`, which must equal `/etc/machine-id` or the Windows MachineGuid, and then only the id
  decides. The daemon repeats the check before every command, so a renamed or cloned disk answers `refused` with
  reason `wrong_machine` and runs nothing. The agent only warns once when `HOSTWATCH_HOST_NAME` differs from the
  machine name, because containers often differ.
- `signing.py` builds canonical JSON (sorted keys, no spaces, UTF-8 without ASCII escaping) and verifies the Ed25519
  signature, sent as base64 beside the command, against the pinned key written as `ed25519:` plus base64. The
  `cryptography` import happens only inside the check, and win32 modules are never imported.
- `state.py` keeps the highest executed seq and the last 1000 ids in one JSON file, written to a temporary name,
  flushed and renamed. A corrupt file is an error, never an empty state.
- `verify.py` runs the checks in order and returns a `Decision` with a reason code on refusal. A command is recorded
  only after the allowlist accepts it, and before it is handed back, so a crash cannot run it twice. A refusal by
  the allowlist uses no seq. A state file that cannot be read or written refuses everything (fail closed).

Parameters are matched exactly, so executors never see a field the allowlist did not check.

### Linux executors

`actions_linux.py` holds `LinuxActions`. Every external command is an argument list handed to an injected `Runner`
(the real one calls `subprocess.run` with `shell=False`), and programs are named by absolute path so the sudoers rule
matches what is run. The executors validate again what the allowlist already checked: header ids, the 0 to 100 duty,
the mode and the service name, all before any call.

- Overrides: the file is read and merged (only `mode` and `[headers.<id>] min_duty` are kept, which is all thermalctl
  accepts), written to a candidate file in the same directory (`overrides.toml.candidate`, mode 0600) and flushed. `thermalctl
  check-config <config> --overrides <candidate>` validates the candidate, and only on success is it renamed over the
  real path. On failure the candidate is deleted, the real file is never touched and the failure is reported with the
  check output. A floor then sends SIGHUP through
  `systemctl kill -s HUP thermalctl`; a mode change runs `systemctl restart thermalctl`, because a reload refuses a
  mode change. An existing overrides file that cannot be parsed fails the action rather than being overwritten.
  Whether every header is mapped before going active is enforced by `check-config`, not duplicated here.
- Controller selection: the fan actions run only when `[fan] controller` in `control.toml` names the executor's own
  controller. The Linux executor refuses them (status `refused`, no command run) unless it is `thermalctl`, and the
  Windows executor refuses them unless it is `thermal-control-suite`.
- Restart: `systemctl restart <unit>` or `docker restart <name>` for `docker:<name>`, only for names in the local list.
- Reboot: a transient systemd timer, `systemd-run --unit=hostwatch-reboot --on-active=<N>s systemctl reboot`, with N the
  delay in whole seconds (not `shutdown`, which rounds to minutes), capped at 999999, and
  `systemctl stop hostwatch-reboot.timer` to cancel. The delay has a minimum of 30 seconds: a configured 0 (or any
  value below 30) is raised to 30, by the `control.toml` parser and again by the executor. While the timer is pending a
  local `hostwatch-control cancel` stops it, so the whole delay is cancellable. A second reboot while one is pending
  fails because the unit name is in use, and is reported as `failed`.
  `main_cancel` is the older body of the local cancel command; `python -m hostwatch control cancel` now runs the
  platform executor's `cancel_reboot` through `daemon.run_cancel`.
- Privilege: a process that is not root prefixes the commands with `sudo -n`. `render_sudoers` produces the sudoers
  rule from the allowlist, and `deploy/hostwatch-control.sudoers` is its output for an example list. The only wildcard
  is the digit pattern in the reboot delay (two to six digits, one rule each). The 30 second minimum is enforced by
  the executor, not by the sudoers pattern. This is an enforced limit on what the account may run as root. The
  sudoers rule names the candidate path `/etc/thermalctl/overrides.toml.candidate`. The overrides file write itself is not a sudo command, so the fan actions still need a process able to write that
  directory as root (see `UNVERIFIED.md`).

### Windows executors

`actions_windows.py` holds `WindowsActions`. It imports no win32 module and runs programs only through the
`CommandRunner` seam of `hostwatch.windows` as argument lists, so it is tested on Linux with fakes. The Thermal Control
Suite pipe is reached through an injectable `PipeClient`; `NamedPipeClient` is the real one and can open only
`ThermalControlSuite.Ipc`. It checks the pipe directory first so a stopped service never blocks, and it runs the
length-prefixed JSON exchange on a daemon thread with a timeout, the same way the read-only status reader does.

- `fan.set_floor` refuses unless `fan.controller` is `thermal-control-suite`, validates the header and the 0 to 100 duty,
  sends `GetFans`, finds the fan by id and sends `SetFanMapping` with every field of the mapping unchanged except
  `MinDutyPercent`, because that request replaces the whole mapping. A `Success` of false from the service is reported
  as `refused` with its error text; a missing pipe or timeout is `failed`. The service applies its own limits and audits
  the change under the caller identity, which is LocalSystem for the daemon. This is an enforced limit on the daemon side
  (allowlist and range) and the service side (its permission check).
- `fan.set_mode` is always refused here. The pipe documents no request that sets dry run, which is a setting in the
  Suite configuration file, so the daemon does not pretend to. The refusal text says so.
- `service.restart` runs `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <script> <name>`
  where the script is the constant `& { param([string]$Name) Restart-Service -Name $Name -ErrorAction Stop }`. The name is
  never part of the script text. It must be in the local list, match the strict service name pattern and not start with
  `docker:`. The pattern allows no space, quote, `$`, backtick, `;`, `|` or leading dash, which is the enforced
  protection against a name being read as anything but one token.
- `host.reboot` runs `shutdown.exe /r /t <delay_s>` with the same 30 second minimum (capped at the 10 year maximum
  of the tool) and `cancel_reboot` runs `shutdown.exe /a`, which works for the whole delay.

### Pull loop, results outbox and service files

`daemon.py` holds `ControlDaemon`, `outbox.py` the results outbox and `service.py` the Windows service host. The
daemon only dials out and opens no port. Each cycle does these steps in order:

1. Replay queued results oldest first. A result leaves the queue after a 2xx answer, after a 409
   (Observe already has a final result), or when it is parked. A permanent 4xx answer (any 4xx except 401, 403, 404,
   408, 425, 429 and 409, so in practice 400, 413 and 422, plus a 404 whose detail is `no such command for this host`)
   parks the result with the reason in the outbox's `parked` table and the next result goes on; a parked result is kept
   for the owner to inspect and is never sent again. Every other failure, including 401, 403, any other 404 and any 5xx,
   leaves the result queued and the cycle reports a delivery error, so nothing is lost while the results route is
   missing.
2. `GET /api/v1/control/commands?host=<host from control.toml>` with `Authorization: Bearer <wpc key>`. A 401 or 403 is
   reported as a rejected key, never with the key. The answer is `{"commands": [{"command": {...}, "signature": "..."}], "cancel": [command ids]}`, where `cancel`
   lists this host's scheduled commands that an admin cancelled.
   After the pull the daemon resolves due reboots, then cancels every listed id it holds a pending reboot for (see
   below). An id it never scheduled is ignored, so a result is only ever posted for a command this host pulled.
3. Sort by `seq` and handle at most 20 commands, one at a time. Each goes through `CommandVerifier`, then the platform
   executor (`LinuxActions` or `WindowsActions`, chosen by `sys.platform`, the Windows module imported only there). The
   result is written to the outbox and delivery is tried before the next command starts. An executor that raises is
   reported as `failed`. A command with no usable id cannot be reported and is only logged.

The body posted to `POST /api/v1/control/results` is exactly the model the Observe results route validates, which
refuses any other field: `{"id","state","output","started_at","finished_at"}` with the two times as floats. `state` is
`done`, `failed`, `refused`, `scheduled` or `cancelled`. A refusal or failure puts its stable reason code from
`verify.py` at the start of `output` (`unit_not_allowed: ...`). The outbox keeps the richer record (`v`, `host`,
`action`, `seq`, `status`, `ok`, `reason`, `received_at`, `outbox_dropped`) and `wire_body` in `daemon.py` cuts it down
at send time; output is clipped to 4096 characters, the amount Observe keeps.

A `host.reboot` that sets its timer is reported `scheduled`, and the outbox records the promise in its `scheduled`
table with the due time. Later the same id is reported `done` when the daemon started after the due time (the host went
down and the service came back), `failed` (`reboot_not_seen`) when the due time plus 30 s passed and the same daemon
process is still running, or `cancelled` when a pull lists the id in `cancel`: the daemon runs the platform executor's
`cancel_reboot`, and a cancel that fails is logged and tried again on the next pull. A local `control cancel` is not
seen by the daemon and later shows as `failed`. A command that is pulled again after it was accepted (Observe has not
recorded its outcome) is never refused as `replayed_id`: the daemon re-sends its stored result from the outbox's
`executed` table (the latest result of the last 1000 commands that ran), or reports `failed` (`result_lost`) when the
result is gone, and it sends nothing while the result is still queued or the reboot is still pending. A `host.reboot`
may carry a `confirm_host` text in its signed params, which is ignored; any other extra parameter is refused as
`bad_params`.

Output is masked and then clipped to 2000 characters (`redact.py`; masking runs on the whole
text first, and an executor's own output is masked before its clip, so a secret cut by the clip is never half shown). The
masked shapes are `wpc_`, `wpi_`, `wpf_` and `hw_` keys, bearer tokens, Authorization headers, `password`, `passwd`,
`secret`, `token` and `api_key` pairs (bare or quoted), PEM blocks (also an unterminated one), hex runs of 32 or more
characters and mixed-case base64 runs of 40 or more. This is a courtesy and not a guarantee that no secret is present. The outbox keeps one row per
command id and status, with the first final result winning (a refusal is not queued when anything real is known about the id, and a queued refusal is replaced by the result of a command that really ran) and holds at most 200 results, dropping the
oldest and counting it (kept in the local record, not sent), because Observe shows a command with no result as `unknown`. A corrupt outbox file is renamed
aside and a fresh one started.

Verification records a command before it runs (at most once). A crash between execution and the outbox write therefore
loses the report and not the safety: Observe shows `unknown` and the command is never run twice.

After a cycle in which the pull failed the wait grows from the interval (5 s by default, 5 to 300) in doubling steps to
60 s. A cycle whose pull succeeded but whose result could not be delivered keeps the normal interval, so pending results
never delay fetching commands such as a cancel. The loop
ends on SIGINT, SIGTERM or a service stop, and results still queued stay on disk for the next start. Startup fails with
a plain message when the `control` extra is missing, `control.toml` is unreadable or writable by group or others, or the
URL or key setting is missing or the key does not start with `wpc_`.

Service files, with their labels:

- `deploy/hostwatch-control.service` runs as `hostwatch-control`, a separate account from the collector, with a
  private state directory, `ProtectSystem=strict` and no writable path except that directory. `NoNewPrivileges` is left
  off on purpose because it would stop `sudo`. The root limit is the sudoers snippet (enforced by sudo). The rest of the
  hardening is defence in depth, not authentication. The unit grants no write to `/etc/thermalctl`, so Linux fan
  actions fail with a clear report until the owner decides how that file is written (see `UNVERIFIED.md`).
- `deploy/windows/install-control.ps1` and `uninstall-control.ps1` register `hostwatch-control`, a service separate from
  `hostwatch-agent`, with its own virtual environment, as LocalSystem with restart-on-failure. The installer locks
  `control.toml` and `control.env` to SYSTEM and Administrators before the key is written. The data folder is the
  installer's `DataDir` service parameter, as for the agent. The ACL is advisory until checked on a host.
- `python -m hostwatch control run` runs the loop in the foreground on either platform.

Import isolation is enforced by `tests/test_control_daemon.py`: a static scan of every module outside `control/` for an
import of `hostwatch.control` that runs at import time, and a fresh interpreter that imports the collector entry points
and checks that no `hostwatch.control` module is loaded.

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

`deploy/truenas/compose.yaml` runs the agent as a TrueNAS custom app with the same limits as the Debian
compose file: read-only root, all capabilities dropped, no privileged mode, uid 10001, read-only `/sys` and
journal mounts, host networking and the host `/proc` not mounted. The Observe URL and ingest key come from an
`env_file` on the data dataset and the TrueNAS API key from a mounted file, so the app definition holds no
secret. `deploy/truenas/rapl-postinit.sh` is registered as a Post Init script because TrueNAS host changes do
not survive updates. It is a dry run unless given `--apply`, needs root to apply, is idempotent, and changes
only the group and mode of `energy_uj` files under the powercap tree and, read-only, of `/sys/fs/pstore` and
its files (advisory control; it widens access to the PLATYPUS side channel and to crash dumps that can
contain kernel memory fragments for members of the group). On Debian `scripts/pstore-access.sh` does the
pstore part with a unit ordered after `sys-fs-pstore.mount`. See `docs/deploy-truenas.md`.

## Agent deployment

`deploy/docker-compose.yml` (MediaIn-SVR), `deploy/agent/` (a Debian host such as the Raspberry Pi),
`deploy/truenas/compose.yaml` (the TrueNAS custom app) and `deploy/windows/install.ps1` (the Windows
service) all run the same agent. Each takes the Observe URL and the ingest key from an env file that
is not committed. `docs/deploy-agents.md` and `docs/deploy-truenas.md` give the steps.

## Platforms

Linux (Debian 13 amd64), the Raspberry Pi (arm64), TrueNAS SCALE and a native Windows
agent all send the same OTLP to Observe; only the collectors and the event sources differ.

### Windows platform seam

`hostwatch/windows/__init__.py` defines four small protocols that every Windows collector reads through, so
no Windows collector needs a sysfs or procfs path: `EventLogReader` (newest-first events with id, provider,
level, epoch time and message), `CimQuery` (one dict per CIM instance), `PipeStatusReader` (one JSON object
from a named pipe) and `CommandRunner` (a program, an argument list and a timeout, never a shell). A
`WindowsSeam` bundles one of each. `Collector.__init__` takes an optional `seam` and its `sysfs` and
`procfs` arguments are now optional, `build_collectors(cfg, seam)` and `Agent(cfg, seam)` pass it along, and
`detect_platform` returns `windows` when `sys.platform` is `win32` before it looks at any path.

The real readers use only the standard library. `PowerShellEventLogReader` and `PowerShellCimQuery` build a
`powershell.exe -NoProfile -NonInteractive` script around `Get-WinEvent` or `Get-CimInstance` that ends in
`ConvertTo-Json`, run it through the `CommandRunner` with a timeout (30 seconds by default), and parse the
output. Every script begins by setting `[Console]::OutputEncoding` to UTF-8, and `SubprocessRunner` captures bytes
and decodes them as UTF-8 with replacement, so localized event text survives and a stray byte becomes U+FFFD
instead of failing the cycle. The log name, class name, property names and namespace are checked against a strict pattern and
event ids and times are formatted as numbers, so a caller value cannot add PowerShell syntax. A log with no
matching events is an empty list, and any other failure raises `SeamError` with a reason that becomes the
source's unavailable reason. Process-spawning is imported inside `SubprocessRunner.run`, and no Windows-only
module is imported at module import time, so the package imports and is tested on Linux. `real_seam()` builds
the real set and is called only by the Windows agent entry point in `hostwatch/windows/service.py`.

The service class is built lazily and exposed as the module attribute `HostwatchAgentService` through a module level
`__getattr__`, because pywin32 loads a registered service by its dotted class string and the module must still
import without pywin32. `HandleCommandLine` receives that string. `install.ps1` stores `-DataDir` in the service
parameter `DataDir`, which `service_data_dir()` reads before `HOSTWATCH_DATA_DIR` and the default. `Agent.flush`
sends with a 5 second timeout, stops between sends once a stop is requested, and takes an optional deadline; the final
flush in `AgentHost.flush_outbox` uses a 10 second deadline, so a stop is honoured promptly and unsent requests stay in
the outbox.

Tests use `tests/fakes_windows.py`, which loads `tests/fixtures/windows/seam.json` into fake readers and a
recording fake runner, and `tests/test_windows_seam.py` fails if a real reader is constructed. The pipe
protocol of the fan controller service and the PowerShell output shape are unconfirmed on Windows; see
`UNVERIFIED.md`.

### Windows Event Log boot and crash events

`hostwatch/events/winevent.py` reads the System log through the seam's `EventLogReader` for Kernel-Power 41,
EventLog 6006 and 6008, BugCheck 1001 and WHEA-Logger records. The `PowerShellEventLogReader` script now also
returns the record id, an additive key that fakes may omit. `classify_windows_boot()` maps one shutdown's
records onto the existing `Classification` kinds and `boot_event()` builds the event: a BugCheck is
`kernel_panic`, 41 or 6008 without a BugCheck is `unknown_unclean` (a power cut and a hang cannot be told apart
without a witness, so it is never `power_loss`), and 6006 alone is `clean_shutdown`. Windows exposes no boot id,
so the boot id is `win-<epoch seconds of the earliest record>`. Records within 15 minutes of each other form one
shutdown, and a group is classified only once it has been quiet for 15 minutes, because the BugCheck record can
arrive after the Kernel-Power one. WHEA records become `hardware_error` events with `table`, `err_type` and
`err_msg` in the detail, as rasdaemon events have, from source `winevent`.

The bookmark is the time of the newest finished record. In the agent it and the keys of records already
reported are staged as outbox markers (`winevent.bookmark` and `winevent.keys`), so they become durable only
with the requests that carry the events, and a failed unit re-reads the same records. Without an outbox they are
files under `winevent/` in the data directory, saved before the events are returned. The read is oldest first
(`Get-WinEvent -Oldest`) and capped at 500 records. A full window moves the bookmark only to the newest record
returned and treats that record as the present when settling shutdown groups, so the rest is read next cycle.
A bookmark that is not finite, not positive or more than five minutes in the future is corrupt: it is logged
once and replaced by the seven day lookback. A 6006 record closes its shutdown group when the next record is
more than two minutes later, so a clean shutdown followed by a crash is two events. The first read looks back
seven days. A log that cannot be
read makes the source unavailable with the reason. `build_agent` registers this reader as the `winevent` event
source. See `UNVERIFIED.md` for the unconfirmed record shapes.

## Collector and platform notes

### ZFS pool state

The `zfs` collector reads `<procfs>/spl/kstat/zfs/<pool>/state` for every directory that holds a
`state` entry. The file is readable without privilege on TrueNAS-SVR. Each pool yields a
`pool_state` sample with labels `pool` and `state`, which the mapping sends as the `hw.status` metric with
`hw.type` `logical_disk` and the state text in `hw.state`. A state file that cannot be read gives a sample with no value, which is dropped and never sent
as healthy. The source is
reported not present only when the zfs kstat directory is readable and empty, or is missing while
`/proc` is readable. A degraded pool is a watched source, so the agent raises its events between storage polls.

### Raspberry Pi throttling

The `rpi` collector detects a Pi from `<procfs>/device-tree/model` or `<sysfs>/firmware/devicetree/base/model`. It reads the firmware throttled bitmask from `<sysfs>/devices/platform/soc/soc:firmware/get_throttled`, or from the file named by `HOSTWATCH_RPI_THROTTLED_PATH`, and emits one `throttle_flag` sample per decoded bit (under-voltage, frequency capped, throttled and soft temperature limit, each as now and has-occurred), a `throttled_raw` sample and a `soc_temp` sample from the thermal zone of type `cpu-thermal`. A Pi without the bitmask file is unavailable with a reason that names the `vcgencmd get_throttled` alternative, and its flags are never reported as zero. On a Windows agent the Linux-only sources (`rapl`, `hwmon`, `mdraid`, `zfs`, `rpi`, and `thermalctl` with no configured status path) carry `linux_only` and are reported `present` false with a reason, without being probed. A host is reported not present only on positive evidence: a model file that was read and names no Pi, or model files missing from readable trees with no throttled file and no configured path. An unreadable model file with a throttled file or configured path leaves the source present, detected or unavailable with a reason.

The flags, the raw bitmask and the SoC temperature are sent as metrics; deciding what is a warning is Observe's job. Under-voltage now, capped or throttled now, and the has-occurred bits are separate flags, so a rule can tell them apart.

### Fan controller (thermalctl)

The `thermalctl` collector reads one JSON file, `/run/thermalctl/status.json` by default or the path in `HOSTWATCH_THERMALCTL_STATUS`, which the thermalctl service in the thermal-control-linux repo writes atomically each cycle. It emits `zone_temp` (C) and `zone_load` (%) per zone with a `zone` label, and for each header a `fan_duty` (%) and a `fan` (RPM) sample. The header samples carry the labels `chip=thermalctl`, `sensor=<header id>`, `state`, `mode` and `reasons` (the failsafe reasons joined with commas), so they are sent as fan metrics beside the hwmon fans. A value the controller could not measure is a sample with no value, never zero.

The source is unavailable, with a reason, when the file cannot be read, is not a JSON object, has no numeric timestamp, or its timestamp is more than 60 seconds old, since a stopped controller leaves its last file behind. It is reported not present only on positive evidence: the directory that would hold the file is readable and the file is missing, or the directory is missing from a readable parent, which is the normal case on a host that never ran thermalctl. A header whose state label is `failsafe` carries the controller's reasons; the controller drives the fan at full speed in that state, so it is a warning and not a fan fault.

### Windows CPU and memory collectors

`hostwatch/collectors/win_cpu.py` and `win_memory.py` read through the seam's `CimQuery` and keep the source ids `cpu`
and `memory` and the metric names of the Linux collectors, so the mapping needs no change. On a Windows
platform `build_collectors` builds them in place of the Linux pair, because two sources must not share an id; on any
other platform they are not built. The platform comes from the new optional `platform` argument, which defaults from
`sys.platform`.

`WinCpuCollector` reads the `_Total` instance of `Win32_PerfRawData_PerfOS_Processor`. Its counters are cumulative, so
`utilization_pct` is 100 times one minus the change in `PercentIdleTime` over the change in `Timestamp_Sys100NS`,
clamped to 0 to 100. The first call returns nothing. A counter that goes backwards (a wrap or a reset) or a timestamp
that does not advance returns nothing for that cycle and becomes the new baseline, since a guessed value would be
worse than none. 64-bit counters may arrive from PowerShell JSON as strings and are converted.

`WinMemoryCollector` reports `mem_total` from `Win32_OperatingSystem.TotalVisibleMemorySize` (KiB converted to bytes),
and `mem_available`, plus the Windows-only `commit_limit` and `commit_used`, from `Win32_PerfFormattedData_PerfOS_Memory`
(`AvailableBytes`, `CommitLimit`, `CommittedBytes`). A figure the host does not report is left out. A seam failure
makes the source unavailable with the reason. The counter shapes are listed in `UNVERIFIED.md`.

### Windows disk, Storage Spaces and smartctl collectors

`hostwatch/collectors/win_storage.py` holds two collectors that `build_collectors` adds only on a Windows platform, so
they never exist on Linux and add no source id that a Linux host reports.

`WinStorageCollector` (source `win_storage`) queries the `root/Microsoft/Windows/Storage` namespace through the seam's
`CimQuery`. `MSFT_PhysicalDisk` is required: if it fails or returns no disks the source is unavailable with the reason.
`MSFT_StorageReliabilityCounter`, `MSFT_StoragePool` and `MSFT_VirtualDisk` are optional, since not every host exposes
them, and a failed query only leaves its samples out. Per physical disk it reports `disk_health` and, from the
reliability counter with the same `DeviceId`, `temp`, `wear_pct`, `power_on_hours`, `read_errors_uncorrected` and
`write_errors_uncorrected`. A counter that is missing or null is left out, never reported as zero. It also reports
`pool_health` (the primordial pool is skipped) and `virtual_disk_health`. Health samples carry a stable `id` label plus
the `health` and `operational` text Windows reported.

Health uses the 0 ok, 1 warning, 2 critical scale of the truenas `pool_health` metric. The level is the worst of
`HealthStatus` (0 healthy, 1 warning, 2 unhealthy) and every `OperationalStatus` value that is recognised. OK is 0;
Stressed, Stopped and In Service (a repair or maintenance in progress) are 1; Degraded, Predictive Failure, Error,
Non-Recoverable Error, No Contact and Lost Communication are 2, because a degraded pool is critical for md and ZFS too.
Values the collector does not recognise are ignored, and a subject with no recognised value has a null health, never
zero. Enum values may arrive as numbers, numeric strings or names.

`WinSmartctlCollector` (source `win_smartctl`) runs `smartctl --scan -j` and then `smartctl -a -j [-d type] <device>`
for up to 32 devices through the seam's `CommandRunner`, with no shell. Device names and types from the scan are checked
against a strict pattern before they are used as arguments. It reports `smart_passed` (1 passed, 0 failed, null when
smartctl gave no verdict), `temp`, `power_on_hours`, `reallocated_sectors` (ATA attribute 5), and for NVMe `wear_pct`
and `media_errors`. smartctl's exit status is a bit mask that also encodes a failing disk, so the JSON is read whatever
the status; a disk whose output is not JSON is skipped for that cycle. The source is absent (not just unavailable) only
when the runner reports that smartctl cannot be started, which is the normal case on a host without it; a timeout or a
bad answer is unavailable with the reason.

The threshold engine gains one rule for both sources. `winstorage.health_raised` fires when the level of a disk, pool,
virtual disk or SMART self-assessment rises (warning for 1, critical for 2, and again when 1 becomes 2), and
`winstorage.health_cleared` fires on return to 0. The rule key uses the metric and the `id` label, so it survives the
text labels changing, and the state is saved with the other rules. A null level neither raises nor
clears. The class and property assumptions are listed in `UNVERIFIED.md`.

### Windows Thermal Control Suite status

`hostwatch/collectors/win_thermalsuite.py` (source id `win_thermalsuite`, Windows only) reads the status of the
Thermal Control Suite service through the seam's `PipeStatusReader`. The real `NamedPipeStatusReader` first looks the
pipe `ThermalControlSuite.Ipc` up in the pipe directory listing, which does not connect, and raises `PipeAbsentError`
when it is missing. It then opens the pipe and writes exactly one request, the length-prefixed JSON
`{"Type": "GetStatusReadOnly"}`, which the service documents as having no write path and needing no privilege. It reads
one length-prefixed reply, checks `Success`, and returns the `ReadOnlyStatus` object. The exchange runs on a helper
thread with a 3 second timeout (`DEFAULT_PIPE_TIMEOUT_S`), so a service that accepts the connection and never answers
cannot hold the agent. No setter, override or audit request is ever built.

The accepted payload is the service's read-only status document with `schemaVersion` 1. The collector rejects any other
version, including a missing or non-integer one, as unavailable with the version in the reason, because the service
adds fields within a version and raises the number only for a breaking change. The pipe serves PascalCase property
names and the status file camelCase, so the collector lowers the first letter of every key and accepts both.

It emits `zone_temp`, `zone_load` and `zone_duty` per zone, and for each fan `fan_duty`, `fan` (RPM) and `fan_target`,
plus a document level `failsafe` count. The fan samples use the `thermalctl` label names: `chip=thermalsuite`,
`sensor=<fan id>`, `state`, `mode` and `reasons`, with `dry_run`, `firmware_controlled`, `config_error` and `applied`
added. The state is `failsafe` when a `fan:<id>` or `control:` reason is active or the fan is stalled, then
`firmware_controlled`, `dry_run` and `active`, so a failsafe fan reads the same as for `thermalctl`. `fan_duty` carries the applied percentage and has no value when the duty was not applied (dry run) or
the firmware sets the fan, because the service reports an actual of 0 there that is not a measurement; `fan_target` carries
the computed duty. The contract has no watts, so no power reading is emitted.

The source is unavailable when the read times out or fails, the payload is not the documented shape, the schema version
is unknown, the service has not completed a control pass (`passAgeSeconds` is null), or the last pass is more than 60
seconds old. It is not present only when the pipe does not exist. Nothing here is verified against a running service; see `UNVERIFIED.md`.

### Windows agent run mode and service (Phase 8)

`hostwatch/windows/service.py` builds the Windows agent and hosts it as the `hostwatch-agent` service. `build_agent` constructs the ordinary `Agent` with
`platform="windows"` (a new optional constructor argument, so the Windows collector set can be built on Linux in tests),
drops the Linux-only event sources (`pstore`, `rasdaemon`, `journal` and `truenas_alerts`) and registers the
`WinEventReader` as the `winevent` source. The Linux boot id and heartbeat check is skipped, because Windows boot and
crash classification comes from the Event Log. The outbox is the same SQLite file in the data directory, by default
`C:/ProgramData/hostwatch`, and delivery, backoff, dead-lettering and the credential are the same as on Linux: OTLP to Observe with
the bearer `HOSTWATCH_INGEST_KEY`.

`python -m hostwatch windows run` (in `cli.py`) loads the
optional `agent.env` file from the data directory, validates the configuration and runs the loop
in the foreground. File values never override variables already set, only `HOSTWATCH_` names are accepted, and a bad
line is reported by number without printing it.

`AgentHost` runs the agent and, when the loop ends for any reason, makes one more delivery attempt. A failure there is
logged and the requests stay in the outbox for the next start. The service class is built inside `service_class()` and
`main()`, which import pywin32 (`win32serviceutil`, `win32service` and `servicemanager`) only when called, so the module
imports on Linux and the tests never need pywin32. `SvcStop` only sets the stop flag, and `SvcDoRun` returns after the
flush. An exception ends the process non-zero so the recovery actions restart it. Logs go to a rotating
`agent.log` in the data directory.

`deploy/windows/install.ps1` creates a venv, installs the checkout with the `windows` extra, writes `agent.env` after
locking its ACL to SYSTEM and Administrators (by SID), registers the service with `--startup delayed`, sets LocalSystem
and the restart recovery actions, and starts it. It supports `-DryRun` and asks before acting. `uninstall.ps1` removes
the service and the venv and keeps the data directory unless `-RemoveData` is given. Tests check the scripts as text
and with the PowerShell parser when one is present, and never run them.

Destination: `HOSTWATCH_OBSERVE_URL`, with `HOSTWATCH_HUB_URL` kept as an alias because Observe's install scripts set it,
and `HOSTWATCH_INGEST_KEY`.
