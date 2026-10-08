# hostwatch

A host agent that collects power, crash, RAID and disk health and sends it to Observe as
OpenTelemetry (OTLP) metrics and logs. The agent serves nothing and has no database of its own. The
hostwatch hub, its web UI and its Home Assistant, Orion and Prometheus outputs were retired when the
agent was converted to OTLP, and the old batch wire format went with them. See `PLAN.md` for the
phased plan and `UNVERIFIED.md` for assumptions not yet confirmed on real hardware. The design that
the agent follows is `docs/DATA-API-DESIGN.md` in the Observe repository.

Current state: the OTLP conversion is code complete and unit-tested. It has **not been deployed or
verified against a running Observe or on real hardware**. There is no migration path from the old
agent: the owner destroys and redeploys, and each host needs a new Observe ingest key. The threat
model is in `docs/THREAT-MODEL.md`.

## What the agent does

* **Collects by polling tier.** Collectors run at the rate Observe sets for their tier:
  availability (heartbeat and source status, 30 s by default), device metrics (60 s), storage
  health (15 min), SMART (1 h) and inventory (1 h). The agent reads the rates from
  `GET /internal/v1/agent-config` at start and every five minutes, clamps each to the limits Observe
  enforces, and keeps the defaults when Observe cannot be reached. Source detection and the rate request run
  on worker threads, so an unreachable source or Observe never delays events.
* **Sends events at once.** Boot classifications, kernel journal matches, RAID, ZFS, SMART, UPS and
  WHEA events, TrueNAS alerts and threshold events are read every five seconds and sent as OTLP logs
  without waiting for their tier.
* **Sends OTLP only.** `POST /v1/metrics` and `POST /v1/logs`, JSON by default (protobuf with
  `HOSTWATCH_OTLP_FORMAT=protobuf`), gzip, an `Idempotency-Key` per request and a bearer ingest key.
  A partial success is acknowledged and counted. A request Observe can never accept is
  dead-lettered; everything else waits and is retried with backoff.
* **Keeps a durable outbox.** Encoded requests wait in `outbox.db` until Observe answers 2xx, bounded
  in count, size and age. A restart replays each request once with the same key.
* **Reports what it cannot read.** A missing or unreadable source is unavailable with a reason,
  never zero.

## Layout

| Path | Purpose |
|---|---|
| `hostwatch/agent.py` | The loop: detect, schedule tiers, read events, build requests, deliver. Writes the boot heartbeat |
| `hostwatch/tiers.py` | The five tiers, their defaults and limits, rate parsing and the schedule |
| `hostwatch/otel_map.py` | Maps samples, source statuses and events to OpenTelemetry names, UCUM units, attributes and log records |
| `hostwatch/otlp.py` | Hand-written OTLP protobuf and JSON encoder, request splitting, `Idempotency-Key`s and the partial success reader |
| `hostwatch/outbox.py` | The durable outbox (requests, progress markers, dead letters, counters); recovers from a damaged file |
| `hostwatch/privfile.py` | Creates the outbox, heartbeat and liveness files with mode 0600 on POSIX |
| `hostwatch/model.py` | The agent's own `Sample`, `SourceStatus` and `Event` types. They never cross the network as they are |
| `hostwatch/config.py` | Settings read from `HOSTWATCH_*` environment variables |
| `hostwatch/collectors/` | One module per source: `cpu`, `memory`, `rapl`, `hwmon`, `mdraid`, `zfs`, `scrutiny`, `nut`, `truenas`, `rpi`, `thermalctl`, plus the Windows-only `win_cpu`, `win_memory`, `win_storage` (the `win_storage` and `win_smartctl` sources) and `win_thermalsuite` |
| `hostwatch/events/` | `boot` (heartbeat and boot classifier), `journal`, `pstore`, `rasdaemon`, `thresholds` and `winevent` |
| `hostwatch/truenas/client.py` | Read-only TrueNAS JSON-RPC client over WebSocket |
| `hostwatch/windows/` | The Windows seam (event log, CIM, a status pipe, a command runner) and `service.py`, the `hostwatch-agent` service host |
| `hostwatch/control/` | `hostwatch-control`, a separate daemon that runs signed commands from Observe. The collector never imports it |
| `deploy/` | Compose file and `.env.example` for MediaIn-SVR, `agent/` for a Debian host such as the Raspberry Pi, `truenas/` for the TrueNAS custom app, `windows/` for the service installers, and the control daemon files |
| `scripts/` | `host-prep.sh` (Phase 0 check), `rapl-access.sh` and `pstore-access.sh` (group read grants) |
| `docs/` | `ARCHITECTURE.md`, `THREAT-MODEL.md`, `deploy-agents.md`, `deploy-truenas.md`, `hosts/truenas-svr.md` |

The `hwmon` source sends one series per sensor: the id names the chip, the chip instance, the input and the
label, so two NVMe drives that both report `Composite` are two series. The platform is `truenas` on a TrueNAS
host (the host kernel version names it, or the TrueNAS API is on this machine). A source the host does not have,
such as `rapl` without powercap, `pstore` without its directory or `rasdaemon` without its database, is sent as
not present rather than present but unavailable.

The `rpi` source reads the Raspberry Pi firmware throttled bitmask (default the sysfs `get_throttled`
file under `soc:firmware`, or the path in `HOSTWATCH_RPI_THROTTLED_PATH`) and the `cpu-thermal` zone.
It reports the raw bitmask, one flag per condition (under-voltage, frequency capped, throttled and soft
temperature limit, each now and has-occurred) and the SoC temperature. On a Pi without the file it is
unavailable with the `vcgencmd get_throttled` alternative named, and on any other host it is reported
not present only on positive evidence. The bit meanings and file location are unconfirmed; see
`UNVERIFIED.md`.

The `thermalctl` source reads the status file written by the thermalctl fan controller (default
`/run/thermalctl/status.json`, or the path in `HOSTWATCH_THERMALCTL_STATUS`). It reports zone
temperature and load, and the duty and rpm of each header with the header state, mode and failsafe
reasons, and a failsafe count with its reasons that reaches Observe as a gauge and a warning log. The
source is unavailable when the file is unreadable, is not valid JSON or is older than
60 seconds or stamped more than 5 seconds in the future. It is reported not present on Windows unless a
status path is configured, and elsewhere only when the directory that would hold the file is readable
and the file is missing.

The `win_thermalsuite` source (Windows only) reads the read-only status of the Thermal Control Suite
service through its `ThermalControlSuite.Ipc` named pipe, with one documented request and a 3 second
timeout. It accepts status payload `schemaVersion` 1 only, and reports zone temperature, load and duty
and, for each fan, the applied duty, the computed target and the rpm. A fan in dry run or under
firmware control has no duty value, because the service reports an actual of 0 there that is not a
measurement. It is verified only with fakes; see `UNVERIFIED.md`.

## Quick start

This takes a fresh Debian 13 host to an agent that sends to Observe. It assumes Docker Engine and the
Compose plugin are already installed (installing Docker is out of scope), that you have `sudo`, and that
the host has `git`. You also need an Observe address and an ingest key for this host, created in Observe
and bound to the host name you will use. The expected output below is taken from what the code prints,
not from a recorded run, so treat small differences in wording as normal and report them.

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
   with `r-x` for the group. The unit is skipped, not failed, on a host where pstore is not a separate
   mount unit. On TrueNAS the Post Init script `deploy/truenas/rapl-postinit.sh` does both.

4. **Create the settings file.** Copy the example, then set the Observe address, the key and the two
   group ids.

   ```
   cp deploy/.env.example deploy/.env
   chmod 0600 deploy/.env
   getent group systemd-journal | cut -d: -f3
   nano deploy/.env
   ```

   Expected: the `getent` command prints one number. In `deploy/.env` set `HOSTWATCH_OBSERVE_URL` to
   the Observe base URL, `HOSTWATCH_INGEST_KEY` to the key for this host, `HOSTWATCH_RAPL_GID` to the
   number from step 3 and `HOSTWATCH_JOURNAL_GID` to the number just printed. Set `HOSTWATCH_HOST_NAME`
   when the machine name is not the name Observe knows this host by. If Scrutiny is not on
   `http://127.0.0.1:8081`, set `HOSTWATCH_SCRUTINY_URL`. Do not commit this file.

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
   sudo docker logs hostwatch
   ```

   Expected: `starting` for the first seconds, then `healthy`. The log shows the polling rates taken
   from Observe, or a warning that Observe could not be reached and the defaults are in force. The
   health check says the agent loop is turning; it does not say Observe is receiving.

7. **Confirm in Observe.** Open the host in Observe and check that it has a recent heartbeat and that
   the sources show values or an "unavailable" reason. They never show a made-up zero. A rejected key
   or a wrong host name shows in the agent log as `Observe answered 401` or `403`, and the requests stay
   queued until it is fixed.

### Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `docker compose` stops with a message naming `HOSTWATCH_RAPL_GID` or `HOSTWATCH_JOURNAL_GID` | The group id is empty in `deploy/.env` | Repeat steps 3 and 4, then run `sudo docker compose up -d` again |
| The container exits at start naming `HOSTWATCH_OBSERVE_URL` or `HOSTWATCH_INGEST_KEY` | A required setting is missing or malformed | Set it in `deploy/.env` and run `sudo docker compose up -d` |
| The log says `Observe answered 401` or `403` | The key is wrong, revoked, or bound to another host name | Check `HOSTWATCH_INGEST_KEY` and that `HOSTWATCH_HOST_NAME` is the host the key is bound to |
| The log says delivery failed and requests are queued | Observe is down or unreachable | Nothing to do. The outbox holds the data, bounded in count, size and age, and the agent retries with backoff |
| The log says Observe could not be reached for agent-config | Observe is down, or the URL is wrong | The defaults apply until it answers. Fix `HOSTWATCH_OBSERVE_URL` if it is wrong |
| The power source shows unavailable | The container group cannot read the RAPL counters, for example after a reboot before the service ran | Check `HOSTWATCH_RAPL_GID`, run `sudo systemctl status hostwatch-rapl.service`, then restart the container |
| The pstore source shows `cannot read /host/pstore: Permission denied` | `/sys/fs/pstore` is root-only and `scripts/pstore-access.sh` has not run or the group id is wrong | Run `sudo ./scripts/pstore-access.sh`, check `ls -ld /sys/fs/pstore` and `sudo systemctl status hostwatch-pstore.service`, then restart the container |
| The journal or boot events show unavailable | `HOSTWATCH_JOURNAL_GID` is wrong or the journal is not persistent | Re-check the group id from step 4; see `UNVERIFIED.md` |
| The RAID source shows absent on a host with no md arrays | This is expected, not a fault | Nothing to do |
| The Scrutiny source shows unavailable | `HOSTWATCH_SCRUTINY_URL` does not point at your Scrutiny | Fix the URL in `deploy/.env` and run `sudo docker compose up -d` |

Boolean settings (`HOSTWATCH_OTLP_GZIP`, `HOSTWATCH_TRUENAS_INSECURE`) accept `1`, `true`, `yes`, `on` as
true and `0`, `false`, `no`, `off` or empty as false, in any letter case. Any other value stops startup
with an error naming the variable (enforced).

## Settings

| Variable | Meaning |
|---|---|
| `HOSTWATCH_OBSERVE_URL` | The Observe base URL. `HOSTWATCH_HUB_URL` is accepted as an alias, because Observe's install scripts set it. When both are set the first wins |
| `HOSTWATCH_INGEST_KEY` | The ingest key for this host. It is sent only in the `Authorization` header and is never logged |
| `HOSTWATCH_HOST_NAME` | The host name in every request. Observe checks it against the host the key is bound to. Defaults to the machine name |
| `HOSTWATCH_OTLP_FORMAT` | `json` (default) or `protobuf` |
| `HOSTWATCH_OTLP_GZIP` | gzip the bodies (default on) |
| `HOSTWATCH_DATA_DIR` | Where `outbox.db`, the heartbeat and the liveness marker live (default `/data`) |
| `HOSTWATCH_REDETECT` | Seconds between source re-detection (default 600). A source that fails after it was detected is read again within seconds, not after this interval |
| `HOSTWATCH_SCRUTINY_URL`, `HOSTWATCH_NUT_*`, `HOSTWATCH_TRUENAS_*`, `HOSTWATCH_RPI_THROTTLED_PATH`, `HOSTWATCH_THERMALCTL_STATUS` | Optional sources, off unless configured |
| `HOSTWATCH_HWMON_IGNORE`, `HOSTWATCH_HWMON_CPU_SENSORS`, `HOSTWATCH_HWMON_REQUIRED_FANS` | hwmon tuning, as `chip:sensor` globs |
| `HOSTWATCH_SYSFS`, `HOSTWATCH_PROCFS`, `HOSTWATCH_JOURNAL`, `HOSTWATCH_JOURNAL_VOLATILE`, `HOSTWATCH_PSTORE`, `HOSTWATCH_RASDAEMON_DB` | Paths of the read-only host mounts, as the container sees them |

The polling rates are not settings. Observe tells the agent its rates, so an admin changes them in
Observe and they apply without a visit to the host. `HOSTWATCH_INTERVAL` no longer exists, and neither
do the hub, TLS, allowlist, login, MQTT, Prometheus and power witness settings.

## Verify

```
# What the agent sees, one pass, nothing sent:
sudo docker exec hostwatch python -m hostwatch collect-once

# Event sources are mounted read-only; each reports unavailable with a reason if absent:
sudo docker exec hostwatch ls /host/journal /host/pstore /host/rasdaemon
sudo docker exec hostwatch which journalctl

# Boot and hardware event checks on MediaIn-SVR (owner-run). After each, look in Observe for the
# newest boot or hardware event of the host:
# 1. Clean reboot: run `sudo systemctl reboot`. Expect observe.host.boot with kind boot.clean_shutdown.
# 2. Watchdog hang: stop the watchdog feeder or hang the host so the watchdog resets it.
#    Expect boot.watchdog_reset.
# 3. Power pull: remove power with the host running. Expect boot.unknown_unclean, because the agent
#    cannot tell a power cut from a hang. Any power loss verdict is Observe's.
# 4. Test-array failure: `sudo mdadm /dev/<test-array> --fail /dev/<member>`. Expect an
#    hostwatch.md.degraded log within about 20 seconds, not at the next storage poll.
```

Cross-check against the host: `sudo turbostat --quiet --show PkgWatt --interval 15` for `rapl`,
`cat /proc/mdstat` for `mdraid`, `sensors` for `hwmon`, and the Scrutiny UI for `scrutiny`.

### Unused hwmon inputs

Super I/O chips such as the NCT6779 on MediaIn-SVR report unused inputs with nonsense values (AUXTIN0 to
AUXTIN2 above 98 C, the PCH_* inputs at 0 C). To remove an input completely, set `HOSTWATCH_HWMON_IGNORE`
on the agent to comma-separated `chip:sensor` globs, for example
`HOSTWATCH_HWMON_IGNORE=nct6779:AUXTIN*,nct6779:PCH_*`. An invalid entry stops the agent at start with a
message naming the variable. `HOSTWATCH_HWMON_CPU_SENSORS` marks extra `chip:sensor` readings as CPU
temperatures, and `HOSTWATCH_HWMON_REQUIRED_FANS` names fans that should never read 0 RPM. The alternative
to the ignore setting is an `ignore` line in a file under `/etc/sensors.d/`, which hides the input from the
`sensors` tool but does not change what the kernel exposes in sysfs.

## Windows agent

A native Windows host runs the agent as the `hostwatch-agent` service, with no container. It is the same
agent loop as on Linux, wired to the Windows seam, the Event Log reader and the Windows collectors, and it
sends OTLP to Observe.

```
python -m hostwatch windows run                # foreground, for a console check
.\deploy\windows\install.ps1 -ObserveUrl https://observe.example.lan   # elevated; add -DryRun to preview
```

The durable outbox lives in `C:/ProgramData/hostwatch` (`HOSTWATCH_DATA_DIR`), so requests survive a restart
or an Observe outage and replay oldest first. The credential is `HOSTWATCH_INGEST_KEY`. The installer reads
it as a secure string, never prints it, and writes it to `agent.env` in the data directory with an ACL that
grants only SYSTEM and Administrators. The service runs as LocalSystem, starts after boot, restarts after a
failure (after 5, 30 and 60 seconds, with the count reset after a day), and on a clean stop makes one last
delivery attempt so queued requests are not left behind. The `pywin32` package is declared only as the
Windows-marked `windows` extra and is not in `requirements.lock`. None of this has run on a real Windows host
yet; see `UNVERIFIED.md`.

## OTEL mapping

`hostwatch/otel_map.py` maps every collector sample and event to OpenTelemetry metric names, UCUM units,
attributes and log records as Observe defines them. Metrics a collector adds before the table is updated are
sent as `observe.legacy.<source>.<metric>`. `hostwatch/otlp.py` encodes the result as OTLP JSON (default)
or JSON, with optional gzip, split to Observe's request limits, with a stable `Idempotency-Key` per outbox
entry. The scheduler and the sender are described in `docs/ARCHITECTURE.md`.

## hostwatch-control

`hostwatch/control/` is the per-host control daemon from `docs/CONTROL.md` in the Observe repository. It is
separate from the read-only collector: the collector never imports it, and it needs the optional `control`
extra (`pip install 'hostwatch[control]'`) for Ed25519. It is unchanged by the OTLP conversion. It loads
`control.toml` (the pinned Observe public key, the host name and the fan, services and reboot allowlist), and
on POSIX refuses a file that group or others can write. The daemon also refuses to start when the `host` in
`control.toml` is not this machine's own name (full or short name, any case, or COMPUTERNAME on Windows),
unless `machine_id` in `control.toml` matches `/etc/machine-id` or the Windows MachineGuid. The same check
runs before every command (the machine names are looked up once and cached) and a failure is reported as `refused` with reason `wrong_machine`. A scheduled reboot is reported `done` only when the host boot id changed since it was scheduled; a restart of the daemon alone leaves it pending. A missing `control.toml` stops the daemon with a message naming the path. It then checks
each signed command in this order: signature, host, expiry with 30 seconds of skew, the issue-time limits (expiry at most 900 seconds after issue,
not issued in the future, not older than 600 seconds), id unseen, seq above the
persisted one and at most 1000 above it, and the local allowlist. Every refusal has a reason code, listed in
`hostwatch/control/verify.py`. The replay state is written atomically with a keyed checksum and a second anchor file, so a corrupt, edited or
restored-older state file refuses every
command. On Windows `control.toml` must also have a DACL that gives write access only to SYSTEM and Administrators,
and the installers refuse a data folder owned by another account and lock it to SYSTEM and Administrators. The Linux executors are in `hostwatch/control/actions_linux.py`: `fan.set_floor` and `fan.set_mode`
stage a candidate beside `/etc/thermalctl/overrides.toml` through the sudo rule `tee`, which keeps the file root
owned as thermalctl requires, run `thermalctl check-config` with `--overrides` on the candidate, install it with
`mv -f` only if the check passes, and otherwise remove it and leave the live file and the fans alone, then reload thermalctl with
`systemctl kill -s HUP` (floor) or restart it (mode); `service.restart` runs `systemctl restart <unit>` or
`docker restart <name>` as an argument list, never a shell, for names that pass a strict pattern (letters,
digits, `_`, `.`, `-`, no `@`, no `..`, no leading dash); `host.reboot` runs `shutdown -r +N` after `delay_s`
(rounded up to whole minutes) and can be cancelled with `shutdown -c`, which is what the local
`hostwatch-control cancel` runs. `deploy/hostwatch-control.sudoers` is the sudo rule for exactly those
commands. The daemon loop is in `hostwatch/control/daemon.py`. The Windows executors are in
`hostwatch/control/actions_windows.py`: `fan.set_floor` reads the fan list from the Thermal Control Suite pipe
(`GetFans`) and sends `SetFanMapping` with the same mapping and the new `MinDutyPercent`, reporting a refusal
from the service as `refused`; `fan.set_mode` is refused with a plain reason because the Suite pipe has no
request that changes dry run; `service.restart` runs `powershell.exe` with a fixed `Restart-Service` script
and the service name as a separate argument, only for names in the local list that pass the same strict
pattern; `host.reboot` runs `shutdown.exe /r /t <delay_s>` and `shutdown.exe /a` cancels it. The Windows
executors are tested only with a fake pipe client and a fake runner. The test vector is in
`tests/fixtures/control_vector.json`.

Upgrading and key rotation (replay state). The replay state file `control-state.json` in the data folder is
versioned. A file written by a build before the checksum was added has no `v`, `gen` or `mac`, and the daemon
refuses every command (`state_unavailable`) and logs the file path until the operator upgrades it. Stop the
service and run `python -m hostwatch control state-upgrade` once (same environment or `control.env` as the
service); it keeps the saved sequence number and command ids. The checksum is keyed from
`HOSTWATCH_CONTROL_STATE_KEY` when that is set and from `HOSTWATCH_CONTROL_KEY` otherwise. If you rotate the
control key without a separate state key, the state fails its checksum; either set `HOSTWATCH_CONTROL_STATE_KEY`
to the old control key value before rotating, or as a last resort run `python -m hostwatch control state-reset
--yes --last-seq N`, which deletes the replay history and starts from the sequence number you give. The same
reset is the way back for a host that was offline while Observe's sequence moved more than 1000 ahead
(`seq_jump_too_large`); pick N close to the current Observe sequence. Without `--last-seq` the first command after a
reset may set any sequence number, because there is no baseline to bound it.

The daemon is started with `python -m hostwatch control run`. Every 5 seconds it asks Observe for this host's
commands (`GET /api/v1/control/commands?host=`, bearer `wpc_` key), handles them one at a time in `seq` order,
and posts each result to `POST /api/v1/control/results`. A refused command is not run and its result carries
the reason code. Results are written to a small durable outbox (`control-outbox.db` in the data directory)
before they are sent, so an Observe outage or a restart delays a report but does not lose it, and a replayed
command can never overwrite the report of what really happened. Settings are `HOSTWATCH_CONTROL_URL`,
`HOSTWATCH_CONTROL_KEY`, `HOSTWATCH_CONTROL_CONFIG`, `HOSTWATCH_CONTROL_DATA_DIR` and
`HOSTWATCH_CONTROL_INTERVAL_S`. The daemon opens no listening port. On Linux it runs under its own account from
`deploy/hostwatch-control.service` with the sudo rules in `deploy/hostwatch-control.sudoers`; on Windows it is
the separate `hostwatch-control` service installed by `deploy/windows/install-control.ps1`. `python -m
hostwatch control cancel` cancels a scheduled reboot locally. The pull, results and install paths are tested
only against a fake Observe and fake runners; see `UNVERIFIED.md`. The install steps are in
`docs/deploy-agents.md`.

## Container health and image labels

The image declares a `HEALTHCHECK` that runs `python -m hostwatch healthcheck` every 30 seconds. The agent
serves nothing, so the command reads the `agent.alive` marker that the agent loop rewrites every fifteen
seconds in the data directory, and exits 0 only when the marker is less than two minutes old. It says the loop
is turning, not that Observe is receiving; delivery trouble is reported by the `outbox` source. Check the
result with `sudo docker inspect --format '{{.State.Health.Status}}' hostwatch`.

The image carries OCI labels for source, version, revision and licenses. Set them at build time with
`--build-arg VERSION=...`, `--build-arg REVISION=...` and `--build-arg LICENSES=...`. The licenses label
defaults to `NOASSERTION` because the repository does not declare a license yet. The base image is pinned by
digest; the Dockerfile comment explains how to update it.

## CI, SBOM, scanning and releases

The `ci` workflow runs the tests, builds the amd64 image once, and then runs two checks on that same image in
parallel. The scan job writes an SPDX SBOM (`hostwatch.spdx.json`, kept as a workflow artifact) and scans the
image with trivy. It fails on any CRITICAL vulnerability that has a fix available, and uploads the SARIF
result to code scanning. The smoke job runs the image on the runner with a generated key, a read-only root and
a tmpfs data directory, points it at an address that answers nothing, and waits for the health check to pass;
the key is masked and never printed. The multi-arch image is published only after both pass. Every action is
pinned to a full commit SHA. Pushing a tag that starts with `v` also publishes semver image tags (`1.2.3` and
`1.2`), passes the version and revision to the image labels, and creates a GitHub release with the SBOM
attached. The `edge` tag still follows `master`. The workflow has not run yet; see `UNVERIFIED.md`.

## Dependency lock

The container image installs its runtime dependencies from `requirements.lock`, which pins every package with
`==` and at least one SHA-256 hash. The Dockerfile runs
`pip install --require-hashes --no-cache-dir -r requirements.lock` and then installs hostwatch itself with
`--no-deps`, so a substituted package fails the build. The runtime dependencies are now `httpx`, `pydantic`
and `websockets`; the lock still lists the packages of the retired hub until it is regenerated (see
`UNVERIFIED.md`). Regenerate it after changing the dependencies in `pyproject.toml`:

```
uv pip compile pyproject.toml --generate-hashes --universal --python-version 3.12 -o requirements.lock
```

## Tests

```
pip install -e '.[test]' && pytest
```
