# Deploy the agents and the three-host layout

This guide connects the three test hosts to Observe. MediaIn-SVR, TrueNAS-SVR and ai-pi each run the
hostwatch agent, which sends OpenTelemetry (OTLP) to Observe. There is no hostwatch hub any more, and no
migration path from the old agent: each host is redeployed with the new agent and a new ingest key. Facts
measured on hosts are in `docs/hosts/truenas-svr.md`. Nothing about ai-pi has been measured yet; the checks
that would confirm it are in `UNVERIFIED.md` and a source that cannot be confirmed is reported unavailable,
never guessed.

## The layout

| Host | Agent | Notes |
|---|---|---|
| MediaIn-SVR | `deploy/docker-compose.yml` | Container with RAPL, journal, pstore and rasdaemon mounts. Steps are in the README quick start. |
| TrueNAS-SVR | `deploy/truenas/compose.yaml` | Custom app, see `docs/deploy-truenas.md`. |
| ai-pi | `deploy/agent/docker-compose.yml` | Raspberry Pi 5, Debian arm64. |

Security labels: the per-host ingest key is bound by Observe to one host name, and that binding is an
enforced control in Observe. Traffic between the agent and Observe is plain HTTP unless `HOSTWATCH_OBSERVE_URL`
starts with `https://`, so use a trusted LAN segment or HTTPS.

## 1. Observe settings

In Observe, create one ingest key per host so that one host can be revoked without touching the others. Bind
each key to the host name that the agent will report, which is the `HOSTWATCH_HOST_NAME` of the agent. Observe
refuses requests that name another host, so one agent cannot report as another. Keep the key out of files you
commit.

Every agent needs two settings, and nothing else about Observe:

```
HOSTWATCH_OBSERVE_URL=https://observe.example.lan
HOSTWATCH_INGEST_KEY=<the key for this host>
```

`HOSTWATCH_HUB_URL` is accepted as an alias for the URL, because Observe's install scripts set it. The agent
fetches its polling rates from Observe at start and every five minutes, so a rate changed in the Observe
console applies without a visit to the host. When Observe cannot be reached the defaults apply (availability 30 s,
device metrics 60 s, storage health 15 min, SMART 1 h, inventory 1 h) and the agent keeps collecting and
queueing. Events (boot, kernel, RAID, ZFS, SMART, UPS and WHEA) are sent within a few seconds whatever the
rates are. Data is sent as JSON with gzip; set `HOSTWATCH_OTLP_FORMAT=protobuf` to send protobuf instead.

To retire a host, revoke its key in Observe and stop the agent.

## 2. The Raspberry Pi (ai-pi)

First run the owner checks listed for ai-pi in `UNVERIFIED.md`, which are read-only. Then,
on ai-pi, with Docker installed:

1. Get the repository and enter the agent folder: `cd deploy/agent`.
2. Copy the example settings: `cp .env.example .env`, then `chmod 0600 .env`.
3. Fill in `HOSTWATCH_OBSERVE_URL` with the Observe address, paste the key from step 1 into
   `HOSTWATCH_INGEST_KEY`, and set `HOSTWATCH_HOST_NAME`.
4. Set `HOSTWATCH_JOURNAL_GID` from `getent group systemd-journal | cut -d: -f3`.
5. Start it: `sudo docker compose up -d`.
6. In Observe confirm ai-pi appears with a recent heartbeat.

The container runs as uid 10001 with a read-only root filesystem, all capabilities dropped,
no privileged mode, host networking and read-only host mounts. The host `/proc` is not
mounted. The Pi throttling source reads the firmware bitmask through `/sys`; if the file is
not at the default location, the confirming command in `UNVERIFIED.md` tells you where it is,
and you set `HOSTWATCH_RPI_THROTTLED_PATH`. Sources the Pi lacks, such as RAPL and RAID, are
reported unavailable with a reason. Because `/proc` is not mounted, the Pi model file may be
unreadable in the container; the Pi source then stays present and is judged by the throttled
file, and it is reported not present only when a readable model file names another board.

On a Linux host that runs the thermalctl fan controller, the agent can also report the controller
status. The `thermalctl` source reads `/run/thermalctl/status.json`, so that directory must be
visible to the container as a read-only mount (for example `/run/thermalctl:/run/thermalctl:ro`),
or set `HOSTWATCH_THERMALCTL_STATUS` to another path. A host without the controller reports the
source as not present, and a controller that has stopped is reported unavailable once its file
is older than 60 seconds.

## Windows agents

A Windows host runs the native agent as the `hostwatch-agent` service. It is not verified on a real Windows host yet
(see `UNVERIFIED.md`). It sends the same OTLP as the other agents, so the Observe settings in step 1 apply
unchanged: create a key bound to the Windows host name.

On the Windows host, from an elevated PowerShell in a checkout of this repository (Python 3.11 or newer is needed):

```
.\deploy\windows\install.ps1 -ObserveUrl https://observe.example.lan -DryRun   # preview, changes nothing
.\deploy\windows\install.ps1 -ObserveUrl https://observe.example.lan           # asks, then prompts for the key
```

`deploy/windows/install.ps1` creates a virtual environment under `C:\Program Files\hostwatch`, installs the package with
the `windows` extra (which brings in pywin32 on Windows only), writes `C:\ProgramData\hostwatch\agent.env` with an ACL
limited to SYSTEM and Administrators, registers the service as LocalSystem with restart-on-failure recovery, and starts
it. The key is read as a secure string and is never printed. The outbox and `agent.log` live in
`C:\ProgramData\hostwatch`, or the folder given with `-DataDir`: the installer records that folder in the service
parameter `DataDir` under `HKLM\SYSTEM\CurrentControlSet\Services\hostwatch-agent\Parameters`, and the service reads it
before it looks for `agent.env`. The service is registered with its full class string
`hostwatch.windows.service.HostwatchAgentService` so pywin32 can load it from the virtual environment. Each send times
out after 5 seconds, a stop request ends delivery between sends, and the one last delivery attempt on stop is limited to
10 seconds in total. Anything not accepted stays queued for the next start. For a console check without the service, run `python -m hostwatch windows run` with the same
settings in the environment or in `agent.env`. `deploy/windows/uninstall.ps1` removes the service and the virtual
environment and keeps the data directory unless `-RemoveData` is given.

On a Windows host that has the Thermal Control Suite service, the
`win_thermalsuite` source needs no setting and no file mount. It connects to the service pipe
`ThermalControlSuite.Ipc`, which any local user may query, and asks only for the read-only status.
A host without the service reports the source as not present, and a service whose last control pass
is more than 60 seconds old is reported unavailable.

## 3. TrueNAS-SVR

Follow `docs/deploy-truenas.md`. Create an ingest key for it in Observe, bound to `TrueNAS-SVR`, as in step 1 above.
A pool seen by both the kstat and API sources is reported by both; Observe decides how to present them together.
The TrueNAS API client does not use proxy environment variables.

## OTEL metric names

The names, units and attributes each collector uses are defined in `hostwatch/otel_map.py` and described in
`docs/ARCHITECTURE.md`. Every request carries the resource attributes `host.name`, `os.type`, `service.name`,
`service.version` and `observe.platform`, and each collector is its own instrumentation scope named
`hostwatch.collector.<source>`.

## hostwatch-control

The control daemon is a separate program from the collector. It pulls signed commands from Observe, checks them against
the local allowlist `control.toml`, runs the allowed ones and reports the result. It only dials out and opens no port. It
needs the `control` extra (`pip install 'hostwatch[control]'`) and runs under its own account, not the collector's. The
collector works without it. None of the steps below has been run on a real host; see `UNVERIFIED.md`.

Before installing, on both platforms:

1. In Observe, create a control key bound to this host: `--ingest-key-create HOST --ingest-key-scope wpc`. Keep the
   `wpc_` value out of files you commit.
2. Write `control.toml` with the Observe public key (`ed25519:...`), the host name exactly as Observe knows it, and
   the fan, services and reboot allowlist. The format is in `CONTROL.md` in the docs folder of the Observe repository. Everything
   not listed is refused. The `host` must also be this machine's own name (full or short, any case): the daemon refuses
   to start on any other machine, and refuses each command with reason `wrong_machine` if the name changes later. If the
   operating system name differs from the Observe name, add `machine_id = "<contents of /etc/machine-id>"` (the
   MachineGuid on Windows) and that id is checked instead. The agent logs one warning when `HOSTWATCH_HOST_NAME`
   differs from the machine name, which is normal in a container and does not stop it.

Linux (systemd), as root:

1. Create the account: `useradd --system --no-create-home --shell /usr/sbin/nologin hostwatch-control`.
2. Install into its own environment: `python3 -m venv /opt/hostwatch-control/venv` and
   `/opt/hostwatch-control/venv/bin/pip install '/path/to/hostwatch[control]'`.
3. Put `control.toml` at `/etc/hostwatch/control.toml`, owned by root and not writable by group or others, in a directory
   that group and others cannot write. The loader refuses it otherwise. On Windows it checks the owner (SYSTEM or
   Administrators) when pywin32 is installed.
4. Copy `deploy/hostwatch-control.env.example` to `/etc/hostwatch/control.env`, set `HOSTWATCH_CONTROL_URL` and
   `HOSTWATCH_CONTROL_KEY`, and set owner root, group `hostwatch-control`, mode 0640.
5. Regenerate `deploy/hostwatch-control.sudoers` from your `control.toml` with `render_sudoers` in
   `hostwatch/control/actions_linux.py` when the restart list changes, check it with `visudo -c -f`, and install it in
   `/etc/sudoers.d/hostwatch-control` with mode 0440. It lists the only commands the account may run as root. The
   reboot rules need `systemd-run` and `systemctl` at `/usr/bin`.
6. Install `deploy/hostwatch-control.service` into `/etc/systemd/system/`, then `systemctl daemon-reload` and
   `systemctl enable --now hostwatch-control`. Logs are in `journalctl -u hostwatch-control`.

The unit leaves `NoNewPrivileges` off because `sudo` would stop working with it. Fan actions run only when `[fan] controller` is `thermalctl` on Linux. The daemon builds the new
overrides in memory, keeping every floor already set, and pipes them to the one command in `hostwatch-control.sudoers`
that touches thermalctl: `sudo -n /opt/thermalctl/venv/bin/thermalctl install-override`. thermalctl requires
`/etc/thermalctl/overrides.toml` to be owned by root, so the daemon never writes it itself; install-override validates
the text, replaces the file atomically as root and signals the service. Floor changes expire with the signed command
(at most 900 seconds). The rule matches the example in thermal-control-linux exactly, with no arguments. The thermalctl
path, the venv's bin directory and its interpreter must be root owned and not writable by anyone else. The unit sets
`ReadWritePaths=-/etc/thermalctl` because `ProtectSystem=strict` would otherwise keep `/etc` read-only for that root
command too; the directory stays root owned, so the control account itself still cannot write it. If thermalctl refuses
the text the command is reported failed with its message and the live overrides and the fans are untouched.

Windows, from an elevated PowerShell (a separate service from `hostwatch-agent`):

1. Put `control.toml` in `C:/ProgramData/hostwatch`, or pass its path as `-ConfigFile`.
2. Run `deploy/windows/install-control.ps1 -ObserveUrl https://observe.example.lan:8443 -DryRun` to read the steps,
   then run it again without `-DryRun`. It asks for the `wpc_` key as a secure string and never prints it.
3. It creates its own environment, writes `control.env`, locks `control.toml` and `control.env` to SYSTEM and
   Administrators, and registers `hostwatch-control` as LocalSystem, which the Thermal Control Suite pipe needs. Logs are
   in `control.log` in the data folder.
4. Remove it with `deploy/windows/uninstall-control.ps1`. It keeps the control files unless `-RemoveControlData` is given.

To run it by hand on either platform: `python -m hostwatch control run`, with `HOSTWATCH_CONTROL_URL` and
`HOSTWATCH_CONTROL_KEY` set, and optionally `--config`, `--data-dir` and `--env-file`. `python -m hostwatch control cancel`
cancels a scheduled reboot on this host without Observe; this works for the whole delay. The reboot delay in
`control.toml` (`[reboot] delay_s`, default 60) has a minimum of 30 seconds, and a smaller value, including 0, is raised
to 30. On Linux it is a systemd timer named `hostwatch-reboot` and is exact to the second. A reboot is reported to
Observe as `scheduled`, then `done` or `failed` for the same command id, and an admin cancel in Observe reaches the
host on its next pull (the pull answer lists the cancelled ids) and cancels the pending reboot here, reported as
`cancelled`. A command whose result was lost is re-sent, not refused as a replay. Results that Observe refuses
with a permanent 4xx answer are parked in `control-outbox.db` in the data directory, with the reason, and the results
behind them are still sent. The settings are `HOSTWATCH_CONTROL_URL`,
`HOSTWATCH_CONTROL_KEY`, `HOSTWATCH_CONTROL_CONFIG`, `HOSTWATCH_CONTROL_DATA_DIR` (state, results outbox and logs) and
`HOSTWATCH_CONTROL_INTERVAL_S` (5 to 300, default 5). Over plain HTTP on the LAN the signatures still protect the
commands, but the key and results travel unencrypted, so TLS to Observe is recommended.

## Windows source reporting

A Windows agent reports the Linux-only sources (`rapl`, `hwmon`, `mdraid`, `zfs`, `rpi` and `thermalctl` unless `HOSTWATCH_THERMALCTL_STATUS` is set) as not present, so they never raise an unmeasured warning. `win_storage` is unavailable with a reason when Windows returns no physical disks, and a failed pool or virtual disk query appears as an unknown health sample whose `reason` label says which query failed. A `thermalctl` status stamped in the future by more than 5 seconds, or one that becomes older than 60 seconds after detection, makes that source unavailable with the reason.

## Windows PowerShell output encoding

The Windows agent runs PowerShell with `-NoProfile -NonInteractive`, sets the console output encoding to UTF-8 at the start of every script, and decodes the output as UTF-8 with replacement. Event text in any language is kept, and an invalid byte appears as a replacement character instead of failing the read. No host setting is needed.

## Windows event log bookmark

The Windows agent keeps its Event Log position in the outbox database (`outbox.db` in the data directory), so the position moves forward only when the requests carrying the events are stored. If a read fails, the next read reads the same records again. A burst of more than 500 records is delivered over several reads, oldest first. If the stored position is damaged or lies in the future, the agent logs one warning and reads back seven days; Observe drops repeats by their dedup key, so this does not duplicate events.
