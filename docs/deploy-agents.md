# Deploy remote agents and the three-host layout

This guide connects the three test hosts. MediaIn-SVR runs the hub, TrueNAS-SVR and
ai-pi run agents that push to it. Facts measured on hosts are in `docs/hosts/truenas-svr.md`.
Nothing about ai-pi has been measured yet; the checks that would confirm it are in
`UNVERIFIED.md` and a source that cannot be confirmed is reported unavailable, never guessed.

## The layout

| Host | Role | Notes |
|---|---|---|
| MediaIn-SVR | `all` (hub plus its own agent) | Binds the hub to its LAN address and lists the agent addresses in an allowlist. |
| TrueNAS-SVR | `agent` | Custom app, see `docs/deploy-truenas.md`. A standalone setup can use `all` instead. |
| ai-pi | `agent` | Raspberry Pi 5, Debian arm64, uses `deploy/agent/docker-compose.yml`. |

Security labels: the source allowlist and the per-agent ingest key are enforced controls.
Binding the hub to one LAN address is exposure control only, not authentication. Traffic
between agent and hub is plain HTTP unless the hub is given a certificate, so use a trusted
LAN segment or set `HOSTWATCH_TLS_CERT` and `HOSTWATCH_TLS_KEY` on the hub.

## 1. Hub settings on MediaIn-SVR

The hub binds to 127.0.0.1 by default, so no remote agent can reach it. In `deploy/.env` set:

```
HOSTWATCH_HUB_BIND=<MediaIn-SVR LAN address>
HOSTWATCH_ALLOWED_CLIENTS=<TrueNAS-SVR address>,<ai-pi address>
```

The bind must be one specific address, never a wildcard. A non-loopback bind without TLS
needs a non-empty `HOSTWATCH_ALLOWED_CLIENTS` list of individual addresses. In the `all`
role the hub also keeps listening on 127.0.0.1 so the local agent keeps delivering. Apply
with `cd deploy && sudo docker compose up -d`.

Create one key per agent so that one agent can be revoked without touching the others.
The secret is printed once. Each agent key carries only the `ingest` scope and is bound to
one host with `--host`, which must match the `HOSTWATCH_HOST_NAME` the agent reports. This is
enforced: the hub answers 403 and writes an audit row naming both hosts when a batch names a
different host, so one agent cannot post as another. A host-bound ingest key may also read its
own host's events, which is how the agent restores its threshold state after a restart, and
nothing else. The hub refuses to create an ingest key without `--host`. Keys created before
this existed stay unbound and keep working, and the audit log marks each of their ingests as
`unbound_key`; replace them with bound keys and revoke the old ones:

```
sudo docker exec hostwatch python -m hostwatch key create --scopes ingest --host ai-pi --owner agent-ai-pi
sudo docker exec hostwatch python -m hostwatch key create --scopes ingest --host TrueNAS-SVR --owner agent-truenas
sudo docker exec hostwatch python -m hostwatch key list
```

To retire an agent, run `python -m hostwatch key revoke ID` with its id from the list.

## 2. The Raspberry Pi (ai-pi)

First run the owner checks listed for ai-pi in `UNVERIFIED.md`, which are read-only. Then,
on ai-pi, with Docker installed:

1. Get the repository and enter the agent folder: `cd deploy/agent`.
2. Copy the example settings: `cp .env.example .env`, then `chmod 0600 .env`.
3. Fill in `HOSTWATCH_HUB_URL` with the hub's LAN address and port 8090, paste the key from
   step 1 into `HOSTWATCH_INGEST_KEY`, and set `HOSTWATCH_HOST_NAME`.
4. Set `HOSTWATCH_JOURNAL_GID` from `getent group systemd-journal | cut -d: -f3`.
5. Start it: `sudo docker compose up -d`.
6. In the hub UI confirm ai-pi appears with a recent sample.

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
(see `UNVERIFIED.md`). It pushes the same wire schema as the other agents, so the hub settings in step 1 apply
unchanged: create a key bound to the Windows host name with `python -m hostwatch key create --scopes ingest --host <name>`.
The destination is only the `HOSTWATCH_HUB_URL` setting, and it is expected to move from the hostwatch hub to watchpost
later, which will ingest the same schema.

On the Windows host, from an elevated PowerShell in a checkout of this repository (Python 3.11 or newer is needed):

```
.\deploy\windows\install.ps1 -HubUrl https://hub.example.lan:8090 -DryRun   # preview, changes nothing
.\deploy\windows\install.ps1 -HubUrl https://hub.example.lan:8090           # asks, then prompts for the key
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
10 seconds in total. Anything not accepted stays queued for the next start. `HOSTWATCH_INTERVAL` must be at least 5
seconds; zero or a negative value is refused at start. For a console check without the service, run `python -m hostwatch windows run` with the same
settings in the environment or in `agent.env`. `deploy/windows/uninstall.ps1` removes the service and the virtual
environment and keeps the data directory unless `-RemoveData` is given.

On a Windows host that has the Thermal Control Suite service, the
`win_thermalsuite` source needs no setting and no file mount. It connects to the service pipe
`ThermalControlSuite.Ipc`, which any local user may query, and asks only for the read-only status.
A host without the service reports the source as not present, and a service whose last control pass
is more than 60 seconds old is reported unavailable.

## 3. TrueNAS-SVR

A pool seen by both the kstat and API sources appears once on the hub, at the worse of the two states. The TrueNAS API client does not use proxy environment variables.


Follow `docs/deploy-truenas.md`. Add the TrueNAS-SVR address to `HOSTWATCH_ALLOWED_CLIENTS`
on the hub and use its own ingest key, as in step 1 above.

## Windows PowerShell output encoding

The Windows agent runs PowerShell with `-NoProfile -NonInteractive`, sets the console output encoding to UTF-8 at the start of every script, and decodes the output as UTF-8 with replacement. Event text in any language is kept, and an invalid byte appears as a replacement character instead of failing the cycle. No host setting is needed.

## Windows event log bookmark

The Windows agent keeps its Event Log position in the outbox database (`outbox.db` in the data directory), so the position moves forward only when the batch carrying the events is stored. If a cycle fails, the next cycle reads the same records again. A burst of more than 500 records is delivered over several cycles, oldest first. If the stored position is damaged or lies in the future, the agent logs one warning and reads back seven days; the hub drops repeats by their dedup key, so this does not duplicate events.
