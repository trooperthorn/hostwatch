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
The secret is printed once. The agent needs `ingest` to push and `read:events` to restore
its threshold state after a restart, and no other scope:

```
sudo docker exec hostwatch python -m hostwatch key create --scopes ingest,read:events --owner agent-ai-pi
sudo docker exec hostwatch python -m hostwatch key create --scopes ingest,read:events --owner agent-truenas
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
reported unavailable with a reason.

## 3. TrueNAS-SVR

Follow `docs/deploy-truenas.md`. Add the TrueNAS-SVR address to `HOSTWATCH_ALLOWED_CLIENTS`
on the hub and use its own ingest key, as in step 1 above.
