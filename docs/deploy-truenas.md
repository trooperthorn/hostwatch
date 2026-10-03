# Deploy the agent on TrueNAS-SVR

This guide runs the hostwatch agent on TrueNAS-SVR as a custom app and pushes its
data to the hub on MediaIn-SVR. It is written for TrueNAS 26 SCALE. Measured facts
about the host are in `docs/hosts/truenas-svr.md`. Two points are not yet confirmed
on the host and are tracked in `UNVERIFIED.md`: the WebSocket path
`wss://<host>/api/current`, and how TrueNAS treats an API key used over a connection
it considers insecure. The URL is configurable in `HOSTWATCH_TRUENAS_URL`.

Security labels: the hub source allowlist and the ingest key are enforced controls.
Binding to one LAN address is exposure control only, not authentication. The agent
container limits (read-only root, no capabilities, non-root) are enforced by Docker.

## 1. Hub side on MediaIn-SVR

The hub binds to 127.0.0.1 by default, so a remote agent cannot reach it. Bind it to
the host's LAN address and list the agent's address in the allowlist. In
`deploy/.env` on MediaIn-SVR set:

```
HOSTWATCH_HUB_BIND=<MediaIn-SVR LAN address>
HOSTWATCH_ALLOWED_CLIENTS=10.10.11.98
```

`10.10.11.98` is TrueNAS-SVR. A specific address is required: the hub refuses a
wildcard bind, and a non-loopback bind without TLS needs a non-empty allowlist. In the
`all` role the hub also keeps listening on 127.0.0.1 so the local agent keeps working.
Restart with `cd deploy && sudo docker compose up -d`. Add the address of any other
agent, such as ai-pi, to the same comma separated list.

Create an ingest key for this agent, bound to the host name it will report. The key carries only
the `ingest` scope, and the hub refuses batches from it that name any other host. The secret is
printed once:

```
sudo docker exec hostwatch python -m hostwatch key create --scopes ingest --host TrueNAS-SVR --owner agent-truenas
```

## 2. Create the TrueNAS API key

In the TrueNAS UI open the user menu, then API Keys, then Add. Give it a name such as
hostwatch and a user whose role is READONLY_ADMIN. Copy the key when it is shown,
because TrueNAS does not show it again. The collector sends only read queries.

## 3. Prepare the dataset

Pick a dataset for the app, for example `/mnt/Apps/hostwatch`. From the TrueNAS shell
as an administrator:

```
mkdir -p /mnt/Apps/hostwatch/data
chown 10001:10001 /mnt/Apps/hostwatch/data
```

Save the API key to a file and make it readable by the container user only:

```
printf '%s' 'PASTE_THE_API_KEY_HERE' > /mnt/Apps/hostwatch/truenas-api-key
chown 10001:10001 /mnt/Apps/hostwatch/truenas-api-key
chmod 0400 /mnt/Apps/hostwatch/truenas-api-key
```

Create `/mnt/Apps/hostwatch/agent.env` with the hub URL and the ingest key from step 1,
then protect it the same way:

```
HOSTWATCH_HUB_URL=http://<MediaIn-SVR LAN address>:8090
HOSTWATCH_INGEST_KEY=<the key printed in step 1>
```

```
chmod 0400 /mnt/Apps/hostwatch/agent.env
```

Docker reads `env_file` as root before the container starts, so this file does not
need to be readable by uid 10001. Neither file is committed anywhere. The compose file
names the key file in `HOSTWATCH_TRUENAS_API_KEY_FILE`; the key value never appears in
the environment or in the app definition.

## 4. Register the Post Init script

TrueNAS host changes do not survive updates, and the RAPL counters are root-only after
each boot. Copy `deploy/truenas/rapl-postinit.sh` to the dataset, for example
`/mnt/Apps/hostwatch/rapl-postinit.sh`, and look at what it would do first:

```
sh /mnt/Apps/hostwatch/rapl-postinit.sh --dry-run
```

The default with no arguments is also a dry run. Consequences: it creates the
`hostwatch-rapl` system group if missing and changes the group and mode of `energy_uj`
under `/sys/class/powercap`. Members of that group can read fine-grained energy
readings, which is the PLATYPUS side channel (CVE-2020-8694). Only the hostwatch
container should hold the group. Nothing else is touched, and a second run changes
nothing.

Run it once with `--apply` as root, note the group id it prints, and put that id in
the second `group_add` entry of the compose file. Then in the UI open System, Advanced,
Init/Shutdown Scripts, Add. Choose type Command, command
`sh /mnt/Apps/hostwatch/rapl-postinit.sh --apply`, when Post Init, and enable it.
The group id can change if TrueNAS recreates the group, so check it after an update
and correct the compose file when it differs.

## 5. Create the app

In the UI open Apps, Discover Apps, the three dot menu, Install via YAML. Name the app
hostwatch and paste `deploy/truenas/compose.yaml`, with the dataset paths and the
second group id adjusted. The file runs the `agent` role as uid 10001 with a read-only
root filesystem, all capabilities dropped, no privileged mode, `/sys` mounted read-only
and host networking. The API client ignores proxy environment variables on purpose, so the TrueNAS URL must be reachable directly from the container. Each pool appears once in the outputs, at the worse of the kstat and API states. The host `/proc` is not mounted; ZFS pool state comes from the
container's own `/proc/spl/kstat`.

The compose file sets `HOSTWATCH_TRUENAS_INSECURE` to 1 because the API is reached at
`wss://127.0.0.1` where the TrueNAS certificate cannot match the name. That disables
certificate checking for this loopback connection only. To verify instead, export the
certificate to the dataset, mount it, set `HOSTWATCH_TRUENAS_CA` to its path and use
the host name in `HOSTWATCH_TRUENAS_URL`.

## 6. Check the result

On MediaIn-SVR, sign in to the hub UI and confirm TrueNAS-SVR appears with a recent
sample. The sources `zfs` and `truenas` should be available, and `rapl` becomes
available after the group id is correct. Check the agent log on the Apps page for
the line naming a failing source and its reason. Any source that cannot be read is
reported unavailable with a reason rather than as zero.
