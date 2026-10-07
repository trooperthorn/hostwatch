# hostwatch threat model

This document says what the hostwatch agent protects, where its trust boundaries are, which threats it
considers, and how honest each defence is. The agent sends OpenTelemetry data to Observe and serves
nothing. The hostwatch hub, its login, API keys, audit log and integrations were retired, so the threats
that belonged to them are gone with them. Every control carries one label:

- **enforced**: the code refuses the request or the container runtime enforces the limit, and a
  test or a build check proves it.
- **advisory**: the control depends on how the operator deploys or runs the system, so hostwatch
  cannot guarantee it.
- **planned**: not built yet. It is listed so that nobody assumes it exists.

A bind address, a port number or obscurity is never counted as authentication. The test
`tests/test_docs.py` checks that every control line below carries exactly one label.

## Assets

- **Host health data**: power draw, temperatures, RAID and disk state, crash and boot history.
  Integrity matters most, because a false "healthy" hides a failing host.
- **Credentials**: the Observe ingest key, the TrueNAS API key file and the NUT password file.
- **The right to report for a host**: whoever holds the ingest key can make Observe show that host's data.
- **Availability of the alerts**: Observe's alerts depend on the agent's heartbeat and events arriving.

## Trust boundaries

| Boundary | Trusted side | Less trusted side | What crosses it |
|---|---|---|---|
| Host to container | The host kernel and the operator with `docker` access | The hostwatch process | Read-only mounts of `/sys`, the journal, pstore and rasdaemon; the data volume |
| Agent to Observe | Observe | The agent and the LAN path between them | OTLP requests under an ingest key bound to one host, and one read of the polling rates |
| Agent to NUT server | The agent | The NUT server and the network path | Read-only `LIST VAR` requests |
| Agent to TrueNAS | The agent | The TrueNAS API and the network path | Read-only JSON-RPC queries under an API key read from a file |
| Operator to data directory | The operator with shell or volume access | Everyone else | The outbox database and the heartbeat |

## Threats and controls

Each threat names the controls against it. Controls are written as `Control [label]: text`.

### Inbound attack on the agent

- Control [enforced]: the agent opens no listening port, so there is no inbound surface to authenticate or to scan.
- Control [enforced]: the container runs with host networking only so that it can reach local services; it publishes nothing.

### Network eavesdropping and tampering

- Control [advisory]: when `HOSTWATCH_OBSERVE_URL` starts with `http://`, traffic is plain HTTP, so the key and the data can be read or replayed by anyone on the path; use `https://` or a trusted switch.
- Control [enforced]: with an `https://` URL the agent verifies the server certificate with the default trust store and does not follow redirects, so a key is never sent to an address the operator did not configure.
- Control [advisory]: a private certificate authority must be added to the trust store of the image or host, because the agent has no setting to disable verification.

### Stolen or leaked credentials

- Control [enforced]: the ingest key is held as a `Secret` whose repr is redacted, is sent only in the `Authorization` header, and is never written to the outbox, a log line or a source reason.
- Control [enforced]: the TrueNAS API key and the NUT password are read from files and are not written to logs.
- Control [advisory]: key rotation is manual, and nothing expires a key.
- Control [advisory]: the env file that holds the key must be readable only by the operator (mode 0600, or SYSTEM and Administrators on Windows); the Windows installer sets that ACL, and the Linux operator must set the mode.

### Reporting as another host

- Control [enforced]: every request carries `host.name` from `HOSTWATCH_HOST_NAME`, and Observe refuses a request whose host is not the one its key is bound to.
- Control [advisory]: the binding is checked by Observe, not by the agent. A holder of the key can still send false but well-formed data for that one host.

### Replayed or duplicated data

- Control [enforced]: each request carries an `Idempotency-Key` built from its outbox entry, and a replay after a restart sends the same bytes under the same key, so Observe stores it once.
- Control [enforced]: a request Observe cannot accept (400, 409, 413, 415, 422) is dead-lettered and never retried, and every other failure leaves it queued.

### Container escape and privilege

- Control [enforced]: the container runs as a non-root user with a read-only root filesystem, all capabilities dropped and `no-new-privileges`.
- Control [enforced]: the host `/proc` is never mounted, and every host mount is read-only except the data volume.
- Control [advisory]: the supplementary groups for RAPL and the journal widen what the process can read, and the operator sets them in `.env`.
- Control [advisory]: anyone who can run `docker` on the host already controls the container.

### Supply chain

- Control [enforced]: the image installs dependencies from a hash-locked list with `--require-hashes`, and the base image is pinned by digest.
- Control [enforced]: CI pins every action to a full commit SHA, generates an SBOM, and fails on a fixable CRITICAL vulnerability found by the image scan.
- Control [advisory]: the scan covers the amd64 image only, and unfixed vulnerabilities are not gated.
- Control [advisory]: the lock still lists packages of the retired hub until it is regenerated, which widens the image's dependency set without being used.
- Control [planned]: signing the published image and verifying the signature at deploy time.

### Abuse of integrations

- Control [enforced]: the NUT, Scrutiny and TrueNAS sources are off unless configured.
- Control [enforced]: the NUT client sends read-only commands only, refuses any line holding a CR or LF, and the TrueNAS client sends only an allowlist of read-only methods.
- Control [advisory]: a NUT server or TrueNAS API on the network without TLS or authentication lets another client on the path read or alter what the agent sees.

### Denial of service

- Control [enforced]: the outbox is bounded in count, in bytes and in age, so an Observe outage cannot fill the disk, and metrics are dropped before events.
- Control [enforced]: delivery backs off to five minutes, honours `Retry-After` up to the same cap, and the polling rates are clamped to the limits Observe enforces, so neither a bad answer nor an outage makes the agent spin.
- Control [advisory]: a hostile Observe could ask for the fastest rates it permits, and the agent follows them; the floors are the only limit.

### Wrong answers that hide a failure

- Control [enforced]: a missing or unreadable source is reported unavailable with a reason and is never substituted by zero.
- Control [enforced]: the heartbeat and source status go out on the availability tier, so a silent agent is visible to Observe as a missing heartbeat.
- Control [advisory]: a power pull and a hang look the same to the agent, so the boot stays `unknown_unclean`, and any power loss verdict is Observe's.

## Residual risks

These risks remain after the controls above and are accepted until the planned items are built.

1. **RAPL side channel.** Since kernel 5.10 the energy counters are root-only because of the
   PLATYPUS side channel (CVE-2020-8694). `scripts/rapl-access.sh` grants read access to one group
   so the container can measure power. Any process in that group can read fine-grained energy
   data, so keep interactive accounts out of the group. This is advisory, because the host decides
   who joins it.
2. **Plain HTTP to Observe.** An `http://` URL carries the key and the data in clear text. A
   spoofed or shared address on the same segment can read or replay them.
3. **Operator trust.** Anyone with `docker exec` or write access to the data volume can read the
   outbox and the env file. The agent cannot stop them.
4. **Unverified on hardware.** Several controls are proven only against fakes. The open checks are
   listed in `UNVERIFIED.md`.
