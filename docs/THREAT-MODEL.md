# hostwatch threat model

This document says what hostwatch protects, where its trust boundaries are, which threats it
considers, and how honest each defence is. Every control carries one label:

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
- **Credentials**: argon2id password hashes, hashed API keys, session tokens, the Home Assistant
  token file, the MQTT password file and the NUT password file.
- **Audit log**: the record of who read or changed what.
- **The right to ingest**: whoever can post samples and events can make the dashboard lie.
- **Availability of the alerts**: Home Assistant and Orion alerts that depend on the hub.

## Trust boundaries

| Boundary | Trusted side | Less trusted side | What crosses it |
|---|---|---|---|
| Host to container | The host kernel and the operator with `docker` access | The hostwatch process | Read-only mounts of `/sys`, the journal, pstore and rasdaemon; the data volume |
| Container to hub API | The hub process | Any caller on the bound address | HTTP requests that need a session, a scoped key or a certificate identity |
| Agent to hub | The hub | A local or remote agent | Sample and event batches under an `ingest` key |
| LAN clients | The hub | Browsers, Home Assistant, Orion, Prometheus | Reads under `read:metrics` or `read:events`, over plain HTTP with an allowlist or over TLS |
| Hub to Home Assistant | The hub | Home Assistant REST API | A long-lived token read from a file; history reads only |
| Hub to MQTT broker | The hub | The broker and its other clients | Discovery, state and event messages; optional username, password and TLS |
| Agent to NUT server | The agent | The NUT server and the network path | Read-only `LIST VAR` requests |
| Hub to Orion | The hub | The SolarWinds Orion API Poller | Flat JSON documents under a `read:metrics` key |
| Operator to data directory | The operator with shell or volume access | Everyone else | The SQLite database, which the CLI opens directly |

## Threats and controls

Each threat names the controls against it. Controls are written as `Control [label]: text`.

### Unauthenticated access to the API

- Control [enforced]: every route except health, login and the static shell is denied without a session, a scoped key or a certificate identity (`tests/test_phase3_exit.py`).
- Control [enforced]: a revoked key is refused on its next request.
- Control [enforced]: password logins use argon2id, a uniform failure answer and a lockout after repeated failures, and cookie writes carry a CSRF token.
- Control [enforced]: a non-loopback bind is refused unless TLS is configured, or one specific address is bound with a non-empty `HOSTWATCH_ALLOWED_CLIENTS` list, or the explicit insecure override is set.
- Control [advisory]: the loopback default bind limits exposure as a deployment choice, and it is not authentication.
- Control [advisory]: the source allowlist limits who can reach the login and API, and it is exposure control only because an allowed client still needs a session or key.

### Network eavesdropping and tampering

- Control [enforced]: with `HOSTWATCH_TLS_CERT` and `HOSTWATCH_TLS_KEY` set, the hub serves TLS and marks cookies `Secure`.
- Control [advisory]: on plain HTTP with an allowlist, traffic is unencrypted, so keys, session cookies and data can be read or replayed by anyone on the path; use TLS beyond a trusted switch.
- Control [advisory]: client certificates through a reverse proxy rely on the proxy verifying the certificate and stripping forged headers, because the hub only enforces the peer allowlist and the subject binding.
- Control [planned]: the hub does not yet terminate mutual TLS for agents on its own.

### Stolen or leaked credentials

- Control [enforced]: API key secrets are shown once and stored only as hashes.
- Control [enforced]: keys carry scopes (`read:metrics`, `read:events`, `ingest`, `admin`), so a key leaked from Home Assistant cannot ingest or administer.
- Control [enforced]: disabling a user or changing a password revokes that user's sessions.
- Control [enforced]: secrets for MQTT, NUT and Home Assistant are read from files and are not written to logs.
- Control [advisory]: the legacy shared ingest token works until `HOSTWATCH_LEGACY_TOKEN_DISABLED` is set, and although it is ingest only it is one secret shared by every agent.
- Control [advisory]: key rotation is manual, and nothing expires a key.

### Forged or replayed ingest

- Control [enforced]: ingest needs the `ingest` scope, and batches are idempotent, so a replay does not duplicate samples or events.
- Control [enforced]: a malformed batch is rejected by schema validation before storage.
- Control [advisory]: a holder of an ingest key can still send false but well-formed data for any host name it chooses, because keys are not bound to a host.

### Container escape and privilege

- Control [enforced]: the container runs as a non-root user with a read-only root filesystem, all capabilities dropped and `no-new-privileges`.
- Control [enforced]: the host `/proc` is never mounted, and every host mount is read-only except the data volume.
- Control [advisory]: the supplementary groups for RAPL and the journal widen what the process can read, and the operator sets them in `.env`.
- Control [advisory]: anyone who can run `docker` on the host already controls the container.

### Tampering with the audit log

- Control [enforced]: database triggers refuse updates and deletes on the audit table, and authenticated requests and denials append rows.
- Control [enforced]: the hourly retention prune is the only deletion, and it records itself.
- Control [advisory]: a person with write access to the database file can bypass the triggers, so the log is append-only at the application layer only.
- Control [planned]: shipping audit rows to a separate system, so that history survives a compromised host.

### Supply chain

- Control [enforced]: the image installs dependencies from a hash-locked list with `--require-hashes`, and the base image is pinned by digest.
- Control [enforced]: CI pins every action to a full commit SHA, generates an SBOM, and fails on a fixable CRITICAL vulnerability found by the image scan.
- Control [advisory]: the scan covers the amd64 image only, and unfixed vulnerabilities are not gated.
- Control [planned]: signing the published image and verifying the signature at deploy time.

### Abuse of integrations

- Control [enforced]: the MQTT, NUT and Home Assistant integrations are off unless configured.
- Control [enforced]: the NUT client sends read-only requests, and the Home Assistant client reads history and states only.
- Control [advisory]: an MQTT broker without TLS or authentication lets other clients on the network read hostwatch topics or publish to Home Assistant discovery topics.
- Control [advisory]: Orion and Prometheus keys need the `read:metrics` scope only, and the operator should issue one key per consumer so each can be revoked alone.

### Denial of service

- Control [enforced]: audit rows for denied sources are aggregated per peer per minute, with a cap on tracked peers, so a scanner cannot grow the database without bound.
- Control [enforced]: raw samples are pruned after `HOSTWATCH_RAW_RETENTION_DAYS`.
- Control [advisory]: the hub has no request rate limit, so rely on the allowlist and the network.

### Wrong answers that hide a failure

- Control [enforced]: a missing or unreadable source is reported unavailable with a reason and is never substituted by zero.
- Control [enforced]: an agent that goes silent turns the host stale after the configured window.
- Control [advisory]: power loss is classified from witnesses (a UPS or a smart plug), and without a witness a power pull and a hang look the same, so the boot stays `unknown_unclean`.

## Residual risks

These risks remain after the controls above and are accepted until the planned items are built.

1. **RAPL side channel.** Since kernel 5.10 the energy counters are root-only because of the
   PLATYPUS side channel (CVE-2020-8694). `scripts/rapl-access.sh` grants read access to one group
   so the container can measure power. Any process in that group can read fine-grained energy
   data, so keep interactive accounts out of the group. This is advisory, because the host decides
   who joins it.
2. **Plain HTTP with an allowlist.** The allowlist stops strangers from reaching the login, but
   it does not encrypt anything, and a spoofed or shared address on the same segment is admitted.
   Behind NAT or a proxy, the allowlist admits everything that proxy forwards.
3. **Shared token until disabled.** The legacy ingest token is one secret shared by every agent
   that uses it. Until `HOSTWATCH_LEGACY_TOKEN_DISABLED` is set, leaking it lets an attacker post
   false data. Move every agent to its own ingest key and then disable the token.
4. **Operator trust.** Anyone with `docker exec` or write access to the data volume can use the
   CLI, create keys and edit the database. The audit log records CLI use but cannot stop it.
5. **Unverified on hardware.** Several controls are proven only against fakes. The open checks are
   listed in `UNVERIFIED.md`.
