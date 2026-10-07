# The base image is pinned by the multi-arch index digest, so a moved tag cannot change the
# build. To update: pull python:3.12-slim, read the new index digest with
# "docker buildx imagetools inspect python:3.12-slim", replace the digest below, then rebuild
# and let CI scan the result before merging.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

# Non-root runtime user. UID/GID are fixed so host-side file ownership on the
# data volume is predictable across rebuilds.
RUN groupadd --system --gid 10001 hostwatch \
 && useradd --system --uid 10001 --gid hostwatch --no-create-home --shell /usr/sbin/nologin hostwatch

# journalctl reads the read-only journal mount for the event engine. Only the
# systemd package is added, without recommended extras, and apt lists are removed.
# Pending Debian security updates are applied at build time, because the pinned
# base image ages between digest updates and the CI scan fails on fixable
# critical vulnerabilities.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends systemd \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.lock pyproject.toml ./
# Every dependency is installed from the hash lock, so a tampered or substituted
# package fails the build. The package itself is then installed without
# resolving anything further.
RUN pip install --require-hashes --no-cache-dir -r requirements.lock
COPY hostwatch ./hostwatch
# pip, setuptools and wheel are only needed to build. They are removed afterwards
# so the runtime image carries no installer with its own vulnerability history.
RUN pip install --no-cache-dir --no-deps . \
 && pip uninstall -y pip setuptools wheel \
 && rm -rf /root/.cache

# A fresh named volume copies the ownership of the image directory, so /data is
# created here owned by the runtime user. Without this the volume would be
# root-owned and the non-root process could not write to it.
RUN mkdir /data && chown 10001:10001 /data

ARG VERSION=unknown
ARG REVISION=unknown
# The repository declares no license yet, so the default is the SPDX value for "not asserted".
# Pass the real SPDX identifier once the owner chooses one.
ARG LICENSES=NOASSERTION
LABEL org.opencontainers.image.title="hostwatch" \
      org.opencontainers.image.source="https://github.com/trooperthorn/hostwatch" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="${LICENSES}"

USER hostwatch
VOLUME ["/data"]
# The agent serves nothing, so the check reads the marker file the agent loop rewrites every
# few seconds in the data directory and fails when it is stale. It says the loop is turning, not
# that Observe is receiving; delivery trouble is reported by the outbox source. The start period
# gives the first detection pass time before failures count.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD ["python", "-m", "hostwatch", "healthcheck"]
ENTRYPOINT ["python", "-m", "hostwatch"]
