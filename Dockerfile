FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

# Non-root runtime user. UID/GID are fixed so host-side file ownership on the
# data volume is predictable across rebuilds.
RUN groupadd --system --gid 10001 hostwatch \
 && useradd --system --uid 10001 --gid hostwatch --no-create-home --shell /usr/sbin/nologin hostwatch

# journalctl reads the read-only journal mount for the event engine. Only the
# systemd package is added, without recommended extras, and apt lists are removed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.lock pyproject.toml ./
# Every dependency is installed from the hash lock, so a tampered or substituted
# package fails the build. The package itself is then installed without
# resolving anything further.
RUN pip install --require-hashes --no-cache-dir -r requirements.lock
COPY hostwatch ./hostwatch
RUN pip install --no-cache-dir --no-deps . && rm -rf /root/.cache

# A fresh named volume copies the ownership of the image directory, so /data is
# created here owned by the runtime user. Without this the volume would be
# root-owned and the non-root process could not write to it.
RUN mkdir /data && chown 10001:10001 /data

USER hostwatch
VOLUME ["/data"]
ENTRYPOINT ["python", "-m", "hostwatch"]
