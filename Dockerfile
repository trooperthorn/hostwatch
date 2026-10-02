FROM python:3.12-slim

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
COPY pyproject.toml ./
COPY hostwatch ./hostwatch
RUN pip install --no-cache-dir . && rm -rf /root/.cache

# A fresh named volume copies the ownership of the image directory, so /data is
# created here owned by the runtime user. Without this the volume would be
# root-owned and the non-root process could not write to it.
RUN mkdir /data && chown 10001:10001 /data

USER hostwatch
VOLUME ["/data"]
ENTRYPOINT ["python", "-m", "hostwatch"]
