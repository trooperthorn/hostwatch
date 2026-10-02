FROM python:3.12-slim

# Non-root runtime user. UID/GID are fixed so host-side file ownership on the
# data volume is predictable across rebuilds.
RUN groupadd --system --gid 10001 hostwatch \
 && useradd --system --uid 10001 --gid hostwatch --no-create-home --shell /usr/sbin/nologin hostwatch

WORKDIR /app
COPY pyproject.toml ./
COPY hostwatch ./hostwatch
RUN pip install --no-cache-dir . && rm -rf /root/.cache

USER hostwatch
VOLUME ["/data"]
ENTRYPOINT ["python", "-m", "hostwatch"]
