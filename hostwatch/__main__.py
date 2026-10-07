"""Entry point.

  python -m hostwatch                run the agent
  python -m hostwatch healthcheck    exit 0 when the agent loop has run recently, used by the
                                     container HEALTHCHECK
  python -m hostwatch collect-once   print one cycle of detection and samples, without sending
                                     anything; useful for verification
  python -m hostwatch windows run    the native Windows agent in the foreground, see cli.py
  python -m hostwatch control ...    the hostwatch-control daemon, see cli.py
"""

from __future__ import annotations

import logging
import signal
import sys
import time
from pathlib import Path

from . import cli
from .agent import ALIVE_FILE, Agent
from .config import Config

# The loop writes its marker every few seconds. A marker older than this means the loop is stuck.
ALIVE_MAX_AGE_S = 120.0


def collect_once(cfg: Config) -> int:
    agent = Agent(cfg)
    agent.detect()
    agent.collect_samples()           # prime rate-based collectors
    time.sleep(2)
    samples = agent.collect_samples()
    print(f"host={cfg.host_name} platform={agent.platform}")
    for st in agent.status.values():
        print(f"source {st.source}: {'available' if st.available else 'unavailable'}"
              f"{' (' + st.reason + ')' if st.reason else ''}")
    for s in samples:
        lbl = " ".join(f"{k}={v}" for k, v in s.labels.items())
        print(f"{s.source:9} {s.metric:22} {str(s.value):>14} {s.unit:4} {lbl}")
    return 0


def healthcheck(cfg: Config, now: float | None = None) -> int:
    """Return 0 when the agent loop has written its marker recently, else 1. The agent serves
    nothing, so this reads the marker file in the data directory. It says the loop is turning, not
    that Observe is receiving: delivery trouble is reported by the outbox source."""
    path: Path = cfg.data_dir / ALIVE_FILE
    try:
        written = float(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"unhealthy: {path} is not readable: {exc}", file=sys.stderr)
        return 1
    age = (time.time() if now is None else now) - written
    if age > ALIVE_MAX_AGE_S:
        print(f"unhealthy: the agent loop last ran {age:.0f}s ago", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config()
    if argv and argv[0] == "healthcheck":
        return healthcheck(cfg)
    if argv and argv[0] == "collect-once":
        return collect_once(cfg)
    if argv and argv[0] in cli.COMMANDS:
        return cli.run(argv, cfg)
    try:
        cfg.validate()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    agent = Agent(cfg)
    # The handler only sets a flag; the run loop writes the clean flag on exit.
    signal.signal(signal.SIGTERM, lambda *_: agent.stop())
    agent.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
