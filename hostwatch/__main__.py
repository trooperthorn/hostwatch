"""Entry point.

  python -m hostwatch                run the configured role (HOSTWATCH_ROLE)
  python -m hostwatch collect-once   print one cycle of detection and samples,
                                     without a hub; useful for verification
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time

from .agent import Agent
from .config import Config


def collect_once(cfg: Config) -> int:
    agent = Agent(cfg)
    agent.detect()
    agent.collect_once()           # prime rate-based collectors
    time.sleep(2)
    batch = agent.collect_once()
    print(json.dumps({"host": batch.host, "platform": batch.platform,
                      "sources": [s.model_dump() for s in batch.sources]}, indent=2))
    for s in batch.samples:
        lbl = " ".join(f"{k}={v}" for k, v in s.labels.items())
        print(f"{s.source:9} {s.metric:22} {str(s.value):>14} {s.unit:4} {lbl}")
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config()
    if len(sys.argv) > 1 and sys.argv[1] == "collect-once":
        return collect_once(cfg)
    cfg.validate()

    if cfg.role == "agent":
        agent = Agent(cfg)
        # The handler only sets a flag; the run loop writes the clean flag on exit.
        signal.signal(signal.SIGTERM, lambda *_: agent.stop())
        agent.run()
        return 0

    import uvicorn

    from .hub import create_app
    from .store import Store

    store = Store(cfg.data_dir / "hostwatch.db")
    agent = Agent(cfg) if cfg.role == "all" else None
    thread = threading.Thread(target=agent.run, name="agent", daemon=True) if agent else None
    app = create_app(cfg, store,
                     on_start=thread.start if thread else None,
                     on_stop=agent.stop_and_wait if agent else None)
    uvicorn.run(app, host=cfg.hub_bind, port=cfg.hub_port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
