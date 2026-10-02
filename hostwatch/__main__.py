"""Entry point.

  python -m hostwatch                run the configured role (HOSTWATCH_ROLE)
  python -m hostwatch collect-once   print one cycle of detection and samples,
                                     without a hub; useful for verification
"""

from __future__ import annotations

import dataclasses
import json
import logging
import signal
import ssl
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


def uvicorn_kwargs(cfg: Config) -> dict:
    """Keyword arguments for uvicorn.run, including TLS when the operator supplied a certificate.

    A client CA asks for a client certificate but does not require one, so
    password and key callers still work; certificate login is decided by the
    hub from the verified identity, not by the handshake alone.
    """
    kwargs: dict = {"host": cfg.hub_bind, "port": cfg.hub_port, "log_level": "info"}
    if cfg.tls_configured:
        kwargs["ssl_certfile"] = cfg.tls_cert
        kwargs["ssl_keyfile"] = cfg.tls_key
        if cfg.tls_client_ca:
            kwargs["ssl_ca_certs"] = cfg.tls_client_ca
            kwargs["ssl_cert_reqs"] = ssl.CERT_OPTIONAL
    return kwargs


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
    if cfg.role == "all":
        # The local agent talks to its own hub with a hashed, scoped key minted in memory.
        from .auth import mint_internal_ingest_key
        cfg = dataclasses.replace(cfg, ingest_key=mint_internal_ingest_key(cfg, store))
    agent = Agent(cfg) if cfg.role == "all" else None
    thread = threading.Thread(target=agent.run, name="agent", daemon=True) if agent else None
    app = create_app(cfg, store,
                     on_start=thread.start if thread else None,
                     on_stop=agent.stop_and_wait if agent else None)
    uvicorn.run(app, **uvicorn_kwargs(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
