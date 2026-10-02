"""Entry point.

  python -m hostwatch                run the configured role (HOSTWATCH_ROLE)
  python -m hostwatch bootstrap-admin | user ... | key ...
                                     operator commands, see cli.py
  python -m hostwatch collect-once   print one cycle of detection and samples,
                                     without a hub; useful for verification
"""

from __future__ import annotations

import dataclasses
import json
import logging
import signal
import socket
import ssl
import sys
import threading
import time

from . import cli
from .agent import Agent
from .config import Config, _is_loopback, normalize_ip


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


LOOPBACK_V4 = "127.0.0.1"


def listen_addresses(cfg: Config) -> list[tuple[str, int]]:
    """The (host, port) pairs the hub serves on.

    The all role runs the agent in the same process and the agent posts over
    loopback. When the hub is bound to one specific non-loopback address, that
    address does not accept loopback connections, so 127.0.0.1 is added as a
    second listener. The hub role and every loopback or wildcard bind get the
    single configured address.
    """
    addrs = [(cfg.hub_bind, cfg.hub_port)]
    if cfg.role == "all" and not _is_loopback(cfg.hub_bind):
        try:
            unspecified = normalize_ip(cfg.hub_bind).is_unspecified
        except ValueError:
            unspecified = False
        if not unspecified:
            addrs.append((LOOPBACK_V4, cfg.hub_port))
    return addrs


def local_agent_hub_url(cfg: Config) -> str:
    """The hub URL the in-process agent uses in the all role: always loopback, same scheme and port."""
    scheme = "https" if cfg.tls_configured else "http"
    return f"{scheme}://{LOOPBACK_V4}:{cfg.hub_port}"


def _bind_one(host: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if sys.platform != "win32":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(2048)
        sock.set_inheritable(True)
    except OSError:
        sock.close()
        raise
    return sock


def bind_sockets(cfg: Config, bind_one=_bind_one) -> list[socket.socket]:
    """Bind every listener before serving. If any bind fails, close the ones already bound and raise
    RuntimeError naming the address, so startup fails loudly instead of the agent queueing silently."""
    socks: list[socket.socket] = []
    for host, port in listen_addresses(cfg):
        try:
            socks.append(bind_one(host, port))
        except OSError as exc:
            for s in socks:
                s.close()
            raise RuntimeError(
                f"Cannot listen on {host}:{port} ({exc}). In the all role the hub must listen on both the "
                f"configured address and {LOOPBACK_V4} so the local agent can deliver; free the port or "
                "change HOSTWATCH_HUB_BIND or HOSTWATCH_HUB_PORT.") from exc
    return socks


def serve_hub(app, cfg: Config) -> None:
    import uvicorn
    kwargs = uvicorn_kwargs(cfg)
    if len(listen_addresses(cfg)) == 1:
        uvicorn.run(app, **kwargs)
        return
    socks = bind_sockets(cfg)
    try:
        uvicorn.Server(uvicorn.Config(app, **kwargs)).run(sockets=socks)
    finally:
        for s in socks:
            s.close()


def build_ha(cfg: Config, store, transport_factory=None):
    """The Home Assistant discovery publisher and events publisher, sharing one MQTT client, or
    (None, None) when MQTT is not configured. Only the hub and all roles call this."""
    if not cfg.mqtt_enabled:
        return None, None
    from .integrations.ha_events import HomeAssistantEventPublisher
    from .integrations.homeassistant import HomeAssistantPublisher
    from .integrations.mqtt_client import MqttClient, PahoTransport
    transport = transport_factory() if transport_factory else PahoTransport("hostwatch-hub")
    client = MqttClient(cfg, transport)
    return HomeAssistantPublisher(cfg, client, store), HomeAssistantEventPublisher(cfg, client, store)


def chain(*hooks):
    """One callable that runs each non-None hook in order, or None when there are none."""
    active = [h for h in hooks if h]
    if not active:
        return None

    def run() -> None:
        for hook in active:
            hook()
    return run


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config()
    if argv and argv[0] == "collect-once":
        return collect_once(cfg)
    if argv and argv[0] in cli.COMMANDS:
        return cli.run(argv, cfg)
    cfg.validate()

    if cfg.role == "agent":
        agent = Agent(cfg)
        # The handler only sets a flag; the run loop writes the clean flag on exit.
        signal.signal(signal.SIGTERM, lambda *_: agent.stop())
        agent.run()
        return 0

    from .hub import create_app
    from .store import Store

    store = Store(cfg.data_dir / "hostwatch.db")
    if cfg.role == "all":
        # The local agent talks to its own hub with a hashed, scoped key minted in memory.
        from .auth import mint_internal_ingest_key
        cfg = dataclasses.replace(cfg, ingest_key=mint_internal_ingest_key(cfg, store),
                                  hub_url=local_agent_hub_url(cfg))
    agent = Agent(cfg) if cfg.role == "all" else None
    thread = threading.Thread(target=agent.run, name="agent", daemon=True) if agent else None
    ha_publisher, ha_events = build_ha(cfg, store)
    app = create_app(cfg, store,
                     on_start=chain(thread.start if thread else None, ha_events.start if ha_events else None),
                     on_stop=chain(ha_events.stop if ha_events else None, agent.stop_and_wait if agent else None),
                     ha_publisher=ha_publisher)
    serve_hub(app, cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
