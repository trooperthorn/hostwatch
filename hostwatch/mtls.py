"""Optional client certificate identity.

Mode "off" never reads any certificate or header. Mode "uvicorn" reads the
client certificate name from the ASGI TLS extension, which exists only when the
server terminates TLS and verified the client certificate itself. Mode "proxy"
reads the certificate subject and subject alternative names from headers set by
a reverse proxy, and only when the TCP peer is on the trusted proxy allowlist
and the proxy reports a successful verification.

The proxy mode is only as strong as the proxy configuration: the proxy must
verify the client certificate against the intended CA, must strip any client
supplied copies of these headers, and must be the only path to the hub. The
allowlist check on the peer address is enforced here, the proxy behaviour is not.

A certificate name is mapped to a user through the cert_bindings table. A name
with no binding authenticates nobody and is audited as an authentication failure.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Callable

from fastapi import Request

from .config import Config
from .store import Store

log = logging.getLogger("hostwatch.mtls")

VERIFY_HEADER = "x-ssl-client-verify"
SUBJECT_HEADER = "x-ssl-client-subject"
SAN_HEADER = "x-ssl-client-san"
MODES = frozenset({"off", "uvicorn", "proxy"})


def parse_proxies(raw: str) -> tuple:
    """Parse a comma separated list of addresses or CIDR networks. A bad entry raises ValueError."""
    nets = []
    for item in (i.strip() for i in raw.split(",")):
        if item:
            nets.append(ipaddress.ip_network(item, strict=False))
    return tuple(nets)


def peer_trusted(cfg: Config, remote: str | None) -> bool:
    try:
        addr = ipaddress.ip_address(remote or "")
    except ValueError:
        return False
    return any(addr in net for net in parse_proxies(cfg.mtls_trusted_proxies))


def normalize(name: str) -> str:
    return " ".join(name.split())


def candidates(subject: str | None, sans: list[str]) -> list[str]:
    """Lookup keys in priority order: the subject, then each SAN as `san:<entry>`."""
    out = []
    if subject and normalize(subject):
        out.append(normalize(subject))
    out.extend("san:" + normalize(s) for s in sans if normalize(s))
    return out


def _from_headers(request: Request) -> list[str] | None:
    h = request.headers
    if h.get(VERIFY_HEADER, "").strip().upper() != "SUCCESS":
        return None
    sans = [s for s in h.get(SAN_HEADER, "").split(",")]
    found = candidates(h.get(SUBJECT_HEADER), sans)
    return found or None


def _from_asgi(request: Request) -> list[str] | None:
    tls = (request.scope.get("extensions") or {}).get("tls") or {}
    name = tls.get("client_cert_name")
    return candidates(name, []) or None


def make_identity(cfg: Config, store: Store):
    """Build the identity hook used by the hub. Returns a callable taking a request."""
    from .hub import Principal, SESSION_SCOPES

    def identity(request: Request):
        if cfg.mtls_mode == "uvicorn":
            names = _from_asgi(request)
        elif cfg.mtls_mode == "proxy":
            remote = request.client.host if request.client else None
            if not peer_trusted(cfg, remote):
                return None  # header from an untrusted peer is ignored, as if absent
            names = _from_headers(request)
        else:
            return None
        if not names:
            return None
        for name in names:
            user = store.find_cert_user(name)
            if user:
                return Principal(user["username"], "mtls", SESSION_SCOPES, {"cert": name},
                                 is_admin=bool(user.get("is_admin")))
        request.state.audit = {"actor": "anonymous", "kind": "auth_failure",
                               "detail": {"cert_result": "unmapped client certificate", "cert": names[0][:256]}}
        return None

    return identity


Identity = Callable[[Request], object]
