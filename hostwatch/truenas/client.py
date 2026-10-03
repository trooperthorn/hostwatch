"""Read-only TrueNAS JSON-RPC 2.0 client over WebSocket.

Rules this module keeps:

* Only the methods in `ALLOWED_METHODS` can be sent. The check runs in the one function that
  writes a frame, before anything is written, so a method outside the list raises
  `MethodNotAllowed` and no frame leaves the process. The API key the operator supplies should
  also be a READONLY_ADMIN key, so the client and the key each prevent changes to the NAS.
* A failure of any kind (no key file, refused connection, TLS failure, rejected key, timeout,
  error answer from the server) is returned as a `Result` with `available=False` and a reason.
  Nothing is substituted for a missing answer.
* The key is read from its file at connect time, is sent only in the login frame, is held in a
  `Secret` and never appears in a log line, a reason or a repr. Reasons are built from exception
  class names, and any text that could hold the key is scrubbed.
* TLS verification is on for `wss://`. `ca_file` names a private CA bundle. `insecure` turns
  verification off and must be set explicitly. A plain `ws://` URL is refused unless the host is
  loopback or `insecure` is set, because the login frame carries the key.
* `{"$date": ms}` values in answers are converted to epoch seconds by `convert_dates`.

The endpoint path (expected `wss://<host>/api/current`) and whether the server refuses an API key
over plain `ws` are recorded in `UNVERIFIED.md`; the URL is configurable for that reason.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, WebSocketException

from ..config import Secret

log = logging.getLogger(__name__)

LOGIN_METHOD = "auth.login_with_api_key"
ALLOWED_METHODS = frozenset({
    LOGIN_METHOD,
    "system.info",
    "system.boot_id",
    "pool.query",
    "disk.query",
    "disk.temperatures",
    "alert.list",
    "pool.scrub.query",
})
DEFAULT_TIMEOUT_S = 10.0


class MethodNotAllowed(Exception):
    """Raised before any frame is sent when the method is not on the allowlist."""


class _Unavailable(Exception):
    """Internal: carries a reason that is safe to report."""


@dataclass(frozen=True)
class Result:
    """The answer to one call. `value` is meaningful only when `available` is true."""
    available: bool
    value: Any = None
    reason: str = ""


def convert_dates(value: Any) -> Any:
    """Return `value` with every `{"$date": ms}` object replaced by epoch seconds (float)."""
    if isinstance(value, dict):
        if set(value) == {"$date"} and isinstance(value["$date"], (int, float)) \
                and not isinstance(value["$date"], bool):
            return value["$date"] / 1000.0
        return {k: convert_dates(v) for k, v in value.items()}
    if isinstance(value, list):
        return [convert_dates(v) for v in value]
    return value


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class TruenasClient:
    def __init__(self, url: str, api_key_file: str, *, ca_file: str = "", insecure: bool = False,
                 timeout: float = DEFAULT_TIMEOUT_S) -> None:
        self._url = url.strip()
        self._key_file = api_key_file
        self._ca_file = ca_file
        self._insecure = insecure
        self._timeout = timeout
        self._ws = None
        self._next_id = 1
        self._key = Secret("")

    @classmethod
    def from_config(cls, cfg) -> "TruenasClient | None":
        """Build a client from settings, or None when no URL is configured."""
        if not cfg.truenas_url:
            return None
        return cls(cfg.truenas_url, cfg.truenas_api_key_file, ca_file=cfg.truenas_ca,
                   insecure=cfg.truenas_insecure, timeout=cfg.truenas_timeout_s)

    def __repr__(self) -> str:
        return f"TruenasClient(url={self._url!r}, connected={self._ws is not None})"

    # -- public API ---------------------------------------------------------------------------

    async def call(self, method: str, params: list | None = None) -> Result:
        """Call an allowed method. Raises MethodNotAllowed for any other; otherwise never raises."""
        self._check_allowed(method)
        for attempt in (0, 1):
            try:
                async with asyncio.timeout(self._timeout):
                    await self._ensure_connected()
                    return Result(True, convert_dates(await self._request(method, params or [])))
            except _Unavailable as exc:
                await self.close()
                return Result(False, reason=self._scrub(str(exc)))
            except TimeoutError:
                await self.close()
                return Result(False, reason="timed out")
            except (ConnectionClosed, OSError) as exc:
                # A dropped connection is retried once on a fresh one (reconnect and login).
                await self.close()
                if attempt == 1:
                    return Result(False, reason=self._scrub(f"connection failed: {type(exc).__name__}"))
            except (WebSocketException, ValueError) as exc:
                await self.close()
                return Result(False, reason=self._scrub(f"connection failed: {type(exc).__name__}"))
        return Result(False, reason="connection failed")

    async def close(self) -> None:
        ws, self._ws = self._ws, None
        if ws is not None:
            try:
                await ws.close()
            except Exception:  # closing a broken socket must not mask the original failure
                pass

    # -- internals ----------------------------------------------------------------------------

    @staticmethod
    def _check_allowed(method: str) -> None:
        if method not in ALLOWED_METHODS:
            raise MethodNotAllowed(f"method {method!r} is not on the read-only allowlist")

    def _scrub(self, text: str) -> str:
        key = str(self._key)
        return text.replace(key, "***") if key else text

    def _ssl_context(self, scheme: str, host: str) -> ssl.SSLContext | None:
        if scheme == "ws":
            if not (_is_loopback(host) or self._insecure):
                raise _Unavailable("plain ws is refused for a non-loopback host; use wss")
            return None
        try:
            ctx = ssl.create_default_context(cafile=self._ca_file or None)
        except (OSError, ssl.SSLError) as exc:
            raise _Unavailable(f"CA file unusable: {type(exc).__name__}") from None
        if self._insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _read_key(self) -> Secret:
        if not self._key_file:
            raise _Unavailable("no API key file configured")
        try:
            text = Path(self._key_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise _Unavailable(f"API key file unreadable: {type(exc).__name__}") from None
        if not text:
            raise _Unavailable("API key file is empty")
        return Secret(text)

    async def _ensure_connected(self) -> None:
        if self._ws is not None:
            return
        parsed = urlparse(self._url)
        if parsed.scheme not in ("ws", "wss") or not parsed.hostname:
            raise _Unavailable("TrueNAS URL must be ws:// or wss://")
        ctx = self._ssl_context(parsed.scheme, parsed.hostname)
        self._key = self._read_key()
        kwargs = {"ssl": ctx} if ctx is not None else {}
        self._ws = await connect(self._url, open_timeout=self._timeout, proxy=None, **kwargs)
        if await self._request(LOGIN_METHOD, [str(self._key)]) is not True:
            raise _Unavailable("API key rejected")

    async def _send(self, frame: dict) -> None:
        """The only place a frame is written. The allowlist check lives here."""
        self._check_allowed(frame.get("method", ""))
        await self._ws.send(json.dumps(frame))

    async def _request(self, method: str, params: list) -> Any:
        request_id = self._next_id
        self._next_id += 1
        await self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            try:
                frame = json.loads(await self._ws.recv())
            except json.JSONDecodeError:
                raise _Unavailable("unreadable answer from TrueNAS") from None
            if not isinstance(frame, dict) or frame.get("id") != request_id:
                continue
            if "error" in frame:
                err = frame["error"] if isinstance(frame["error"], dict) else {}
                if method == LOGIN_METHOD:
                    raise _Unavailable("API key rejected")
                raise _Unavailable(f"TrueNAS error {err.get('code', '?')} for {method}")
            return frame.get("result")
