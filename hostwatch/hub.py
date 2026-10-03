"""Hub: receives agent batches and serves read endpoints.

Every route except health goes through one authenticate dependency and a scope
check, and every authenticated request and every authentication failure is
appended to the audit log. Credentials are tried in this order: a session
cookie, a scoped bearer API key, the legacy shared ingest token (accepted for the
ingest scope only, deprecated), and last an mTLS identity (see mtls.py, off by default). POST /api/v1/login and /api/v1/logout manage
browser sessions; a cookie-authenticated state-changing request must carry the
CSRF header (see docs/ARCHITECTURE.md). TLS serving and the Home Assistant and
Orion endpoints arrive in later slices, so keep the hub on loopback until then.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import time
from contextlib import asynccontextmanager
from importlib.resources import files
from dataclasses import dataclass, field
from typing import Callable

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, auth
from .config import Config, normalize_ip, parse_allowed_clients
from .integrations import orion as orion_doc
from .integrations import ui_status as ui_status_doc
from .integrations import prometheus as prom
from .integrations.summary import build_host_summary
from .schema import Batch
from .store import Store

log = logging.getLogger("hostwatch.hub")

SESSION_COOKIE = "hostwatch_session"
CSRF_COOKIE = "hostwatch_csrf"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# A browser session may read but never ingest. Admin satisfies every scope except ingest.
SESSION_SCOPES = frozenset({"read:metrics", "read:events"})


class KeyCreate(BaseModel):
    scopes: list[str] = Field(min_length=1, max_length=8)
    owner: str = Field(min_length=1, max_length=64)


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class DenialAggregator:
    """Bounds source_denied audit growth. The first denial from a peer is written. Further denials
    inside the window are only counted; the first one after the window closes is written with the
    count of denials since the previous row. At most one row per peer per window, and at most
    MAX_PEERS peers are tracked (extra peers share one bucket), so memory and database growth stay
    bounded however many requests a scanner sends."""

    WINDOW_S = 60.0
    MAX_PEERS = 4096
    OVERFLOW = "overflow"

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._state: dict[str, list] = {}  # peer -> [last row time, denials not yet written]

    def note(self, peer: str):
        """Record one denial. Returns None when no row should be written, 0 for a first row, or
        the number of denials the summary row covers (including this one)."""
        now = self._clock()
        if peer not in self._state and len(self._state) >= self.MAX_PEERS:
            self._state = {k: v for k, v in self._state.items() if now - v[0] < self.WINDOW_S}
            if len(self._state) >= self.MAX_PEERS:
                peer = self.OVERFLOW
        entry = self._state.get(peer)
        if entry is None:
            self._state[peer] = [now, 0]
            return 0
        if now - entry[0] < self.WINDOW_S:
            entry[1] += 1
            return None
        covered = entry[1] + 1
        self._state[peer] = [now, 0]
        return covered


CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; "
       "frame-ancestors 'none'; base-uri 'none'")


def csrf_token_for(session_token: str) -> str:
    """The CSRF token is derived from the session token, so the server can verify it
    without storing it and a token from another session never matches."""
    return hashlib.sha256(b"hostwatch-csrf:" + session_token.encode()).hexdigest()


@dataclass
class Principal:
    actor: str
    kind: str  # session, api_key, mtls or legacy_token
    scopes: frozenset
    detail: dict = field(default_factory=dict)
    is_admin: bool = False  # session and mTLS users carry the users.is_admin flag; API keys use the admin scope

    def allows(self, scope: str) -> bool:
        return scope in self.scopes or ("admin" in self.scopes and scope != "ingest")


WITNESS_RETRY_TICK_S = 60.0


def create_app(cfg: Config, store: Store, on_start=None, on_stop=None, denial_clock=time.monotonic,
               mtls_identity: Callable[[Request], Principal | None] | None = None,
               ha_publisher=None, ha_interval_s: float = 30.0, power_witness=None) -> FastAPI:
    if mtls_identity is None:
        from .mtls import make_identity
        mtls_identity = make_identity(cfg, store)

    async def maintenance_loop():
        while True:
            await asyncio.sleep(3600)
            try:
                await asyncio.to_thread(store.maintain, cfg.raw_retention_days, cfg.rollup_retention_days)
            except Exception as exc:
                log.warning("maintenance failed: %s", exc)

    async def ha_loop():
        while True:
            try:
                await asyncio.to_thread(ha_publisher.tick)
            except Exception as exc:
                log.warning("Home Assistant publish failed (%s)", type(exc).__name__)
            await asyncio.sleep(ha_interval_s)

    async def witness_retry_loop(startup_done: asyncio.Event):
        from .witness.power import retry_pending
        startup = True
        while True:
            try:
                await asyncio.to_thread(retry_pending, store, power_witness, cfg.witness_skew_s,
                                        cfg.witness_retry_s, time.time(), startup)
            except Exception as exc:
                log.warning("power witness retry pass failed (%s)", type(exc).__name__)
            if startup:
                startup = False
                startup_done.set()
            await asyncio.sleep(WITNESS_RETRY_TICK_S)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(maintenance_loop())
        app.state.witness_startup_done = asyncio.Event()
        retry_task = asyncio.create_task(witness_retry_loop(app.state.witness_startup_done))
        ha_task = asyncio.create_task(ha_loop()) if ha_publisher else None
        if on_start:
            on_start()
        yield
        if on_stop:
            on_stop()
        task.cancel()
        retry_task.cancel()
        await asyncio.gather(retry_task, return_exceptions=True)
        if ha_task:
            ha_task.cancel()
            await asyncio.gather(ha_task, return_exceptions=True)
            await asyncio.to_thread(ha_publisher.close)

    app = FastAPI(title="hostwatch hub", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # The default handler echoes the rejected input, which cannot be encoded
        # to JSON when it is NaN or infinity and would turn a 422 into a 500.
        errors = [{"loc": list(e.get("loc", ())), "msg": str(e.get("msg", "")), "type": e.get("type", "")}
                  for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": errors})

    name_key = auth.audit_name_key(cfg)
    legacy_noted: list = []  # one deprecation audit row per hub process; every use is still audited

    def _resolve(request: Request) -> Principal | None:
        cookie = request.cookies.get(SESSION_COOKIE)
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if cookie and scheme.lower() == "bearer" and token:
            # Two credential kinds on one request is ambiguous, so neither is tried.
            request.state.audit = {"actor": "anonymous", "kind": "auth_failure",
                                   "detail": {"credentials": ["session_cookie", "bearer"],
                                              "reason": "request carried both a session cookie and a bearer credential"}}
            raise HTTPException(status_code=400, detail="send either a session cookie or a bearer credential, not both")
        if cookie:
            sess = store.get_session(cookie)
            if sess:
                request.state.session_token = cookie
                return Principal(sess["username"], "session", SESSION_SCOPES, is_admin=bool(sess["is_admin"]))
        if scheme.lower() == "bearer" and token:
            if token.startswith("hw_"):
                key = store.find_api_key(token)
                if key:
                    return Principal(f"key:{key['prefix']}", "api_key", frozenset(key["scopes"]),
                                     {"owner": key["owner"]}, is_admin="admin" in key["scopes"])
                prefix, why = store.classify_api_key_failure(token)
                extra = {"key_reason": why}
                if prefix:
                    extra["key_prefix"] = prefix
                request.state.audit_extra = extra
            elif cfg.ingest_token and hmac.compare_digest(token.encode(), cfg.ingest_token.encode()):
                if cfg.legacy_token_disabled:
                    request.state.auth_reason = "legacy shared ingest token is disabled"
                    return mtls_identity(request)
                if not legacy_noted:
                    legacy_noted.append(True)
                    store.append_audit("legacy-token", "deprecation", request.method, request.url.path, 0,
                                       request.client.host if request.client else "unknown",
                                       {"deprecated": "the shared ingest token is in use; give the agent a scoped "
                                        "HOSTWATCH_INGEST_KEY and set HOSTWATCH_LEGACY_TOKEN_DISABLED=1"})
                    log.warning("legacy shared ingest token used; migrate the agent to HOSTWATCH_INGEST_KEY")
                return Principal("legacy-token", "legacy_token", frozenset({"ingest"}),
                                 {"deprecated": "shared ingest token, replace with a scoped key"})
        return mtls_identity(request)

    def authenticate(request: Request) -> Principal:
        principal = _resolve(request)
        if principal is None:
            if not getattr(request.state, "auth_reason", None):
                request.state.auth_reason = "invalid or missing credentials"
            raise HTTPException(status_code=401, detail="authentication required")
        request.state.principal = principal
        if principal.kind == "session" and request.method not in SAFE_METHODS:
            sent = request.headers.get(CSRF_HEADER, "")
            expected = csrf_token_for(request.state.session_token)
            if not hmac.compare_digest(sent.encode(), expected.encode()):
                request.state.auth_reason = "missing or invalid CSRF token"
                raise HTTPException(status_code=403, detail="CSRF token required")
        return principal

    def require_scope(scope: str):
        def check(request: Request, principal: Principal = Depends(authenticate)) -> Principal:
            if not principal.allows(scope):
                request.state.auth_reason = f"missing scope {scope}"
                raise HTTPException(status_code=403, detail="insufficient scope")
            return principal
        return check

    def require_admin(request: Request, principal: Principal = Depends(authenticate)) -> Principal:
        if not principal.is_admin:
            request.state.auth_reason = "administrator required"
            raise HTTPException(status_code=403, detail="administrator required")
        return principal

    app.state.require_admin = require_admin

    allowed_clients = parse_allowed_clients(cfg.allowed_clients)
    denials = DenialAggregator(clock=denial_clock)

    @app.middleware("http")
    async def audit(request: Request, call_next):
        # The row is written in finally so a request that raises still leaves one (status 500).
        status = 500
        response = None
        try:
            response = await call_next(request)
            status = response.status_code
        finally:
            if not await _write_audit(request, status):
                if response is not None:
                    response = JSONResponse(status_code=500, content={"detail": "audit unavailable"})
        return response

    async def _write_audit(request: Request, status: int) -> bool:
        """Append the audit row for this request. Returns False only if the write failed."""
        if request.url.path == "/internal/v1/health" or request.url.path == "/"                 or request.url.path.startswith("/static/"):
            # The UI shell is public static content. Browsers send the session cookie with every
            # asset request, so auditing these would bury the real access rows.
            return True
        principal = getattr(request.state, "principal", None)
        override = getattr(request.state, "audit", None)
        presented = bool(request.cookies or request.headers.get("authorization"))
        # 404 and 405 are routed before authentication runs, so they are audited only when the
        # caller presented credentials, which keeps unauthenticated scanner noise out of the log.
        if principal is None and override is None and status != 401 and not presented:
            return True
        detail = dict(principal.detail) if principal else {}
        if override:
            detail.update(override["detail"])
        detail.update(getattr(request.state, "audit_extra", None) or {})
        reason = getattr(request.state, "auth_reason", None)
        if reason:
            detail["reason"] = reason
        elif principal is None and override is None and status != 401:
            detail["reason"] = "credentials presented but the request did not authenticate"
        kind = "auth_failure" if status in (401, 403) else "access"
        actor = principal.actor if principal else "anonymous"
        if override:
            actor, kind = override["actor"], override["kind"]
        if principal:
            detail["credential"] = principal.kind
        remote = request.client.host if request.client else "unknown"
        try:
            await asyncio.to_thread(store.append_audit, actor, kind,
                                    request.method, request.url.path, status, remote, detail)
        except Exception as exc:
            log.error("audit write failed: %s", exc)
            return False
        return True

    if allowed_clients:
        @app.middleware("http")
        async def source_filter(request: Request, call_next):
            """Exposure control, not authentication: reject peers not on the allowlist before any
            credential is looked at. Uses the socket peer, never a forwarded header. Loopback is
            always allowed so the local agent can ingest."""
            peer = request.client.host if request.client else ""
            try:
                addr = normalize_ip(peer)
                permitted = addr.is_loopback or addr in allowed_clients
            except ValueError:
                permitted = False
            if permitted:
                return await call_next(request)
            summary = denials.note(peer or "unknown")
            if summary is not None:
                detail = {"reason": "client address is not in HOSTWATCH_ALLOWED_CLIENTS"}
                if summary > 0:
                    detail["denied_since_last_row"] = summary
                try:
                    await asyncio.to_thread(store.append_audit, "anonymous", "source_denied", request.method,
                                            request.url.path, 403, peer or "unknown", detail)
                except Exception as exc:
                    log.error("audit write failed: %s", exc)
            return JSONResponse(status_code=403, content={"detail": "forbidden"})

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        # Outermost middleware, so it also covers allowlist refusals and audit failures.
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # Static UI shell: public by design, it holds no data. Every data call it makes goes through
    # the authenticated API.
    web_dir = files("hostwatch").joinpath("web")

    async def index(request: Request):
        return FileResponse(str(web_dir.joinpath("index.html")), media_type="text/html")

    app.add_route("/", index, methods=["GET"], include_in_schema=False)
    app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")

    def _uniform_401() -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": "invalid credentials"})

    @app.post("/api/v1/login")
    def login(body: LoginBody, request: Request):
        """Every failure (unknown user, wrong password, locked, disabled) returns the same
        401. The real reason goes to the audit log only."""
        result = auth.check_login(store, cfg, body.username, body.password)
        # An unknown name may be a mistyped password, so its text is never stored; only a keyed
        # fingerprint, so repeated attempts can be correlated.
        if store.get_user(body.username) is not None:
            detail = {"username_attempted": body.username[:64], "reason": result.reason}
        else:
            detail = {"unknown_user": True, "reason": result.reason,
                      "username_hmac": auth.name_fingerprint(name_key, body.username)}
        if not result.ok:
            request.state.audit = {"actor": "anonymous", "kind": "auth_failure", "detail": detail}
            return _uniform_401()
        token = auth.generate_session_token(store, result.user["id"], cfg.session_ttl_s)
        request.state.audit = {"actor": result.user["username"], "kind": "login", "detail": detail}
        csrf = csrf_token_for(token)
        resp = JSONResponse(content={"username": result.user["username"], "csrf_token": csrf})
        resp.set_cookie(SESSION_COOKIE, token, max_age=int(cfg.session_ttl_s), path="/",
                        httponly=True, secure=cfg.tls_active, samesite="strict")
        # Readable by page script on purpose: the script copies it into the CSRF header.
        resp.set_cookie(CSRF_COOKIE, csrf, max_age=int(cfg.session_ttl_s), path="/",
                        httponly=False, secure=cfg.tls_active, samesite="strict")
        return resp

    @app.post("/api/v1/logout")
    def logout(request: Request, principal: Principal = Depends(authenticate)):
        if principal.kind != "session":
            raise HTTPException(status_code=400, detail="logout applies to browser sessions only")
        store.revoke_session(request.state.session_token)
        request.state.audit = {"actor": principal.actor, "kind": "logout", "detail": {}}
        resp = JSONResponse(content={"status": "logged out"})
        resp.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=cfg.tls_active, samesite="strict")
        resp.delete_cookie(CSRF_COOKIE, path="/", secure=cfg.tls_active, samesite="strict")
        return resp

    @app.get("/api/v1/admin/keys")
    def admin_list_keys(principal: Principal = Depends(require_admin)):
        """Every key without its secret or hash."""
        return {"keys": store.list_api_keys()}

    @app.post("/api/v1/admin/keys", status_code=201)
    def admin_create_key(body: KeyCreate, request: Request, principal: Principal = Depends(require_admin)):
        """Create a key. The secret appears in this response only and the response must not be cached."""
        try:
            secret, row = auth.generate_api_key(store, body.scopes, body.owner)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        request.state.audit = {"actor": principal.actor, "kind": "api_key_create",
                               "detail": {"key_id": row["id"], "prefix": row["prefix"],
                                          "scopes": row["scopes"], "owner": row["owner"]}}
        return JSONResponse(status_code=201, content={"key": row, "secret": secret},
                            headers={"Cache-Control": "no-store"})

    @app.post("/api/v1/admin/keys/{key_id}/revoke")
    def admin_revoke_key(key_id: int, request: Request, principal: Principal = Depends(require_admin)):
        if not store.revoke_api_key(key_id):
            raise HTTPException(status_code=404, detail="no active key with that id")
        request.state.audit = {"actor": principal.actor, "kind": "api_key_revoke",
                               "detail": {"key_id": key_id}}
        return JSONResponse(content={"status": "revoked", "key_id": key_id}, headers={"Cache-Control": "no-store"})

    @app.get("/api/v1/admin/audit")
    def admin_audit(kind: str | None = Query(default=None, max_length=64),
                    actor: str | None = Query(default=None, max_length=128),
                    since: float | None = None, until: float | None = None,
                    before_id: int | None = Query(default=None, ge=1),
                    limit: int = Query(default=100, ge=1, le=500),
                    principal: Principal = Depends(require_admin)):
        """Read-only view of the audit log, newest first. There is no write or delete route."""
        return {"rows": store.audit_rows(limit=limit, kind=kind, actor=actor, before_id=before_id,
                                         since=since, until=until)}

    @app.get("/internal/v1/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.post("/internal/v1/ingest", dependencies=[Depends(require_scope("ingest"))])
    def ingest(batch: Batch, background: BackgroundTasks):
        n, e, duplicate = store.ingest_batch(batch)
        if e and not duplicate:
            from .witness.power import assess_batch_events, eligible
            boots = [d for d in (ev.model_dump() for ev in batch.events) if eligible(d)]
            if boots:
                # After the response: the witness may take seconds and the agent must not wait.
                background.add_task(assess_batch_events, store, power_witness, batch.host, boots, cfg.witness_skew_s,
                                    cfg.witness_retry_s)
        out = {"stored": n, "events_stored": e}
        if duplicate:
            out["duplicate"] = True
        return out

    @app.get("/internal/v1/latest", dependencies=[Depends(require_scope("read:metrics"))])
    def latest(host: str | None = None):
        return store.latest(host)

    @app.get("/internal/v1/sources", dependencies=[Depends(require_scope("read:metrics"))])
    def sources():
        return {"agents": store.agents(), "sources": store.sources()}

    @app.get("/internal/v1/events", dependencies=[Depends(require_scope("read:events"))])
    def events(response: Response, host: str | None = None, since: float | None = None,
               kind: str | None = None, source: str | None = None, before: float | None = None,
               before_id: int | None = None, limit: int = Query(default=100, ge=1, le=1000)):
        rows = store.events(host=host, since=since, kind=kind, limit=limit, source=source,
                            before=before, before_id=before_id)
        if len(rows) == limit:
            # A full page means there may be more. The body stays a plain list so
            # existing readers keep working; the cursor travels in headers.
            response.headers["X-Next-Before"] = repr(rows[-1]["ts"])
            response.headers["X-Next-Before-Id"] = str(rows[-1]["id"])
        return rows

    @app.get("/internal/v1/gaps", dependencies=[Depends(require_scope("read:metrics"))])
    def gaps(host: str, source: str, metric: str, hours: float = 24, max_gap_s: float = 60):
        import time
        now = time.time()
        found = store.gaps(host, source, metric, now - hours * 3600, max_gap_s, until=now + 1.0)
        return {"gap_count": len(found), "gaps": found}

    summary_opts = {"silent_after_s": cfg.silence_window_s, "crash_hold_s": cfg.crash_hold_s}

    def orion_summary(host: str):
        if not any(a["host"] == host for a in store.agents()) and not any(r["host"] == host for r in store.sources()):
            raise HTTPException(status_code=404, detail="unknown host")
        return build_host_summary(store, host, time.time(), **summary_opts)

    HISTORY_MAX_POINTS = 1000
    HISTORY_MAX_RANGE_S = 366 * 86400.0

    @app.get("/api/v1/hosts/{host}/history", dependencies=[Depends(require_scope("read:metrics"))])
    def host_history(host: str, source: str = Query(min_length=1, max_length=64),
                     metric: str = Query(min_length=1, max_length=64),
                     since: float = Query(allow_inf_nan=False), until: float | None = Query(default=None, allow_inf_nan=False),
                     step: float | None = Query(default=None, gt=0, allow_inf_nan=False)):
        end = time.time() if until is None else until
        span = end - since
        if span <= 0:
            raise HTTPException(status_code=422, detail="since must be earlier than until")
        if span > HISTORY_MAX_RANGE_S:
            raise HTTPException(status_code=422, detail="range is longer than 366 days")
        if step is None:
            step = max(60.0, span / 300.0)
        if span / step > HISTORY_MAX_POINTS:
            raise HTTPException(status_code=422,
                                detail=f"range and step would return more than {HISTORY_MAX_POINTS} points per series")
        return store.history(host, source, metric, since, end, step, limit=HISTORY_MAX_POINTS * 50)

    @app.get("/api/v1/ui/status", dependencies=[Depends(require_scope("read:metrics"))])
    def ui_status():
        now = time.time()
        names = sorted({a["host"] for a in store.agents()} | {r["host"] for r in store.sources()})
        return ui_status_doc.status_document([build_host_summary(store, n, now, **summary_opts) for n in names], now)

    @app.get("/api/v1/orion/hosts", dependencies=[Depends(require_scope("read:metrics"))])
    def orion_hosts():
        names = sorted({a["host"] for a in store.agents()} | {r["host"] for r in store.sources()})
        out: dict = {"host_count": len(names)}
        for name, key in orion_doc.host_keys(names).items():
            s = build_host_summary(store, name, time.time(), **summary_opts)
            out[f"host_{key}_name"] = name
            out[f"host_{key}_status"] = s.overall_status
        return out

    @app.get("/api/v1/orion/hosts/{host}/summary", dependencies=[Depends(require_scope("read:metrics"))])
    def orion_host_summary(host: str):
        return orion_doc.summary_document(orion_summary(host))

    @app.get("/api/v1/orion/hosts/{host}/{group}", dependencies=[Depends(require_scope("read:metrics"))])
    def orion_group(host: str, group: str):
        if group not in orion_doc.GROUPS:
            raise HTTPException(status_code=404, detail="unknown group")
        return orion_doc.group_document(orion_summary(host), group)

    if cfg.prometheus_enabled:
        # Registered only when enabled, so a disabled endpoint is a plain 404 for everyone.
        @app.get("/metrics", dependencies=[Depends(require_scope("read:metrics"))])
        def metrics():
            now = time.time()
            names = sorted({a["host"] for a in store.agents()} | {r["host"] for r in store.sources()})
            body = prom.render([build_host_summary(store, n, now, **summary_opts) for n in names])
            return Response(content=body, media_type=prom.CONTENT_TYPE)

    return app
