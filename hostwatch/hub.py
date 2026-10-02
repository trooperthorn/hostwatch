"""Hub: receives agent batches and serves read endpoints.

Every route except health goes through one authenticate dependency and a scope
check, and every authenticated request and every authentication failure is
appended to the audit log. Credentials are tried in this order: a session
cookie, a scoped bearer API key, an mTLS identity (a hook that is not wired to a
TLS listener yet), and the legacy shared ingest token, which is accepted for the
ingest scope only and is deprecated. Login endpoints, TLS serving and the Home
Assistant and Orion endpoints arrive in later slices, so keep the hub on
loopback until then.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import __version__
from .config import Config
from .schema import Batch
from .store import Store

log = logging.getLogger("hostwatch.hub")

SESSION_COOKIE = "hostwatch_session"
# A browser session may read but never ingest. Admin satisfies every scope except ingest.
SESSION_SCOPES = frozenset({"read:metrics", "read:events"})


@dataclass
class Principal:
    actor: str
    kind: str  # session, api_key, mtls or legacy_token
    scopes: frozenset
    detail: dict = field(default_factory=dict)

    def allows(self, scope: str) -> bool:
        return scope in self.scopes or ("admin" in self.scopes and scope != "ingest")


def _no_mtls(request: Request):
    return None


def create_app(cfg: Config, store: Store, on_start=None, on_stop=None,
               mtls_identity: Callable[[Request], Principal | None] = _no_mtls) -> FastAPI:
    async def maintenance_loop():
        while True:
            await asyncio.sleep(3600)
            try:
                await asyncio.to_thread(store.maintain, cfg.raw_retention_days, cfg.rollup_retention_days)
            except Exception as exc:
                log.warning("maintenance failed: %s", exc)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(maintenance_loop())
        if on_start:
            on_start()
        yield
        if on_stop:
            on_stop()
        task.cancel()

    app = FastAPI(title="hostwatch hub", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # The default handler echoes the rejected input, which cannot be encoded
        # to JSON when it is NaN or infinity and would turn a 422 into a 500.
        errors = [{"loc": list(e.get("loc", ())), "msg": str(e.get("msg", "")), "type": e.get("type", "")}
                  for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": errors})

    def _resolve(request: Request) -> Principal | None:
        cookie = request.cookies.get(SESSION_COOKIE)
        if cookie:
            sess = store.get_session(cookie)
            if sess:
                return Principal(sess["username"], "session", SESSION_SCOPES)
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() == "bearer" and token:
            if token.startswith("hw_"):
                key = store.find_api_key(token)
                if key:
                    return Principal(f"key:{key['prefix']}", "api_key", frozenset(key["scopes"]),
                                     {"owner": key["owner"]})
            else:
                if cfg.ingest_token and hmac.compare_digest(token.encode(), cfg.ingest_token.encode()):
                    return Principal("legacy-token", "legacy_token", frozenset({"ingest"}),
                                     {"deprecated": "shared ingest token, replace with a scoped key"})
        return mtls_identity(request)

    def authenticate(request: Request) -> Principal:
        principal = _resolve(request)
        if principal is None:
            request.state.auth_reason = "invalid or missing credentials"
            raise HTTPException(status_code=401, detail="authentication required")
        request.state.principal = principal
        return principal

    def require_scope(scope: str):
        def check(request: Request, principal: Principal = Depends(authenticate)) -> Principal:
            if not principal.allows(scope):
                request.state.auth_reason = f"missing scope {scope}"
                raise HTTPException(status_code=403, detail="insufficient scope")
            return principal
        return check

    @app.middleware("http")
    async def audit(request: Request, call_next):
        response = await call_next(request)
        if request.url.path == "/internal/v1/health":
            return response
        principal = getattr(request.state, "principal", None)
        if principal is None and response.status_code != 401:
            return response
        detail = dict(principal.detail) if principal else {}
        reason = getattr(request.state, "auth_reason", None)
        if reason:
            detail["reason"] = reason
        kind = "auth_failure" if response.status_code in (401, 403) else "access"
        if principal:
            detail["credential"] = principal.kind
        remote = request.client.host if request.client else "unknown"
        try:
            await asyncio.to_thread(store.append_audit, principal.actor if principal else "anonymous", kind,
                                    request.method, request.url.path, response.status_code, remote, detail)
        except Exception as exc:
            log.error("audit write failed: %s", exc)
            return JSONResponse(status_code=500, content={"detail": "audit unavailable"})
        return response

    @app.get("/internal/v1/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.post("/internal/v1/ingest", dependencies=[Depends(require_scope("ingest"))])
    def ingest(batch: Batch):
        n, e, duplicate = store.ingest_batch(batch)
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
        found = store.gaps(host, source, metric, time.time() - hours * 3600, max_gap_s)
        return {"gap_count": len(found), "gaps": found}

    return app
