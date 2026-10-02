"""Hub: receives agent batches and serves read endpoints.

Phase 1 scope: an internal API protected by a single shared bearer token
(HOSTWATCH_INGEST_TOKEN), bound to loopback by default. User login, scoped API
keys, TLS, and the Home Assistant and Orion endpoints arrive in Phases 3 and 4.
Do not expose this port beyond the host until then.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import __version__
from .config import Config
from .schema import Batch
from .store import Store

log = logging.getLogger("hostwatch.hub")


def create_app(cfg: Config, store: Store, on_start=None, on_stop=None) -> FastAPI:
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

    def require_token(authorization: str = Header(default="")) -> None:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(token, cfg.ingest_token):
            raise HTTPException(status_code=401, detail="invalid token")

    @app.get("/internal/v1/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.post("/internal/v1/ingest", dependencies=[Depends(require_token)])
    def ingest(batch: Batch):
        n, e, duplicate = store.ingest_batch(batch)
        out = {"stored": n, "events_stored": e}
        if duplicate:
            out["duplicate"] = True
        return out

    @app.get("/internal/v1/latest", dependencies=[Depends(require_token)])
    def latest(host: str | None = None):
        return store.latest(host)

    @app.get("/internal/v1/sources", dependencies=[Depends(require_token)])
    def sources():
        return {"agents": store.agents(), "sources": store.sources()}

    @app.get("/internal/v1/events", dependencies=[Depends(require_token)])
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

    @app.get("/internal/v1/gaps", dependencies=[Depends(require_token)])
    def gaps(host: str, source: str, metric: str, hours: float = 24, max_gap_s: float = 60):
        import time
        found = store.gaps(host, source, metric, time.time() - hours * 3600, max_gap_s)
        return {"gap_count": len(found), "gaps": found}

    return app
