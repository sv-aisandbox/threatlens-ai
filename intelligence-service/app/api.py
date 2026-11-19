"""Internal API for the Spring Boot backend (ADR 0004). Never expose this service publicly.

Run:  uv run uvicorn app.api:create_app --factory --host 127.0.0.1 --port 8000
Every route requires a short-lived service JWT. The tenant and roles come from that token only;
no route accepts a tenant parameter, and ignored query/header tenant hints cannot widen access.
"""

import asyncio
import logging
import os
import re
import threading
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any, Literal

import psycopg
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Path, Query, Request
from neo4j import Driver
from pydantic import BaseModel, ConfigDict, Field

from app.config import get_driver, nvd_api_key, pg_conninfo
from agent.agent import AnalystAgent, AnalystUnavailable, Caller, QuestionError
from agent.factory import build_agent
from agent.models import ModelError
from app.service_auth import AuthError, Principal, validate_secret, verify_service_token
from graph_queries.affected_assets import DEFAULT_STATUSES, get_affected_assets_with_freshness
from graph_queries.vulnerability import get_vulnerability
from ingestion import source_sync, sync
from ingestion.nvd_client import NvdClient
from normalization.nvd import CVE_ID_RE

logger = logging.getLogger("threatlens.api")

CORRELATION_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
ALL_ROLES = ("ADMIN", "SECURITY_ANALYST", "VIEWER")
Environment = Literal["production", "staging", "development"]
MatchStatus = Literal["confirmed", "possible", "not_affected", "unknown"]
CveId = Annotated[str, Path(pattern=CVE_ID_RE.pattern, max_length=40)]


class NvdSyncRequest(BaseModel):
    since: datetime | None = None
    until: datetime | None = None


class AskRequest(BaseModel):
    """Only the question. Any other field (a tenant, a role, a tool list) is rejected, not ignored."""

    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=2000)


MAX_CONCURRENT_ASKS = 4


class ImportCveRequest(BaseModel):
    cve_id: str = Field(pattern=CVE_ID_RE.pattern, max_length=40)


def create_app(
    jwt_secret: str | None = None,
    driver_factory: Callable[[], Driver] = get_driver,
    conn_factory: Callable[[], psycopg.Connection] | None = None,
    nvd_client_factory: Callable[[], NvdClient] | None = None,
    kev_fetch: Callable[[], Any] | None = None,
    analyst_factory: Callable[[], AnalystAgent] | None = None,
) -> FastAPI:
    if not logging.getLogger().handlers:  # visible request logs (with correlation ids) when run by uvicorn
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    secret = validate_secret(jwt_secret if jwt_secret is not None else os.environ.get("INTERNAL_JWT_SECRET"))
    conn_factory = conn_factory or (lambda: psycopg.connect(pg_conninfo()))
    key = nvd_api_key()
    nvd_client_factory = nvd_client_factory or (lambda: NvdClient(key))

    holder: dict[str, Driver] = {}
    holder_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if "driver" in holder:
            holder.pop("driver").close()

    app = FastAPI(title="ThreatLens intelligence service (internal)", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.locks = {"nvd": threading.Lock(), "kev": threading.Lock(), "cve": threading.Lock()}

    def graph() -> Driver:
        with holder_lock:
            if "driver" not in holder:
                holder["driver"] = driver_factory()
            return holder["driver"]

    @app.middleware("http")
    async def correlation(request: Request, call_next):
        cid = request.headers.get("x-correlation-id", "")
        if not CORRELATION_RE.fullmatch(cid):
            cid = str(uuid.uuid4())
        request.state.correlation_id = cid
        response = await call_next(request)
        response.headers["X-Correlation-Id"] = cid
        logger.info("%s %s -> %s cid=%s", request.method, request.url.path, response.status_code, cid)
        return response

    def auth(*roles: str):
        def dependency(request: Request) -> Principal:
            cid = getattr(request.state, "correlation_id", "-")
            header = request.headers.get("authorization", "")
            scheme, _, token = header.partition(" ")
            if scheme.lower() != "bearer" or not token:
                logger.warning("auth failed: no bearer token cid=%s", cid)
                raise HTTPException(status_code=401, detail="unauthorized", headers={"WWW-Authenticate": "Bearer"})
            try:
                principal = verify_service_token(token.strip(), secret)
            except AuthError as exc:
                logger.warning("auth failed: %s cid=%s", exc, cid)
                raise HTTPException(status_code=401, detail="unauthorized", headers={"WWW-Authenticate": "Bearer"}) from None
            if not principal.has_any(*roles):
                logger.warning("forbidden: role check failed cid=%s", cid)
                raise HTTPException(status_code=403, detail="forbidden")
            return principal

        return dependency

    anyone = Depends(auth(*ALL_ROLES))
    admin = Depends(auth("ADMIN"))

    @app.get("/internal/v1/vulnerabilities/{cve_id}")
    def vulnerability(cve_id: CveId, _: Principal = anyone) -> dict[str, Any]:
        found = get_vulnerability(graph(), cve_id)
        if found is None:
            raise HTTPException(status_code=404, detail="not found")
        return found

    @app.get("/internal/v1/vulnerabilities/{cve_id}/affected-assets")
    def affected_assets(
        cve_id: CveId,
        environment: Environment | None = None,
        status: Annotated[list[MatchStatus] | None, Query()] = None,
        principal: Principal = anyone,
    ) -> dict[str, Any]:
        with conn_factory() as conn:
            out = get_affected_assets_with_freshness(
                graph(), conn, principal.tenant_id, cve_id,
                statuses=status or DEFAULT_STATUSES, environment=environment,
            )
        return {"cve_id": cve_id, "tenant_id": principal.tenant_id, **out}

    @app.get("/internal/v1/sources/status")
    def sources_status(_: Principal = anyone) -> list[dict[str, Any]]:
        with conn_factory() as conn:
            rows = source_sync.list_status(conn)
        return [{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in row.items()} for row in rows]

    @app.post("/internal/v1/sources/{source_id}/sync", status_code=202)
    def start_sync(
        source_id: Literal["nvd", "kev"],
        background: BackgroundTasks,
        body: NvdSyncRequest | None = None,
        principal: Principal = admin,
    ) -> dict[str, Any]:
        lock = app.state.locks[source_id]
        if not lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="a sync for this source is already running")
        window = body or NvdSyncRequest()

        def job() -> None:
            try:
                with conn_factory() as conn:
                    if source_id == "nvd":
                        result = sync.run_nvd_sync(
                            graph(), conn, nvd_client_factory(), since=window.since, until=window.until, api_key=key
                        )
                    else:
                        result = sync.run_kev_sync(graph(), conn, kev_fetch or sync.fetch_kev_feed)
                logger.info("sync %s finished: %s (requested by %s)", source_id, result.status, principal.subject)
            except Exception:  # noqa: BLE001 - run_* already recorded operational failures
                logger.exception("sync %s crashed", source_id)
            finally:
                lock.release()

        background.add_task(job)
        return {"accepted": True, "source_id": source_id}

    analyst_lock = threading.Lock()
    analyst_cache: dict[str, AnalystAgent] = {}
    app.state.ask_slots = threading.BoundedSemaphore(MAX_CONCURRENT_ASKS)

    def analyst() -> AnalystAgent:
        with analyst_lock:
            if "agent" not in analyst_cache:
                analyst_cache["agent"] = (analyst_factory or (lambda: build_agent(graph(), conn_factory)))()
            return analyst_cache["agent"]

    @app.post("/internal/v1/analyst/ask")
    def ask(body: AskRequest, request: Request, principal: Principal = Depends(auth("ADMIN", "SECURITY_ANALYST"))) -> dict[str, Any]:
        cid = request.state.correlation_id
        if not app.state.ask_slots.acquire(blocking=False):
            raise HTTPException(status_code=429, detail="the analyst is busy; retry shortly")
        try:
            try:
                agent = analyst()
            except ModelError as exc:
                logger.error("analyst not configured: %s cid=%s", exc.code, cid)
                raise HTTPException(status_code=503, detail="analyst_unavailable") from None
            caller = Caller(subject=principal.subject, tenant_id=principal.tenant_id, roles=principal.roles, correlation_id=cid)
            try:
                return asyncio.run(agent.ask(body.question, caller))
            except QuestionError:
                raise HTTPException(status_code=422, detail="invalid question") from None
            except AnalystUnavailable as exc:
                logger.error("analyst unavailable: %s cid=%s", exc.code, cid)
                raise HTTPException(status_code=503, detail="analyst_unavailable") from None
        finally:
            app.state.ask_slots.release()

    @app.post("/internal/v1/vulnerabilities/import")
    def import_cve(body: ImportCveRequest, _: Principal = admin) -> dict[str, Any]:
        lock = app.state.locks["cve"]
        if not lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="an import is already running")
        try:
            with conn_factory() as conn:
                return sync.import_single_cve(graph(), conn, nvd_client_factory(), body.cve_id, api_key=key).as_dict()
        finally:
            lock.release()

    return app
