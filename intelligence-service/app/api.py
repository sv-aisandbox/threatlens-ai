"""Internal-only sync API. Bind to 127.0.0.1 or the private Docker network; never publish it.

Run:  uv run uvicorn app.api:create_app --factory --host 127.0.0.1 --port 8000
Authentication here is a static internal token (fail closed). Module 06 replaces it with the
short-lived service JWT described in roadmap gap G6.
"""

import hmac
import os
import threading
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException
from neo4j import Driver
from pydantic import BaseModel, Field

from app.config import get_driver, nvd_api_key, pg_conninfo
from ingestion import source_sync, sync
from ingestion.nvd_client import NvdClient
from normalization.nvd import CVE_ID_RE

MIN_TOKEN_LENGTH = 16


class NvdSyncRequest(BaseModel):
    since: datetime | None = None
    until: datetime | None = None


class ImportCveRequest(BaseModel):
    cve_id: str = Field(pattern=CVE_ID_RE.pattern)


def create_app(
    token: str | None = None,
    driver_factory: Callable[[], Driver] = get_driver,
    conn_factory: Callable[[], psycopg.Connection] | None = None,
    nvd_client_factory: Callable[[], NvdClient] | None = None,
    kev_fetch: Callable[[], Any] | None = None,
) -> FastAPI:
    token = token if token is not None else os.environ.get("INTERNAL_API_TOKEN", "")
    if len(token) < MIN_TOKEN_LENGTH:
        raise RuntimeError(f"INTERNAL_API_TOKEN must be set (at least {MIN_TOKEN_LENGTH} characters)")
    conn_factory = conn_factory or (lambda: psycopg.connect(pg_conninfo()))
    key = nvd_api_key()
    nvd_client_factory = nvd_client_factory or (lambda: NvdClient(key))
    locks = {"nvd": threading.Lock(), "kev": threading.Lock(), "cve": threading.Lock()}

    def require_token(x_internal_token: Annotated[str | None, Header()] = None) -> None:
        if not x_internal_token or not hmac.compare_digest(x_internal_token, token):
            raise HTTPException(status_code=401, detail="unauthorized")

    app = FastAPI(title="ThreatLens intelligence service (internal)", dependencies=[Depends(require_token)])

    def run_locked(name: str, fn: Callable[[Driver, psycopg.Connection], sync.SyncResult]) -> dict[str, Any]:
        if not locks[name].acquire(blocking=False):
            raise HTTPException(status_code=409, detail="a sync for this source is already running")
        driver = driver_factory()
        try:
            with conn_factory() as conn:
                return fn(driver, conn).as_dict()
        finally:
            driver.close()
            locks[name].release()

    @app.post("/internal/sync/nvd")
    def sync_nvd(body: NvdSyncRequest | None = None) -> dict[str, Any]:
        body = body or NvdSyncRequest()
        return run_locked(
            "nvd",
            lambda d, c: sync.run_nvd_sync(
                d, c, nvd_client_factory(), since=body.since, until=body.until, api_key=key
            ),
        )

    @app.post("/internal/sync/kev")
    def sync_kev() -> dict[str, Any]:
        return run_locked(
            "kev", lambda d, c: sync.run_kev_sync(d, c, kev_fetch or sync.fetch_kev_feed)
        )

    @app.post("/internal/vulnerabilities/import")
    def import_cve(body: ImportCveRequest) -> dict[str, Any]:
        return run_locked(
            "cve",
            lambda d, c: sync.import_single_cve(d, c, nvd_client_factory(), body.cve_id, api_key=key),
        )

    @app.get("/internal/sync/status")
    def status() -> list[dict[str, Any]]:
        with conn_factory() as conn:
            return [
                {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in row.items()}
                for row in source_sync.list_status(conn)
            ]

    return app
