"""Shared world for the security suite: one seeded graph with the real log4j CVE, two tenants, in disposable stores.

Run from intelligence-service:  uv run pytest ../tests/security -c pyproject.toml --rootdir .
"""

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient

from agent.agent import AgentConfig, AnalystAgent
from agent.mock_adapter import MockAdapter
from agent.usage_log import PostgresUsageLog
from app.api import create_app
from app.config import pg_conninfo
from correlation.match_service import run_matching
from ingestion import seed_loader, source_sync, sync
from ingestion.nvd_client import NvdClient
from mcp_tools.audit import PostgresToolAudit
from tests.conftest import MIGRATIONS, test_driver  # noqa: F401 - re-exported fixture
from tests.helpers import SECRET, FakeClock, load, nvd_transport

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
CVE = "CVE-2021-44228"


class _NoCloseDriver:
    def __init__(self, driver):
        self._d = driver

    def session(self, *a, **k):
        return self._d.session(*a, **k)

    def close(self):
        pass


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
def world(test_driver):  # noqa: F811
    schema = f"sec_{uuid.uuid4().hex[:10]}"
    admin = psycopg.connect(pg_conninfo(), autocommit=True)
    admin.execute(f'CREATE SCHEMA "{schema}"')
    options = f"-c search_path={schema}"

    def connect():
        return psycopg.connect(pg_conninfo(), options=options)

    with connect() as setup:
        for migration in MIGRATIONS:
            setup.execute(migration.read_text())
    with test_driver.session() as s:
        s.run("MATCH (n) DETACH DELETE n").consume()
    seed_loader.apply_schema(test_driver)
    seed_loader.load_seed(test_driver)
    clock = FakeClock()
    nvd = NvdClient(None, httpx.Client(transport=nvd_transport({0: load("nvd/cve-2021-44228.json")})), clock.sleep, clock.monotonic)
    with connect() as conn:
        sync.import_single_cve(test_driver, conn, nvd, CVE, now=lambda: NOW)
        sync.run_kev_sync(test_driver, conn, lambda: load("kev/kev-sample.json"), now=lambda: NOW)
        source_sync.record_result(conn, source_sync.SyncResult(source_id="nvd", attempted_at=NOW))
    run_matching(test_driver, now=lambda: NOW)

    agent = AnalystAgent(MockAdapter(), test_driver, connect, PostgresToolAudit(connect), PostgresUsageLog(connect), AgentConfig())
    app = create_app(
        jwt_secret=SECRET,
        driver_factory=lambda: _NoCloseDriver(test_driver),
        conn_factory=connect,
        analyst_factory=lambda: agent,
    )
    yield SimpleNamespace(driver=test_driver, connect=connect, client=TestClient(app), schema=schema)
    admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
    admin.close()
