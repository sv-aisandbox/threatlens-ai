import uuid

import psycopg
import pytest

from app.config import get_driver, get_test_driver, pg_conninfo
from ingestion import seed_loader

MIGRATION = seed_loader.REPO_ROOT / "database" / "migrations" / "V1__source_sync.sql"


# --- development Memgraph: only used by the synthetic-seed tests (they touch synthetic=true nodes only) ---


@pytest.fixture(scope="session")
def driver():
    drv = get_driver()
    try:
        drv.verify_connectivity()
    except Exception as exc:  # pragma: no cover - environment problem
        pytest.fail(f"Memgraph not reachable; run `docker compose up -d --wait` ({exc})")
    yield drv
    drv.close()


@pytest.fixture()
def seeded(driver):
    """Fresh synthetic seed for every test (only touches nodes with synthetic=true)."""
    seed_loader.apply_schema(driver)
    seed_loader.reset_seed(driver)
    seed_loader.load_seed(driver)
    return driver


# --- ingestion tests: disposable Memgraph (port 7688) and an isolated Postgres schema ---


@pytest.fixture(scope="session")
def test_driver():
    drv = get_test_driver()
    try:
        drv.verify_connectivity()
    except Exception as exc:  # pragma: no cover - environment problem
        pytest.fail(
            "Test Memgraph not reachable; run `docker compose --profile test up -d --wait memgraph-test` "
            f"({type(exc).__name__})"
        )
    yield drv
    drv.close()


@pytest.fixture()
def graph(test_driver):
    """Empty test graph with the schema applied. Safe to wipe: it is a dedicated instance."""
    with test_driver.session() as s:
        s.run("MATCH (n) DETACH DELETE n").consume()
    seed_loader.apply_schema(test_driver)
    return test_driver


@pytest.fixture()
def pg_schema():
    """Name of a throwaway schema containing the real migration; dropped afterwards."""
    schema = f"test_{uuid.uuid4().hex[:12]}"
    try:
        admin = psycopg.connect(pg_conninfo(), autocommit=True)
    except Exception as exc:  # pragma: no cover - environment problem
        pytest.fail(f"PostgreSQL not reachable; run `docker compose up -d --wait` ({type(exc).__name__})")
    admin.execute(f'CREATE SCHEMA "{schema}"')
    with psycopg.connect(pg_conninfo(), options=f"-c search_path={schema}") as setup:
        setup.execute(MIGRATION.read_text())
    yield schema
    admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
    admin.close()


@pytest.fixture()
def pg(pg_schema):
    conn = psycopg.connect(pg_conninfo(), options=f"-c search_path={pg_schema}")
    yield conn
    conn.close()
