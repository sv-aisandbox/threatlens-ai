import pytest

from app.config import get_driver
from ingestion import seed_loader


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
