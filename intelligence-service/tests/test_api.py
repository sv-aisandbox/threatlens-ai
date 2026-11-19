import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.config import pg_conninfo
from ingestion.nvd_client import NvdClient
from tests.helpers import FakeClock, load, nvd_transport

TOKEN = "t" * 32
H = {"X-Internal-Token": TOKEN}


@pytest.fixture()
def api(graph, pg_schema):
    clock = FakeClock()

    def nvd_client():
        return NvdClient(None, httpx.Client(transport=nvd_transport({0: load("nvd/cve-2021-44228.json")})), clock.sleep, clock.monotonic)

    app = create_app(
        token=TOKEN,
        driver_factory=lambda: type("D", (), {"session": graph.session, "close": lambda self: None})(),
        conn_factory=lambda: psycopg.connect(pg_conninfo(), options=f"-c search_path={pg_schema}"),
        nvd_client_factory=nvd_client,
        kev_fetch=lambda: load("kev/kev-sample.json"),
    )
    return TestClient(app)


def test_refuses_to_start_without_a_strong_token(monkeypatch):
    monkeypatch.delenv("INTERNAL_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        create_app()
    with pytest.raises(RuntimeError):
        create_app(token="short")


@pytest.mark.parametrize(
    "method,path",
    [("post", "/internal/sync/nvd"), ("post", "/internal/sync/kev"), ("post", "/internal/vulnerabilities/import"), ("get", "/internal/sync/status")],
)
def test_all_endpoints_require_the_token(api, method, path):
    assert getattr(api, method)(path).status_code == 401
    assert getattr(api, method)(path, headers={"X-Internal-Token": "wrong" * 8}).status_code == 401


def test_kev_sync_and_status(api):
    r = api.post("/internal/sync/kev", headers=H)
    assert r.status_code == 200
    assert (r.json()["status"], r.json()["records_created"], r.json()["records_rejected"]) == ("partial", 4, 1)
    status = api.get("/internal/sync/status", headers=H).json()
    assert status[0]["source_id"] == "cisa_kev" and status[0]["last_status"] == "partial"


def test_import_cve_validates_input(api):
    assert api.post("/internal/vulnerabilities/import", headers=H, json={"cve_id": "CVE-2021-44228"}).json()["records_created"] == 1
    assert api.post("/internal/vulnerabilities/import", headers=H, json={"cve_id": "../etc/passwd"}).status_code == 422
    assert api.post("/internal/vulnerabilities/import", headers=H, json={}).status_code == 422
