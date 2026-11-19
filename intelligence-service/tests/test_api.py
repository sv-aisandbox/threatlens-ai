import json
import time
from datetime import UTC, datetime

import httpx
import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.config import pg_conninfo
from app.service_auth import MAX_LIFETIME_SECONDS
from ingestion import sync
from ingestion.inventory_import import import_inventory
from ingestion.nvd_client import NvdClient
from tests.helpers import FIXTURES, SECRET, FakeClock, bearer, load, mint, nvd_transport

CVE = "CVE-2021-44228"
NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
ANALYST = bearer(mint(roles=["SECURITY_ANALYST"]))
VIEWER = bearer(mint(roles=["VIEWER"]))
ADMIN = bearer(mint(roles=["ADMIN"]))


class _NoCloseDriver:
    """Lets the app 'close' the shared session-scoped test driver without actually closing it."""

    def __init__(self, driver):
        self._d = driver

    def session(self, *a, **k):
        return self._d.session(*a, **k)

    def close(self):
        pass


def nvd_client():
    clock = FakeClock()
    transport = nvd_transport({0: load("nvd/cve-2021-44228.json")})
    return NvdClient(None, httpx.Client(transport=transport), clock.sleep, clock.monotonic)


@pytest.fixture()
def env(graph, pg_schema):
    def conn_factory():
        return psycopg.connect(pg_conninfo(), options=f"-c search_path={pg_schema}")

    app = create_app(
        jwt_secret=SECRET,
        driver_factory=lambda: _NoCloseDriver(graph),
        conn_factory=conn_factory,
        nvd_client_factory=nvd_client,
        kev_fetch=lambda: load("kev/kev-sample.json"),
    )
    return TestClient(app), graph, conn_factory


@pytest.fixture()
def world(env):
    client, graph, conn_factory = env
    with conn_factory() as conn:
        sync.import_single_cve(graph, conn, nvd_client(), CVE, now=lambda: NOW)
        for name, tenant in (("inventory-demo", "TENANT-DEMO"), ("inventory-other", "TENANT-OTHER")):
            data = (FIXTURES.parent / "seed" / f"{name}.json").read_bytes()
            import_inventory(graph, conn, tenant, data, "json", f"{name}.json", now=NOW)
        other = {"assets": [{"asset_id": "ASSET-O09", "name": "other-log", "asset_type": "server",
                             "environment": "staging", "criticality": "critical", "internet_exposed": True,
                             "software": [{"vendor": "Apache", "product": "Log4j", "version": "2.14.1",
                                           "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}]}]}
        import_inventory(graph, conn, "TENANT-OTHER", json.dumps(other), "json", "o.json", now=NOW)
    from correlation.match_service import run_matching

    run_matching(graph, now=lambda: NOW)
    return client


URL = f"/internal/v1/vulnerabilities/{CVE}/affected-assets"


# ---- startup ---------------------------------------------------------------------------------
@pytest.mark.parametrize("secret", [None, "", "too-short", "x" * 31])
def test_refuses_to_start_without_a_strong_secret(monkeypatch, secret):
    monkeypatch.delenv("INTERNAL_JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        create_app(jwt_secret=secret)


# ---- authentication --------------------------------------------------------------------------
PROTECTED = [("get", URL), ("get", f"/internal/v1/vulnerabilities/{CVE}"), ("get", "/internal/v1/sources/status"),
             ("post", "/internal/v1/sources/kev/sync"), ("post", "/internal/v1/vulnerabilities/import")]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_no_token_is_401(env, method, path):
    r = getattr(env[0], method)(path)
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    assert r.json() == {"detail": "unauthorized"}


def good(**kw):
    return bearer(mint(roles=["ADMIN"], **kw))


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer not.a.jwt"},
        good(sub="x") | {"Authorization": "Bearer " + mint(secret="another-secret-" + "y" * 32, roles=["ADMIN"])},
        bearer(mint(roles=["ADMIN"], ttl=-120, iat_offset=-300)),                         # expired
        bearer(mint(roles=["ADMIN"], ttl=MAX_LIFETIME_SECONDS + 60)),                    # lives too long
        bearer(mint(roles=["ADMIN"], aud="someone-else")),
        bearer(mint(roles=["ADMIN"], iss="evil")),
        bearer(mint(roles=["ADMIN"], tenant=None)),                                        # no tenant claim
        bearer(mint(roles=["ADMIN"], tenant="tenant-demo")),                               # malformed tenant
        bearer(mint(roles=["ADMIN"], tenant="TENANT-DEMO' OR 1=1 //")),
        bearer(mint(roles=[])),                                                             # no role
        bearer(mint(roles=["ROOT"])),                                                       # unknown role only
        bearer(mint(roles=["ADMIN"], drop=("jti",))),
        bearer(mint(roles=["ADMIN"], drop=("sub",))),
        bearer(mint(roles=["ADMIN"], drop=("exp",))),
        bearer(mint(roles="ADMIN")),                                                        # roles must be a list
    ],
)
def test_invalid_tokens_are_401(env, headers):
    assert env[0].get("/internal/v1/sources/status", headers=headers).status_code == 401


def test_alg_none_and_other_algorithms_are_rejected(env):
    client = env[0]
    claims = {"iss": "threatlens-backend", "aud": "threatlens-intelligence", "sub": "u", "tenant_id": "TENANT-DEMO",
              "roles": ["ADMIN"], "jti": "1", "iat": int(time.time()), "exp": int(time.time()) + 60}
    unsigned = jwt.encode(claims, key="", algorithm="none")
    assert client.get("/internal/v1/sources/status", headers=bearer(unsigned)).status_code == 401
    hs512 = jwt.encode(claims, SECRET, algorithm="HS512")
    assert client.get("/internal/v1/sources/status", headers=bearer(hs512)).status_code == 401


# ---- authorization ---------------------------------------------------------------------------
def test_viewer_and_analyst_cannot_start_syncs_or_imports(env):
    client = env[0]
    for headers in (VIEWER, ANALYST):
        assert client.post("/internal/v1/sources/kev/sync", headers=headers).status_code == 403
        assert client.post("/internal/v1/sources/nvd/sync", headers=headers).status_code == 403
        assert client.post("/internal/v1/vulnerabilities/import", headers=headers, json={"cve_id": CVE}).status_code == 403


def test_every_role_can_read(world):
    for headers in (VIEWER, ANALYST, ADMIN):
        assert world.get(f"/internal/v1/vulnerabilities/{CVE}", headers=headers).status_code == 200
        assert world.get(URL, headers=headers).status_code == 200
        assert world.get("/internal/v1/sources/status", headers=headers).status_code == 200


# ---- tenant isolation: tenant from the token only ---------------------------------------------
def ids(response):
    return {r["asset_id"] for r in response.json()["results"]}


def test_each_tenant_sees_only_its_own_assets(world):
    demo = world.get(URL + "?status=confirmed&status=possible&status=unknown", headers=bearer(mint(tenant="TENANT-DEMO", roles=["VIEWER"])))
    other = world.get(URL, headers=bearer(mint(tenant="TENANT-OTHER", roles=["VIEWER"])))
    assert demo.json()["tenant_id"] == "TENANT-DEMO" and other.json()["tenant_id"] == "TENANT-OTHER"
    assert ids(demo) == {"ASSET-013", "ASSET-015", "ASSET-016"}
    assert ids(other) == {"ASSET-O05", "ASSET-O09"}  # O05 from the seed, O09 added by the fixture
    assert not ids(demo) & ids(other)


@pytest.mark.parametrize(
    "extra_query,extra_headers",
    [("&tenant_id=TENANT-OTHER", {}), ("&tenantId=TENANT-OTHER", {}), ("", {"X-Tenant-Id": "TENANT-OTHER"}),
     ("&tenant=TENANT-OTHER", {"X-Tenant": "TENANT-OTHER", "X-Forwarded-Tenant": "TENANT-OTHER"})],
)
def test_tenant_hints_in_the_request_are_ignored(world, extra_query, extra_headers):
    headers = bearer(mint(tenant="TENANT-DEMO", roles=["VIEWER"]), **extra_headers)
    r = world.get(URL + "?environment=production" + extra_query, headers=headers)
    assert r.status_code == 200 and r.json()["tenant_id"] == "TENANT-DEMO"
    assert "ASSET-O09" not in ids(r) and ids(r)


def test_environment_filter_and_validation(world):
    prod = world.get(URL + "?environment=production", headers=ANALYST)
    assert ids(prod) == {"ASSET-013", "ASSET-015", "ASSET-016"}  # all demo log4j assets are production
    assert world.get(URL + "?environment=staging", headers=ANALYST).json()["results"] == []
    other = world.get(URL + "?environment=staging", headers=bearer(mint(tenant="TENANT-OTHER", roles=["VIEWER"])))
    assert ids(other) == {"ASSET-O09"}
    assert world.get(URL + "?environment=moon", headers=ANALYST).status_code == 422
    assert world.get(URL + "?status=maybe", headers=ANALYST).status_code == 422


def test_results_contain_status_reason_evidence_and_both_freshness_timestamps(world):
    body = world.get(URL + "?status=confirmed&status=not_affected&status=possible&status=unknown", headers=ANALYST).json()
    rows = {r["asset_id"]: r for r in body["results"]}
    assert rows["ASSET-013"]["match_status"] == "confirmed" and rows["ASSET-013"]["match_reason"]
    assert rows["ASSET-014"]["match_status"] == "not_affected"
    assert rows["ASSET-013"]["evidence"]
    assert set(body["freshness"]) == {"intelligence", "inventory_last_imported_at"}
    assert isinstance(body["warnings"], list)


@pytest.mark.parametrize("bad", ["CVE-1", "cve-2021-44228", "CVE-2021-44228%27%20OR%201%3D1", "..%2Fetc", "CVE-2021-44228x"])
def test_invalid_cve_ids_are_rejected(world, bad):
    assert world.get(f"/internal/v1/vulnerabilities/{bad}", headers=ANALYST).status_code in (404, 422)
    assert world.get(f"/internal/v1/vulnerabilities/{bad}/affected-assets", headers=ANALYST).status_code in (404, 422)


# ---- vulnerability details -------------------------------------------------------------------
def test_vulnerability_details(world):
    r = world.get(f"/internal/v1/vulnerabilities/{CVE}", headers=VIEWER)
    body = r.json()
    assert r.status_code == 200 and body["cve_id"] == CVE and body["cvss_score"] == 10.0
    assert body["evidence"] and body["kev_listed"] is False and body["synthetic"] is False
    assert "configurations_json" not in body  # large internal data is not exposed
    assert world.get("/internal/v1/vulnerabilities/CVE-2099-9999", headers=VIEWER).status_code == 404


# ---- sources: status and background sync -------------------------------------------------------
def test_admin_sync_returns_202_and_updates_status(env):
    client = env[0]
    r = client.post("/internal/v1/sources/kev/sync", headers=ADMIN)
    assert r.status_code == 202 and r.json() == {"accepted": True, "source_id": "kev"}
    status = {s["source_id"]: s for s in client.get("/internal/v1/sources/status", headers=VIEWER).json()}
    assert status["cisa_kev"]["last_status"] == "partial" and status["cisa_kev"]["records_created"] == 4


def test_second_sync_while_running_is_409_and_unknown_source_is_422(env):
    client = env[0]
    lock = client.app.state.locks["kev"]
    assert lock.acquire(blocking=False)
    try:
        assert client.post("/internal/v1/sources/kev/sync", headers=ADMIN).status_code == 409
    finally:
        lock.release()
    assert client.post("/internal/v1/sources/other/sync", headers=ADMIN).status_code == 422


def test_import_cve_validates_input(env):
    client = env[0]
    assert client.post("/internal/v1/vulnerabilities/import", headers=ADMIN, json={"cve_id": CVE}).json()["records_created"] == 1
    for bad in ({"cve_id": "../etc/passwd"}, {"cve_id": "CVE-1"}, {}):
        assert client.post("/internal/v1/vulnerabilities/import", headers=ADMIN, json=bad).status_code == 422


# ---- correlation id ----------------------------------------------------------------------------
def test_correlation_id_is_echoed_or_replaced(env):
    client = env[0]
    ok = client.get("/internal/v1/sources/status", headers=bearer(mint(), **{"X-Correlation-Id": "abcd1234-ef56"}))
    assert ok.headers["x-correlation-id"] == "abcd1234-ef56"
    bad = client.get("/internal/v1/sources/status", headers=bearer(mint(), **{"X-Correlation-Id": "x\r\ny"}))
    assert bad.headers["x-correlation-id"] not in ("x\r\ny", "") and len(bad.headers["x-correlation-id"]) == 36
    denied = client.get("/internal/v1/sources/status", headers={"X-Correlation-Id": "abcd1234-ef56"})
    assert denied.status_code == 401 and denied.headers["x-correlation-id"] == "abcd1234-ef56"


def test_docs_and_openapi_are_not_exposed(env):
    client = env[0]
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code in (404, 401)
