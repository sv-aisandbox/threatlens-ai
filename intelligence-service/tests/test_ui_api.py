"""Overview, vulnerability search, CVE graph and inventory upload: the data the web UI needs (Module 09)."""

import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.config import pg_conninfo
from correlation.match_service import run_matching
from graph_queries.graph_view import get_vulnerability_graph
from graph_queries.overview import get_overview
from ingestion import seed_loader, source_sync, sync
from ingestion.inventory_import import get_import, list_imports
from ingestion.nvd_client import NvdClient
from tests.helpers import SECRET, FakeClock, bearer, load, mint, nvd_transport

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
CVE = "CVE-2021-44228"
ADMIN = bearer(mint(roles=["ADMIN"], sub="admin-sub"))
ANALYST = bearer(mint(roles=["SECURITY_ANALYST"], sub="analyst-sub"))
VIEWER = bearer(mint(roles=["VIEWER"], sub="viewer-sub"))
OTHER_ADMIN = bearer(mint(roles=["ADMIN"], tenant="TENANT-OTHER", sub="other-admin"))
OTHER_VIEWER = bearer(mint(roles=["VIEWER"], tenant="TENANT-OTHER", sub="other-viewer"))
HEADER = "asset_id,name,asset_type,environment,criticality,internet_exposed,vendor,product,version,cpe\n"


class _NoCloseDriver:
    def __init__(self, driver):
        self._d = driver

    def session(self, *a, **k):
        return self._d.session(*a, **k)

    def close(self):
        pass


@pytest.fixture()
def world(graph, pg_schema):
    def connect():
        return psycopg.connect(pg_conninfo(), options=f"-c search_path={pg_schema}")

    seed_loader.load_seed(graph)
    clock = FakeClock()
    client = NvdClient(None, httpx.Client(transport=nvd_transport({0: load("nvd/cve-2021-44228.json")})), clock.sleep, clock.monotonic)
    with connect() as conn:
        sync.import_single_cve(graph, conn, client, CVE, now=lambda: NOW)
        sync.run_kev_sync(graph, conn, lambda: load("kev/kev-sample.json"), now=lambda: NOW)
        source_sync.record_result(conn, source_sync.SyncResult(source_id="nvd", attempted_at=NOW))
    run_matching(graph, now=lambda: NOW)
    return graph, connect


@pytest.fixture()
def client(world):
    graph, connect = world
    return TestClient(create_app(jwt_secret=SECRET, driver_factory=lambda: _NoCloseDriver(graph), conn_factory=connect))


def csv_upload(content: str, name="inventory.csv", fmt="csv"):
    return {"filename": name, "format": fmt, "content_base64": base64.b64encode(content.encode()).decode()}


# ---- overview ----------------------------------------------------------------------------------------------------


def test_overview_counts_for_the_demo_tenant(world):
    graph, connect = world
    with connect() as conn:
        o = get_overview(graph, conn, "TENANT-DEMO")
    assert o["vulnerabilities"] == {"total": 7, "kev": 4, "critical_cvss": 2}   # 3 synthetic + log4j + 3 KEV-only entries
    assert o["assets"] == {"total": 16, "critical": 3, "affected_critical": 3}
    assert o["exposure"] == {"confirmed": 7, "possible": 1, "unknown": 2, "confirmed_cves": 4}
    assert [(e["cve_id"], e["confirmed_assets"]) for e in o["top_exposures"]] == [
        ("CVE-DEMO-0001", 3), ("CVE-DEMO-0002", 2), (CVE, 1), ("CVE-DEMO-0003", 1)]  # ties: KEV first
    assert o["top_exposures"][2]["kev_listed"] is True and o["top_exposures"][0]["synthetic"] is True


def test_overview_is_tenant_scoped_but_global_counts_are_shared(world):
    graph, connect = world
    with connect() as conn:
        mine, theirs = get_overview(graph, conn, "TENANT-DEMO"), get_overview(graph, conn, "TENANT-OTHER")
    assert theirs["assets"] == {"total": 5, "critical": 2, "affected_critical": 2}
    assert theirs["exposure"] == {"confirmed": 3, "possible": 0, "unknown": 1, "confirmed_cves": 3}
    assert theirs["vulnerabilities"] == mine["vulnerabilities"]  # public intelligence is the same for everyone
    assert {e["cve_id"] for e in theirs["top_exposures"]} <= {"CVE-DEMO-0001", "CVE-DEMO-0003", CVE}
    assert get_overview(graph, connect(), "TENANT-NOBODY")["assets"] == {"total": 0, "critical": 0, "affected_critical": 0}


def test_every_source_reports_its_age_and_staleness_and_never_looks_live_when_old(world):
    graph, connect = world
    with connect() as conn:
        fresh = get_overview(graph, conn, "TENANT-DEMO", now=datetime.now(UTC) + timedelta(hours=1))
        old = get_overview(graph, conn, "TENANT-DEMO", now=datetime.now(UTC) + timedelta(days=10))
    by_id = {s["source_id"]: s for s in fresh["sources"]}
    assert {"nvd", "cisa_kev"} <= set(by_id)
    assert all(by_id[s]["stale"] is False and by_id[s]["age_hours"] is not None for s in ("nvd", "cisa_kev"))
    assert fresh["stale_after_hours"] == 48 and fresh["inventory"]["stale"] is True  # the seed's fixed import date is old
    assert any("inventory" in w for w in fresh["warnings"]) and not any("NVD" in w for w in fresh["warnings"])
    assert all(s["stale"] for s in old["sources"]) and sum("hours ago" in w for w in old["warnings"]) >= 3


def test_a_source_that_never_synced_is_stale_with_a_clear_warning(graph, pg_schema):
    with psycopg.connect(pg_conninfo(), options=f"-c search_path={pg_schema}") as conn:
        o = get_overview(graph, conn, "TENANT-DEMO")
    assert [s["last_success_at"] for s in o["sources"]] == [None, None] and all(s["stale"] for s in o["sources"])
    assert any("never synced" in w for w in o["warnings"]) and any("No asset inventory" in w for w in o["warnings"])
    assert o["vulnerabilities"]["total"] == 0 and o["top_exposures"] == []


def test_overview_requires_a_tenant(world):
    graph, connect = world
    with pytest.raises(ValueError):
        get_overview(graph, connect(), "")


def test_overview_endpoint_uses_the_tenant_in_the_token_for_every_role(client):
    mine = client.get("/internal/v1/overview", headers=VIEWER)
    theirs = client.get("/internal/v1/overview?tenant_id=TENANT-DEMO", headers={**OTHER_VIEWER, "X-Tenant-Id": "TENANT-DEMO"})
    assert mine.status_code == theirs.status_code == 200
    assert (mine.json()["tenant_id"], theirs.json()["tenant_id"]) == ("TENANT-DEMO", "TENANT-OTHER")
    assert theirs.json()["assets"]["total"] == 5
    assert client.get("/internal/v1/overview").status_code == 401


# ---- vulnerability search ------------------------------------------------------------------------------------------


def test_search_endpoint(client):
    r = client.get("/internal/v1/vulnerabilities?query=log4j", headers=VIEWER).json()
    assert [x["cve_id"] for x in r["results"]] == [CVE] and r["truncated"] is False
    kev = client.get("/internal/v1/vulnerabilities?kev_only=true&limit=2", headers=VIEWER).json()
    assert len(kev["results"]) == 2 and kev["truncated"] is True and all(x["kev_listed"] for x in kev["results"])
    assert [x["cve_id"] for x in client.get("/internal/v1/vulnerabilities?min_cvss=9.5", headers=VIEWER).json()["results"]] == [CVE]
    assert client.get("/internal/v1/vulnerabilities", headers=VIEWER).status_code == 200  # browse without a query


@pytest.mark.parametrize("qs", ["query=a", "query=" + "x" * 101, "min_cvss=11", "min_cvss=-1", "limit=0", "limit=51", "kev_only=maybe"])
def test_search_validation(client, qs):
    assert client.get(f"/internal/v1/vulnerabilities?{qs}", headers=VIEWER).status_code == 422


def test_search_needs_authentication(client):
    assert client.get("/internal/v1/vulnerabilities?query=log4j").status_code == 401


# ---- CVE graph --------------------------------------------------------------------------------------------------------


def test_graph_connects_cve_software_and_the_tenants_assets(world):
    graph, _ = world
    g = get_vulnerability_graph(graph, "TENANT-DEMO", CVE)
    by_type = {t: {n["id"] for n in g["nodes"] if n["type"] == t} for t in ("vulnerability", "software", "asset")}
    assert by_type["vulnerability"] == {CVE} and by_type["asset"] == {"ASSET-013", "ASSET-015", "ASSET-016"}
    assert len(by_type["software"]) == 3 and g["truncated"] is False
    cve_edges = {e["source"]: e for e in g["edges"] if e["type"] == "AFFECTED_BY"}
    assert {e["match_status"] for e in cve_edges.values()} == {"confirmed", "possible", "unknown"}
    assert all(e["target"] == CVE and e["reason"] for e in cve_edges.values())
    assert sum(1 for e in g["edges"] if e["type"] == "RUNS") == 3
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"])  # no dangling edges


def test_graph_hides_not_affected_unless_asked_and_is_tenant_scoped(world):
    graph, _ = world
    base = {n["id"] for n in get_vulnerability_graph(graph, "TENANT-DEMO", CVE)["nodes"]}
    more = {n["id"] for n in get_vulnerability_graph(graph, "TENANT-DEMO", CVE, include_not_affected=True)["nodes"]}
    assert "ASSET-014" not in base and "ASSET-014" in more
    other = get_vulnerability_graph(graph, "TENANT-OTHER", CVE)
    assert {n["id"] for n in other["nodes"] if n["type"] == "asset"} == {"ASSET-O05"}
    assert not any(n["id"].startswith("ASSET-0") and n["type"] == "asset" for n in other["nodes"])


def test_graph_for_a_known_cve_without_matches_is_just_the_cve_and_unknown_cve_is_none(world):
    graph, _ = world
    stub = get_vulnerability_graph(graph, "TENANT-DEMO", "CVE-2026-59310")  # KEV-only entry: no product data
    assert [n["id"] for n in stub["nodes"]] == ["CVE-2026-59310"] and stub["edges"] == []
    assert get_vulnerability_graph(graph, "TENANT-DEMO", "CVE-2099-0001") is None
    with pytest.raises(ValueError):
        get_vulnerability_graph(graph, "TENANT-DEMO", CVE, limit=0)
    with pytest.raises(ValueError):
        get_vulnerability_graph(graph, "", CVE)


def test_graph_is_bounded(world):
    graph, _ = world
    g = get_vulnerability_graph(graph, "TENANT-DEMO", CVE, limit=1)
    assert [n for n in g["nodes"] if n["type"] == "asset"].__len__() == 1 and g["truncated"] is True


def test_graph_endpoint(client):
    r = client.get(f"/internal/v1/vulnerabilities/{CVE}/graph", headers=VIEWER)
    assert r.status_code == 200 and {n["type"] for n in r.json()["nodes"]} == {"vulnerability", "software", "asset"}
    other = client.get(f"/internal/v1/vulnerabilities/{CVE}/graph?tenant_id=TENANT-DEMO", headers=OTHER_VIEWER).json()
    assert {n["id"] for n in other["nodes"] if n["type"] == "asset"} == {"ASSET-O05"}
    assert client.get("/internal/v1/vulnerabilities/CVE-2099-0001/graph", headers=VIEWER).status_code == 404
    assert client.get("/internal/v1/vulnerabilities/not-a-cve/graph", headers=VIEWER).status_code == 422
    assert client.get(f"/internal/v1/vulnerabilities/{CVE}/graph").status_code == 401


# ---- inventory upload ------------------------------------------------------------------------------------------------


GOOD = HEADER + "ASSET-900,upload-api-01,server,production,critical,true,Apache,Log4j,2.14.1,cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*\n"
MIXED = (HEADER + GOOD.splitlines()[1] + "\n"
         "ASSET-901,bad-01,mainframe,production,low,false,,,,\n"
         "bad id,x,server,production,low,false,,,,\n")


def test_admin_uploads_an_inventory_and_it_is_matched_immediately(client):
    r = client.post("/internal/v1/inventory/import", headers=ADMIN, json=csv_upload(GOOD))
    assert r.status_code == 200
    body = r.json()
    assert (body["rows_received"], body["rows_accepted"], body["rows_rejected"], body["assets_imported"]) == (1, 1, 0, 1)
    assert body["tenant_id"] == "TENANT-DEMO" and body["format"] == "csv" and body["matching"]["created"] >= 0
    affected = client.get(f"/internal/v1/vulnerabilities/{CVE}/affected-assets", headers=VIEWER).json()
    assert "ASSET-900" in {r["asset_id"] for r in affected["results"]}  # imported, matched, and confirmed for this CVE


def test_rejected_rows_are_reported_without_cell_values_and_only_good_rows_are_imported(client):
    body = client.post("/internal/v1/inventory/import", headers=ADMIN, json=csv_upload(MIXED)).json()
    assert (body["rows_accepted"], body["rows_rejected"]) == (1, 2)
    assert {r["ref"] for r in body["rejects"]} == {"row 3", "row 4"}
    assert "mainframe" not in json.dumps(body["rejects"])
    after = client.get(f"/internal/v1/vulnerabilities/{CVE}/affected-assets", headers=VIEWER).json()
    assert "ASSET-901" not in {r["asset_id"] for r in after["results"]}


def test_only_admins_may_upload(client):
    for headers in (ANALYST, VIEWER):
        assert client.post("/internal/v1/inventory/import", headers=headers, json=csv_upload(GOOD)).status_code == 403
    assert client.post("/internal/v1/inventory/import", json=csv_upload(GOOD)).status_code == 401


def test_the_tenant_comes_from_the_token_and_body_hints_are_rejected(client):
    r = client.post("/internal/v1/inventory/import", headers=OTHER_ADMIN, json=csv_upload(GOOD.replace("ASSET-900", "ASSET-O90")))
    assert r.status_code == 200 and r.json()["tenant_id"] == "TENANT-OTHER"
    assert client.post("/internal/v1/inventory/import", headers=ADMIN, json={**csv_upload(GOOD), "tenant_id": "TENANT-OTHER"}).status_code == 422
    mine = client.get(f"/internal/v1/vulnerabilities/{CVE}/affected-assets", headers=VIEWER).json()
    assert "ASSET-O90" not in {x["asset_id"] for x in mine["results"]}


def test_an_asset_of_another_tenant_cannot_be_overwritten_by_an_upload(client):
    r = client.post("/internal/v1/inventory/import", headers=ADMIN, json=csv_upload(GOOD.replace("ASSET-900", "ASSET-O05")))
    assert r.status_code == 200 and (r.json()["rows_accepted"], r.json()["rows_rejected"]) == (0, 1)
    assert r.json()["rejects"][0]["errors"] == [{"field": "asset_id", "type": "not_available"}]
    other = client.get(f"/internal/v1/vulnerabilities/{CVE}/affected-assets", headers=OTHER_VIEWER).json()
    assert [x["asset_name"] for x in other["results"]] == ["other-log-01"]  # untouched


@pytest.mark.parametrize(
    "payload,code",
    [
        (csv_upload("not,a,valid,header\n1,2,3,4\n"), "missing_columns"),
        (csv_upload("{ nope", "x.json", "json"), "not_json"),
        (csv_upload('{"assets": "x"}', "x.json", "json"), "bad_shape"),
        (csv_upload(json.dumps({"tenant_id": "TENANT-OTHER", "assets": []}), "x.json", "json"), "tenant_mismatch"),
        ({"filename": "x.csv", "format": "csv", "content_base64": base64.b64encode(b"\xff\xfe\x00bad").decode()}, "not_utf8"),
        ({"filename": "x.csv", "format": "csv", "content_base64": "%%%not-base64%%%"}, "bad_encoding"),
    ],
)
def test_unusable_files_get_a_stable_code_and_no_file_content(client, payload, code):
    r = client.post("/internal/v1/inventory/import", headers=ADMIN, json=payload)
    assert r.status_code == 422 and r.json()["detail"]["code"] == code
    assert "nope" not in r.text and "not,a,valid" not in r.text


def test_missing_columns_are_named_from_our_own_vocabulary(client):
    r = client.post("/internal/v1/inventory/import", headers=ADMIN, json=csv_upload("asset_id,name\nA,B\n"))
    assert r.json()["detail"] == {"code": "missing_columns", "details": ["asset_type", "environment", "criticality", "internet_exposed"]}


@pytest.mark.parametrize(
    "payload",
    [{}, {"filename": "", "format": "csv", "content_base64": "QQ=="}, {"filename": "x", "format": "xml", "content_base64": "QQ=="},
     {"filename": "x.csv", "format": "csv", "content_base64": ""}, {"filename": "x" * 201, "format": "csv", "content_base64": "QQ=="}],
)
def test_malformed_upload_requests_are_422(client, payload):
    assert client.post("/internal/v1/inventory/import", headers=ADMIN, json=payload).status_code == 422


def test_import_history_and_reject_report_are_tenant_scoped(client):
    first = client.post("/internal/v1/inventory/import", headers=ADMIN, json=csv_upload(MIXED, "first.csv")).json()
    client.post("/internal/v1/inventory/import", headers=OTHER_ADMIN, json=csv_upload(GOOD.replace("ASSET-900", "ASSET-O91"), "theirs.csv"))
    history = client.get("/internal/v1/inventory/imports", headers=ANALYST).json()
    assert [h["source_name"] for h in history] == ["first.csv"]
    assert (history[0]["rows_rejected"], history[0]["source_format"]) == (2, "csv") and "rejects" not in history[0]
    detail = client.get(f"/internal/v1/inventory/imports/{first['import_id']}", headers=ADMIN)
    assert detail.status_code == 200 and len(detail.json()["rejects"]) == 2
    assert client.get(f"/internal/v1/inventory/imports/{first['import_id']}", headers=OTHER_ADMIN).status_code == 404  # looks missing
    assert client.get("/internal/v1/inventory/imports", headers=VIEWER).status_code == 403
    assert client.get(f"/internal/v1/inventory/imports/{first['import_id']}", headers=VIEWER).status_code == 403
    assert client.get("/internal/v1/inventory/imports/not-a-uuid-at-all-and-not-36-characters", headers=ADMIN).status_code == 422
    assert client.get("/internal/v1/inventory/imports/00000000-0000-0000-0000-000000000000", headers=ADMIN).status_code == 404


def test_history_functions_validate_their_input(world):
    _, connect = world
    with connect() as conn:
        for bad in (0, 51, True):
            with pytest.raises(ValueError):
                list_imports(conn, "TENANT-DEMO", bad)
        with pytest.raises(ValueError):
            get_import(conn, "TENANT-DEMO", "'; DROP TABLE inventory_import; --")
        assert list_imports(conn, "TENANT-DEMO") == []
