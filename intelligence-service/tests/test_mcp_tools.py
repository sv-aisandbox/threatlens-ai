"""MCP servers exercised through the official SDK client (in-process), plus real stdio subprocess smoke tests."""

import json
import os
import re
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import psycopg
import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from neo4j.exceptions import ServiceUnavailable

from app import api
from app.config import pg_conninfo
from correlation.match_service import run_matching
from graph_queries.affected_assets import get_affected_assets_with_freshness
from graph_queries.vulnerability import get_vulnerability
from ingestion import seed_loader, source_sync, sync
from ingestion.nvd_client import NvdClient
from mcp_tools import asset_server, vulnerability_server
from mcp_tools.audit import PostgresToolAudit, hash_arguments
from mcp_tools.context import ConfigError, TrustedContext
from mcp_tools.runtime import ToolDeps
from tests.conftest import MIGRATIONS
from tests.helpers import FakeClock, load, nvd_transport

CVE = "CVE-2021-44228"
NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
ROOT = seed_loader.REPO_ROOT / "intelligence-service"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
pytestmark = pytest.mark.anyio


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


# ---- one shared, read-only world for the module ------------------------------------------------------------


@pytest.fixture(scope="module")
def env(test_driver):
    schema = f"mcp_{uuid.uuid4().hex[:10]}"
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
    seed_loader.load_seed(test_driver)  # synthetic tenants, assets, fictional CVEs and their matches
    clock = FakeClock()
    client = NvdClient(None, httpx.Client(transport=nvd_transport({0: load("nvd/cve-2021-44228.json")})), clock.sleep, clock.monotonic)
    with connect() as conn:
        sync.import_single_cve(test_driver, conn, client, CVE, now=lambda: NOW)  # real NVD record
        sync.run_kev_sync(test_driver, conn, lambda: load("kev/kev-sample.json"), now=lambda: NOW)
        source_sync.record_result(conn, source_sync.SyncResult(source_id="nvd", attempted_at=NOW))  # an NVD sync happened
    run_matching(test_driver, now=lambda: NOW)
    yield SimpleNamespace(driver=test_driver, connect=connect, schema=schema, options=options)
    admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
    admin.close()


def make(env, module, tenant="TENANT-DEMO", roles=("VIEWER",), audit=None, driver=None):
    ctx = TrustedContext(tenant, frozenset(roles), "test-actor")
    deps = ToolDeps(ctx=ctx, driver=driver or env.driver, connect=env.connect, audit=audit or PostgresToolAudit(env.connect))
    return module.build_server(deps)


async def call(server, name, args=None):
    async with Client(server) as client:
        result = await client.call_tool(name, args or {})
    structured = getattr(result, "structured_content", None)
    body = structured if structured is not None else json.loads(result.content[0].text)
    return bool(result.is_error), body, result


def error(body):
    return body["error"]


def audit_rows(env, cid):
    with env.connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT server, tool, args_hash, tenant_id, actor, latency_ms, outcome, error_code, correlation_id "
            "FROM tool_call_audit WHERE correlation_id = %s", (cid,))
        return cur.fetchall()


@pytest.fixture(scope="module")
def vuln(env):
    return make(env, vulnerability_server)


@pytest.fixture(scope="module")
def assets(env):
    return make(env, asset_server)


@pytest.fixture(scope="module")
def other_vuln(env):
    return make(env, vulnerability_server, tenant="TENANT-OTHER")


@pytest.fixture(scope="module")
def other_assets(env):
    return make(env, asset_server, tenant="TENANT-OTHER")


# ---- listing and schemas ---------------------------------------------------------------------------------


async def test_both_servers_list_exactly_the_planned_read_only_tools(vuln, assets):
    for server, module in ((vuln, vulnerability_server), (assets, asset_server)):
        async with Client(server) as client:
            tools = (await client.list_tools()).tools
        assert [t.name for t in tools] == module.TOOL_NAMES
        for t in tools:
            assert t.description and len(t.description) > 40
            a = t.annotations
            assert (a.read_only_hint, a.destructive_hint, a.idempotent_hint, a.open_world_hint) == (True, False, True, False)
            props = (getattr(t, "input_schema", None) or t.inputSchema)["properties"]
            assert not ({"tenant", "tenant_id", "tenantid", "org", "organization", "role", "roles"} & {p.lower() for p in props})
            assert getattr(t, "output_schema", None) or t.outputSchema


async def test_schemas_carry_the_validation_rules(vuln, assets):
    async with Client(vuln) as client:
        tools = {t.name: (getattr(t, "input_schema", None) or t.inputSchema) for t in (await client.list_tools()).tools}
    p = tools["get_affected_assets"]["properties"]
    assert p["cve_id"]["pattern"] == r"^CVE-\d{4}-\d{4,}$" and p["cve_id"]["maxLength"] == 40
    assert p["environment"]["enum"] == ["production", "staging", "development", "all"]  # spec section 6 contract
    assert (p["limit"]["minimum"], p["limit"]["maximum"]) == (1, 100)
    assert tools["get_affected_assets"]["required"] == ["cve_id"]
    async with Client(assets) as client:
        tools = {t.name: (getattr(t, "input_schema", None) or t.inputSchema) for t in (await client.list_tools()).tools}
    assert tools["get_asset_details"]["properties"]["asset_id"]["pattern"] == r"^ASSET-[A-Z0-9-]{1,40}$"


def test_tools_use_the_same_service_functions_as_the_rest_api():
    assert vulnerability_server.get_affected_assets_with_freshness is api.get_affected_assets_with_freshness
    assert vulnerability_server.get_vulnerability is api.get_vulnerability


# ---- get_affected_assets -------------------------------------------------------------------------------------


async def test_get_affected_assets_matches_the_rest_service_function(env, vuln):
    is_error, body, _ = await call(vuln, "get_affected_assets", {"cve_id": CVE})
    assert not is_error
    with env.connect() as conn:
        direct = get_affected_assets_with_freshness(env.driver, conn, "TENANT-DEMO", CVE)
    assert [(r["asset_id"], r["match_status"]) for r in body["results"]] == [
        (r["asset_id"], r["match_status"]) for r in direct["results"]]
    assert {r["asset_id"] for r in body["results"]} == {"ASSET-013", "ASSET-015", "ASSET-016"}
    assert body["summary"] == {"confirmed": 1, "possible": 1, "unknown": 1}
    assert body["freshness"] == direct["freshness"]


async def test_result_envelope_is_stable_and_carries_evidence_source_time_and_status(vuln):
    _, body, _ = await call(vuln, "get_affected_assets", {"cve_id": CVE})
    assert {"tool", "scope", "tenant_id", "correlation_id", "generated_at", "results", "freshness", "warnings",
            "truncated", "untrusted_fields", "cve_known", "summary"} <= set(body)
    assert (body["tool"], body["scope"], body["tenant_id"], body["cve_known"]) == ("get_affected_assets", "tenant", "TENANT-DEMO", True)
    assert UUID_RE.match(body["correlation_id"])
    row = next(r for r in body["results"] if r["match_status"] == "confirmed")
    assert row["asset_id"] == "ASSET-013" and row["match_reason"] and row["matched_at"] and row["matched_by"] == "cpe-matcher/1"
    assert row["evidence"] and {"source_name", "source_url", "collected_at"} <= set(row["evidence"][0])
    assert "match_reason" in body["untrusted_fields"]
    assert body["freshness"]["intelligence"]["nvd_last_success_at"] and body["freshness"]["intelligence"]["kev_last_success_at"]


async def test_environment_limit_and_truncation(vuln, other_vuln):
    _, prod, _ = await call(vuln, "get_affected_assets", {"cve_id": CVE, "environment": "production"})
    assert len(prod["results"]) == 3
    _, staging, _ = await call(vuln, "get_affected_assets", {"cve_id": CVE, "environment": "staging"})
    assert staging["results"] == []
    _, one, _ = await call(vuln, "get_affected_assets", {"cve_id": CVE, "limit": 1})
    assert len(one["results"]) == 1 and one["truncated"] is True


async def test_unknown_cve_is_empty_but_flagged_not_safe(vuln):
    _, body, _ = await call(vuln, "get_affected_assets", {"cve_id": "CVE-2099-0001"})
    assert body["results"] == [] and body["cve_known"] is False
    assert any("not in the local vulnerability database" in w for w in body["warnings"])


# ---- malformed and hostile arguments ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args,leaked",
    [
        ({}, None),
        ({"cve_id": "CVE-1"}, "CVE-1"),
        ({"cve_id": "cve-2021-44228"}, "cve-2021-44228"),
        ({"cve_id": 42}, None),
        ({"cve_id": None}, None),
        ({"cve_id": CVE, "environment": "moon"}, "moon"),
        ({"cve_id": CVE, "limit": 0}, None),
        ({"cve_id": CVE, "limit": 1000}, None),
        ({"cve_id": CVE, "limit": "ten"}, "ten"),
        ({"cve_id": "CVE-2021-44228'; MATCH (n) DETACH DELETE n //"}, "DETACH"),
        ({"cve_id": "<script>alert(1)</script>"}, "script"),
    ],
)
async def test_malformed_arguments_are_rejected_with_a_stable_error(vuln, args, leaked):
    is_error, body, result = await call(vuln, "get_affected_assets", args)
    assert is_error and set(error(body)) == {"code", "message", "correlation_id"}
    assert error(body)["code"] == "invalid_argument" and UUID_RE.match(error(body)["correlation_id"])
    text = result.content[0].text
    assert "errors.pydantic.dev" not in text and "input_value" not in text
    if leaked:
        assert leaked not in text, "the offending value must not be echoed back"


@pytest.mark.parametrize("extra", ["tenant_id", "tenantId", "tenant", "organization", "role", "roles", "actor"])
async def test_injected_tenant_or_permission_arguments_are_rejected_not_ignored(env, vuln, extra):
    is_error, body, _ = await call(vuln, "get_affected_assets", {"cve_id": CVE, extra: "TENANT-OTHER"})
    assert is_error and error(body)["code"] == "invalid_argument" and extra in error(body)["message"]
    assert "TENANT-OTHER" not in error(body)["message"]
    rows = audit_rows(env, error(body)["correlation_id"])
    assert len(rows) == 1 and rows[0][6] == "invalid"


async def test_unknown_tool_is_not_found(env, vuln):
    is_error, body, _ = await call(vuln, "delete_everything", {"cve_id": CVE})
    assert is_error and error(body)["code"] == "not_found"
    assert audit_rows(env, error(body)["correlation_id"])[0][1] == "(unknown)"


# ---- cross-tenant -------------------------------------------------------------------------------------------------


async def test_each_server_sees_only_its_own_tenant(vuln, other_vuln):
    _, mine, _ = await call(vuln, "get_affected_assets", {"cve_id": CVE})
    _, theirs, _ = await call(other_vuln, "get_affected_assets", {"cve_id": CVE})
    assert {r["asset_id"] for r in theirs["results"]} == {"ASSET-O05"} and theirs["tenant_id"] == "TENANT-OTHER"
    assert not {r["asset_id"] for r in mine["results"]} & {r["asset_id"] for r in theirs["results"]}
    assert "TENANT-OTHER" not in json.dumps(mine) and "TENANT-DEMO" not in json.dumps(theirs)


async def test_another_tenants_asset_is_indistinguishable_from_a_missing_one(assets):
    for tool in ("get_asset_details", "get_asset_software"):
        _, foreign, _ = await call(assets, tool, {"asset_id": "ASSET-O05"})
        _, missing, _ = await call(assets, tool, {"asset_id": "ASSET-ZZZ-404"})
        assert error(foreign)["code"] == "not_found"
        foreign["error"].pop("correlation_id"), missing["error"].pop("correlation_id")
        assert foreign == missing


async def test_asset_search_never_crosses_tenants(assets, other_assets):
    _, mine, _ = await call(assets, "search_assets", {"limit": 100})
    _, theirs, _ = await call(other_assets, "search_assets", {"limit": 100})
    mine_ids, their_ids = {r["asset_id"] for r in mine["results"]}, {r["asset_id"] for r in theirs["results"]}
    assert mine_ids and their_ids and not mine_ids & their_ids
    assert all(i.startswith("ASSET-O") for i in their_ids) and not any(i.startswith("ASSET-O") for i in mine_ids)
    _, probe, _ = await call(assets, "search_assets", {"query": "ASSET-O05"})
    assert probe["results"] == []
    _, probe2, _ = await call(assets, "search_assets", {"query": "other-log"})
    assert probe2["results"] == []


# ---- asset tools -------------------------------------------------------------------------------------------------


async def test_search_assets_filters(assets):
    _, body, _ = await call(assets, "search_assets", {"environment": "production", "criticality": "critical", "internet_exposed": True})
    assert {r["asset_id"] for r in body["results"]} == {"ASSET-001", "ASSET-002"}
    _, byname, _ = await call(assets, "search_assets", {"query": "LOG-collector"})
    assert {r["asset_id"] for r in byname["results"]} == {"ASSET-013", "ASSET-014", "ASSET-015"}
    _, limited, _ = await call(assets, "search_assets", {"limit": 2})
    assert len(limited["results"]) == 2 and limited["truncated"] is True
    assert "name" in limited["untrusted_fields"]


async def test_asset_details_report_confirmed_exposure_only(assets):
    _, exposed, _ = await call(assets, "get_asset_details", {"asset_id": "ASSET-013"})
    assert exposed["asset"]["software_count"] == 1 and exposed["asset"]["confirmed_vulnerabilities"] == 1
    _, unknown, _ = await call(assets, "get_asset_details", {"asset_id": "ASSET-015"})
    assert unknown["asset"]["confirmed_vulnerabilities"] == 0  # 'unknown' is not exposure
    assert exposed["asset"]["inventory_imported_at"]


async def test_asset_software_lists_findings_with_status_and_hides_ruled_out_by_default(assets):
    _, body, _ = await call(assets, "get_asset_software", {"asset_id": "ASSET-013"})
    finding = body["software"][0]["findings"][0]
    assert body["software"][0]["product"] == "Log4j" and body["software"][0]["cpe"].startswith("cpe:2.3:a:apache:log4j")
    assert (finding["cve_id"], finding["match_status"], finding["kev_listed"]) == (CVE, "confirmed", True)
    assert finding["match_reason"] and finding["matched_by"] == "cpe-matcher/1"
    _, hidden, _ = await call(assets, "get_asset_software", {"asset_id": "ASSET-014"})
    assert hidden["software"][0]["findings"] == []
    _, shown, _ = await call(assets, "get_asset_software", {"asset_id": "ASSET-014", "include_not_affected": True})
    assert [f["match_status"] for f in shown["software"][0]["findings"]] == ["not_affected"]


async def test_critical_assets_are_ordered_by_confirmed_exposure(assets, other_assets):
    _, mine, _ = await call(assets, "get_critical_assets", {})
    assert [(r["asset_id"], r["confirmed_vulnerabilities"]) for r in mine["results"]] == [
        ("ASSET-001", 1), ("ASSET-002", 1), ("ASSET-006", 1)]
    _, theirs, _ = await call(other_assets, "get_critical_assets", {"environment": "production"})
    assert [r["asset_id"] for r in theirs["results"]] == ["ASSET-O01", "ASSET-O05"]
    _, staging, _ = await call(assets, "get_critical_assets", {"environment": "staging"})
    assert staging["results"] == []


# ---- vulnerability tools ---------------------------------------------------------------------------------------


async def test_vulnerability_details_match_the_rest_function_and_are_global(env, vuln, other_vuln):
    _, body, _ = await call(vuln, "get_vulnerability_details", {"cve_id": CVE})
    assert body["vulnerability"] == get_vulnerability(env.driver, CVE) and body["scope"] == "global" and body["tenant_id"] is None
    v = body["vulnerability"]
    assert (v["cvss_score"], v["severity"], v["kev_listed"], v["kev_due_date"]) == (10.0, "critical", True, "2021-12-24")
    assert {"description", "kev_name"} <= set(body["untrusted_fields"])
    _, other, _ = await call(other_vuln, "get_vulnerability_details", {"cve_id": CVE})
    assert other["vulnerability"] == v  # public intelligence is the same for every tenant


async def test_unknown_cve_details_and_evidence_are_not_found(vuln):
    for tool in ("get_vulnerability_details", "get_vulnerability_evidence"):
        is_error, body, _ = await call(vuln, tool, {"cve_id": "CVE-2099-0001"})
        assert is_error and error(body)["code"] == "not_found"


async def test_search_vulnerabilities(vuln):
    _, byword, _ = await call(vuln, "search_vulnerabilities", {"query": "log4j"})
    assert byword["results"][0]["cve_id"] == CVE and all(len(r["description"] or "") <= 300 for r in byword["results"])
    _, kev, _ = await call(vuln, "search_vulnerabilities", {"kev_only": True})
    assert CVE in {r["cve_id"] for r in kev["results"]} and all(r["kev_listed"] for r in kev["results"])
    assert kev["results"][0]["cve_id"] == CVE  # KEV first, then highest CVSS; the KEV-only stubs have no score
    _, severe, _ = await call(vuln, "search_vulnerabilities", {"min_cvss": 9.5})
    assert {r["cve_id"] for r in severe["results"]} == {CVE}
    _, exact, _ = await call(vuln, "search_vulnerabilities", {"query": "cve-demo-0002"})
    assert [r["cve_id"] for r in exact["results"]] == ["CVE-DEMO-0002"] and exact["results"][0]["synthetic"] is True
    _, limited, _ = await call(vuln, "search_vulnerabilities", {"kev_only": True, "limit": 2})
    assert len(limited["results"]) == 2 and limited["truncated"] is True


@pytest.mark.parametrize("args", [{"query": "a"}, {"query": "x" * 101}, {"min_cvss": 11}, {"min_cvss": -1}, {"limit": 51}, {"kev_only": "maybe"}])
async def test_search_arguments_are_validated(vuln, args):
    is_error, body, _ = await call(vuln, "search_vulnerabilities", args)
    assert is_error and error(body)["code"] == "invalid_argument"


async def test_evidence_has_provenance_for_every_source(vuln):
    _, body, _ = await call(vuln, "get_vulnerability_evidence", {"cve_id": CVE})
    sources = {e["source_name"]: e for e in body["evidence"]}
    assert set(sources) == {"NVD", "CISA KEV"}
    for e in sources.values():
        assert re.fullmatch(r"[0-9a-f]{64}", e["content_hash"]) and e["collected_at"] and e["source_url"].startswith("https://")


# ---- error shapes ------------------------------------------------------------------------------------------------


class _DownDriver:
    def session(self, *a, **k):
        raise ServiceUnavailable("bolt://10.0.0.5:7687 secret-host refused")


async def test_unavailable_database_is_a_stable_error_without_internals(env):
    server = make(env, asset_server, driver=_DownDriver())
    is_error, body, result = await call(server, "search_assets", {})
    assert is_error and error(body)["code"] == "unavailable"
    assert "10.0.0.5" not in result.content[0].text and "secret-host" not in result.content[0].text


async def test_unexpected_crash_is_internal_error_without_details(env, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("SECRET-DETAIL jdbc:postgresql://db password=hunter2")

    monkeypatch.setattr(vulnerability_server, "get_vulnerability", boom)
    server = make(env, vulnerability_server)
    is_error, body, result = await call(server, "get_vulnerability_details", {"cve_id": CVE})
    assert is_error and error(body)["code"] == "internal_error"
    assert "SECRET-DETAIL" not in result.content[0].text and "hunter2" not in result.content[0].text
    assert audit_rows(env, error(body)["correlation_id"])[0][6] == "error"


async def test_error_text_and_structured_content_agree(vuln):
    is_error, body, result = await call(vuln, "get_vulnerability_details", {"cve_id": "CVE-2099-0001"})
    assert json.loads(result.content[0].text) == body and result.is_error


# ---- audit (6.5) ---------------------------------------------------------------------------------------------------


async def test_every_call_is_audited_with_a_hash_not_the_arguments(env, vuln):
    args = {"cve_id": CVE, "environment": "production"}
    _, body, _ = await call(vuln, "get_affected_assets", args)
    rows = audit_rows(env, body["correlation_id"])
    assert len(rows) == 1
    server, tool, args_hash, tenant, actor, latency, outcome, code, cid = rows[0]
    assert (server, tool, tenant, actor, outcome, code) == ("threatlens-vulnerability", "get_affected_assets", "TENANT-DEMO", "test-actor", "success", None)
    assert args_hash == hash_arguments(args) and re.fullmatch(r"[0-9a-f]{64}", args_hash)
    assert isinstance(latency, int) and latency >= 0
    with env.connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT concat_ws('|', server, tool, args_hash, tenant_id, actor, outcome, error_code, correlation_id) "
                    "FROM tool_call_audit WHERE correlation_id = %s", (cid,))
        text = cur.fetchone()[0]
    assert CVE not in text and "production" not in text  # raw arguments are never stored


async def test_outcomes_are_audited_for_success_invalid_denied_and_not_found(env, vuln):
    outcomes = {}
    for label, tool, args in [("ok", "get_vulnerability_details", {"cve_id": CVE}),
                              ("bad", "get_vulnerability_details", {"cve_id": "nope"}),
                              ("missing", "get_vulnerability_details", {"cve_id": "CVE-2099-0001"})]:
        _, body, _ = await call(vuln, tool, args)
        cid = body["correlation_id"] if "correlation_id" in body else error(body)["correlation_id"]
        outcomes[label] = audit_rows(env, cid)[0][6]
    assert outcomes == {"ok": "success", "bad": "invalid", "missing": "not_found"}


async def test_argument_hash_is_order_independent_and_covers_extra_keys():
    assert hash_arguments({"a": 1, "b": 2}) == hash_arguments({"b": 2, "a": 1})
    assert hash_arguments({"cve_id": CVE}) != hash_arguments({"cve_id": CVE, "tenant_id": "TENANT-OTHER"})
    assert hash_arguments(None) == hash_arguments({})


async def test_a_failing_audit_never_breaks_the_tool_call(env):
    class Broken(PostgresToolAudit):
        def __init__(self):
            super().__init__(lambda: (_ for _ in ()).throw(psycopg.OperationalError("audit db down")))

    server = make(env, vulnerability_server, audit=Broken())
    is_error, body, _ = await call(server, "get_vulnerability_details", {"cve_id": CVE})
    assert not is_error and body["vulnerability"]["cve_id"] == CVE


# ---- trusted context -----------------------------------------------------------------------------------------------------


async def test_a_context_without_a_read_role_is_denied_and_audited(env):
    server = make(env, vulnerability_server, roles=())
    is_error, body, _ = await call(server, "get_vulnerability_details", {"cve_id": CVE})
    assert is_error and error(body)["code"] == "forbidden"
    assert audit_rows(env, error(body)["correlation_id"])[0][6] == "denied"


def test_context_comes_only_from_valid_server_configuration():
    ok = TrustedContext.from_env("mcp:x", {"THREATLENS_TENANT_ID": "TENANT-DEMO"})
    assert (ok.tenant_id, ok.roles, ok.actor) == ("TENANT-DEMO", frozenset({"VIEWER"}), "mcp:x")  # least privilege default
    multi = TrustedContext.from_env("mcp:x", {"THREATLENS_TENANT_ID": "TENANT-A", "THREATLENS_ROLES": "VIEWER, SECURITY_ANALYST", "THREATLENS_ACTOR": "bob@example.invalid"})
    assert multi.roles == frozenset({"VIEWER", "SECURITY_ANALYST"}) and multi.actor == "bob@example.invalid"
    for bad in ({}, {"THREATLENS_TENANT_ID": ""}, {"THREATLENS_TENANT_ID": "tenant-demo"}, {"THREATLENS_TENANT_ID": "TENANT-DEMO' OR 1=1"},
                {"THREATLENS_TENANT_ID": "TENANT-DEMO", "THREATLENS_ROLES": "ROOT"},
                {"THREATLENS_TENANT_ID": "TENANT-DEMO", "THREATLENS_ROLES": " , "},
                {"THREATLENS_TENANT_ID": "TENANT-DEMO", "THREATLENS_ACTOR": "bad actor; DROP"}):
        with pytest.raises(ConfigError):
            TrustedContext.from_env("mcp:x", bad)


# ---- real stdio subprocess: any MCP client can connect --------------------------------------------------------------------


def _stdio_env(env, **extra):
    base = {k: v for k, v in os.environ.items()}
    base.update({"MEMGRAPH_PORT": os.environ.get("MEMGRAPH_TEST_PORT", "7688"), "PGOPTIONS": env.options,
                 "THREATLENS_TENANT_ID": "TENANT-DEMO", "PYTHONUNBUFFERED": "1"})
    base.update(extra)
    return base


@pytest.mark.parametrize("module,expected_tool,args", [
    ("mcp_tools.vulnerability_server", "get_affected_assets", {"cve_id": CVE}),
    ("mcp_tools.asset_server", "get_critical_assets", {}),
])
async def test_stdio_subprocess_serves_real_tool_calls(env, module, expected_tool, args):
    params = StdioServerParameters(command=sys.executable, args=["-m", module], env=_stdio_env(env), cwd=str(ROOT))
    async with Client(params) as client:
        names = [t.name for t in (await client.list_tools()).tools]
        assert expected_tool in names
        result = await client.call_tool(expected_tool, args)
    assert not result.is_error
    body = result.structured_content or json.loads(result.content[0].text)
    assert body["tenant_id"] == "TENANT-DEMO" and body["results"]


def test_server_refuses_to_start_without_a_valid_tenant_and_keeps_stdout_clean(env):
    out = subprocess.run([sys.executable, "-m", "mcp_tools.asset_server"], cwd=str(ROOT), capture_output=True, text=True, timeout=60,
                         env=_stdio_env(env, THREATLENS_TENANT_ID="not-a-tenant"), stdin=subprocess.DEVNULL)
    assert out.returncode != 0 and out.stdout == "" and "THREATLENS_TENANT_ID" in out.stderr
