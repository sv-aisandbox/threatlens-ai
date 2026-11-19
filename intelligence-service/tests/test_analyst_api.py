"""POST /internal/v1/analyst/ask: service-JWT auth, roles, tenant from the token, error mapping."""

import json
import uuid
from datetime import UTC, datetime

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient

from agent.agent import AgentConfig, AnalystAgent
from agent.factory import build_adapter
from agent.mock_adapter import MockAdapter
from agent.models import ModelError
from agent.usage_log import PostgresUsageLog
from app.api import create_app
from app.config import pg_conninfo
from correlation.match_service import run_matching
from ingestion import seed_loader, source_sync, sync
from ingestion.nvd_client import NvdClient
from mcp_tools.audit import PostgresToolAudit
from tests.helpers import SECRET, FakeClock, ScriptedAdapter, bearer, load, mint, nvd_transport, turn_text

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
URL = "/internal/v1/analyst/ask"
Q = "Which of my production assets are affected by CVE-2021-44228, and how sure are we?"
ANALYST = bearer(mint(roles=["SECURITY_ANALYST"], sub="analyst-sub"))
ADMIN = bearer(mint(roles=["ADMIN"], sub="admin-sub"))
VIEWER = bearer(mint(roles=["VIEWER"], sub="viewer-sub"))


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
        sync.import_single_cve(graph, conn, client, "CVE-2021-44228", now=lambda: NOW)
        source_sync.record_result(conn, source_sync.SyncResult(source_id="nvd", attempted_at=NOW))
    run_matching(graph, now=lambda: NOW)
    return graph, connect


def make_app(world, adapter=None, factory=None):
    graph, connect = world
    agent = AnalystAgent(adapter or MockAdapter(), graph, connect, PostgresToolAudit(connect), PostgresUsageLog(connect), AgentConfig())
    return create_app(jwt_secret=SECRET, driver_factory=lambda: _NoCloseDriver(graph), conn_factory=connect,
                      analyst_factory=factory or (lambda: agent))


@pytest.fixture()
def client(world):
    return TestClient(make_app(world))


def ask(client, token=ANALYST, question=Q, **extra):
    return client.post(URL, headers=token, json={"question": question, **extra})


# ---- authentication and roles ------------------------------------------------------------------------------------


def test_no_token_is_401_and_bad_tokens_are_401(client):
    assert client.post(URL, json={"question": Q}).status_code == 401
    assert client.post(URL, headers={"Authorization": "Bearer x.y.z"}, json={"question": Q}).status_code == 401
    assert client.post(URL, headers=bearer(mint(secret="another-secret-" + "y" * 32, roles=["ADMIN"])), json={"question": Q}).status_code == 401


def test_a_viewer_may_not_use_the_analyst(client):
    assert ask(client, VIEWER).status_code == 403


@pytest.mark.parametrize("token", [ANALYST, ADMIN])
def test_analysts_and_admins_get_an_answer(client, token):
    r = ask(client, token)
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "answered" and body["summary"] == {"confirmed_exposures": 1, "possible": 1, "unknown": 1}
    assert {"answer", "findings", "evidence", "freshness", "warnings", "grounding", "trace", "usage", "correlation_id"} <= set(body)


# ---- tenant comes from the token only -------------------------------------------------------------------------------


def test_each_tenant_gets_only_its_own_findings(client):
    mine = ask(client, bearer(mint(tenant="TENANT-DEMO", roles=["SECURITY_ANALYST"]))).json()
    theirs = ask(client, bearer(mint(tenant="TENANT-OTHER", roles=["SECURITY_ANALYST"]))).json()
    assert [f["asset_id"] for f in mine["findings"]["confirmed"]] == ["ASSET-013"]
    assert [f["asset_id"] for f in theirs["findings"]["confirmed"]] == ["ASSET-O05"]
    assert "TENANT-OTHER" not in json.dumps(mine) and "ASSET-013" not in json.dumps(theirs)


@pytest.mark.parametrize("extra", [{"tenant_id": "TENANT-OTHER"}, {"tenant": "TENANT-OTHER"}, {"roles": ["ADMIN"]}, {"tools": ["get_critical_assets"]}])
def test_extra_body_fields_are_rejected_not_ignored(client, extra):
    r = ask(client, **extra)
    assert r.status_code == 422


def test_header_and_query_tenant_hints_are_ignored(client):
    r = client.post(URL + "?tenant_id=TENANT-OTHER", headers={**ANALYST, "X-Tenant-Id": "TENANT-OTHER"}, json={"question": Q})
    assert r.status_code == 200 and [f["asset_id"] for f in r.json()["findings"]["confirmed"]] == ["ASSET-013"]


# ---- validation ------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("body", [{}, {"question": ""}, {"question": "ab"}, {"question": "x" * 2001}, {"question": 42}, {"question": None}])
def test_invalid_questions_are_422(client, body):
    assert client.post(URL, headers=ANALYST, json=body).status_code == 422


def test_a_non_json_body_is_422(client):
    assert client.post(URL, headers=ANALYST, content="not json").status_code == 422


# ---- correlation, usage, errors -----------------------------------------------------------------------------------------


def test_the_correlation_id_reaches_the_answer_and_the_usage_log(client, world):
    cid = "abcd1234-trace-" + uuid.uuid4().hex[:8]
    r = client.post(URL, headers={**ANALYST, "X-Correlation-Id": cid}, json={"question": Q})
    assert r.headers["x-correlation-id"] == cid and r.json()["correlation_id"] == cid
    _, connect = world
    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT tenant_id, actor, provider, tool_calls, outcome FROM analyst_request_log WHERE correlation_id = %s", (cid,))
        assert cur.fetchall() == [("TENANT-DEMO", "agent:analyst-sub", "mock", 1, "answered")]


def test_a_model_failure_is_a_503_without_details(world):
    adapter = ScriptedAdapter([ModelError("model_auth", "The model provider rejected the credentials. SECRET-DETAIL")])
    r = ask(TestClient(make_app(world, adapter)))
    assert r.status_code == 503 and r.json() == {"detail": "analyst_unavailable"}
    assert "SECRET" not in r.text and "model_auth" not in r.text


def test_a_provider_without_a_key_is_a_503_and_never_leaks_configuration(world, monkeypatch):
    monkeypatch.setenv("MODEL_PROVIDER", "anthropic")
    monkeypatch.setenv("MODEL_API_KEY", "your-model-provider-key")  # the placeholder counts as not set
    graph, connect = world
    from agent.factory import build_agent

    app = create_app(jwt_secret=SECRET, driver_factory=lambda: _NoCloseDriver(graph), conn_factory=connect,
                     analyst_factory=lambda: build_agent(graph, connect))
    r = ask(TestClient(app))
    assert r.status_code == 503 and r.json() == {"detail": "analyst_unavailable"}


def test_too_many_concurrent_questions_get_429(world):
    app = make_app(world)
    slots = app.state.ask_slots
    held = [slots.acquire(blocking=False) for _ in range(4)]
    try:
        assert all(held)
        assert ask(TestClient(app)).status_code == 429
    finally:
        for _ in held:
            slots.release()
    assert ask(TestClient(app)).status_code == 200  # slots are released after use


def test_a_scripted_model_answer_goes_through_the_same_guards(world):
    adapter = ScriptedAdapter([turn_text("CVE-2099-1234 affects ASSET-999 in TENANT-OTHER.")])
    body = ask(TestClient(make_app(world, adapter))).json()
    assert body["grounding"]["ok"] is False and "ASSET-999" not in body["answer"] and "TENANT-OTHER" not in body["answer"]


# ---- provider selection from the environment ------------------------------------------------------------------------------


def test_adapter_selection_from_the_environment():
    assert build_adapter({}).provider == "mock" and build_adapter({"MODEL_PROVIDER": "mock"}).provider == "mock"
    real = build_adapter({"MODEL_PROVIDER": "anthropic", "MODEL_API_KEY": "sk-ant-test", "MODEL_EFFORT": "high", "MODEL_FALLBACKS": "off"})
    assert (real.provider, real.model, real.effort, real.fallbacks) == ("anthropic", "claude-opus-5-5", "high", False)
    assert build_adapter({"MODEL_PROVIDER": "anthropic", "MODEL_API_KEY": "sk-ant-test", "MODEL_NAME": "claude-sonnet-5-5"}).model == "claude-sonnet-5-5"
    for env in ({"MODEL_PROVIDER": "anthropic"}, {"MODEL_PROVIDER": "anthropic", "MODEL_API_KEY": "your-model-provider-key"},
                {"MODEL_PROVIDER": "openai"}):
        with pytest.raises(ModelError) as exc:
            build_adapter(env)
        assert exc.value.code == "model_not_configured" and "sk-ant" not in str(exc.value)
