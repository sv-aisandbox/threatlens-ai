"""The evaluation set, its scorer, and a full mock-provider run against the thresholds."""

import copy

import pytest

from agent import evaluation as ev
from agent.agent import AgentConfig, AnalystAgent
from agent.mock_adapter import MockAdapter
from agent.registry import METADATA
from agent.usage_log import PostgresUsageLog
from mcp_tools.audit import PostgresToolAudit
from tests.test_mcp_tools import env  # noqa: F401  (module-scoped world)

DATA = ev.load_questions()
QUESTIONS = DATA["questions"]


# ---- the dataset ---------------------------------------------------------------------------------------------------


def test_the_starter_set_has_15_to_20_well_formed_questions():
    assert 15 <= len(QUESTIONS) <= 20
    ids = [q["id"] for q in QUESTIONS]
    assert len(ids) == len(set(ids))
    assert {"affected_assets", "vulnerability_details", "evidence", "search", "investigation", "not_found", "refusal"} <= {q["category"] for q in QUESTIONS}
    for q in QUESTIONS:
        assert 3 <= len(q["question"]) <= 2000
        expect = q["expect"]
        assert set(expect.get("tools", [])) <= set(METADATA), q["id"]
        assert set(expect.get("tools_forbidden", [])) <= set(METADATA), q["id"]
        for a in expect.get("args", []):
            assert a["tool"] in expect["tools"], q["id"]
        if expect.get("refusal"):
            assert expect["tools"] == [], q["id"]


def test_the_set_covers_every_metric_and_enough_refusals():
    assert sum(1 for q in QUESTIONS if q["expect"].get("refusal")) >= 4
    assert sum(1 for q in QUESTIONS if q["expect"].get("args")) >= 8
    assert sum(1 for q in QUESTIONS if q["expect"].get("facts")) >= 4
    used = {t for q in QUESTIONS for t in q["expect"].get("tools", [])}
    assert used == set(METADATA)  # every tool is exercised by at least one question


def test_thresholds_exist_for_mock_and_real_runs():
    mock, real = ev.load_thresholds("mock"), ev.load_thresholds("real")
    assert set(mock) == set(real) == set(ev.METRICS)
    assert real["groundedness"] == 1.0 and real["refusal"] == 1.0 and 0.5 < real["tool_choice"] <= 1.0


# ---- a full run with the deterministic mock --------------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_mock_provider_passes_the_evaluation(env):
    agent = AnalystAgent(MockAdapter(), env.driver, env.connect, PostgresToolAudit(env.connect), PostgresUsageLog(env.connect), AgentConfig())
    results, metrics = await ev.run_evaluation(agent, DATA)
    failures = [(r["id"], r["failures"]) for r in results if r["failures"]]
    assert not failures, failures
    assert not ev.check_thresholds(metrics, ev.load_thresholds("mock"))
    assert metrics["questions"] == len(QUESTIONS) and metrics["total_cost_usd"] == 0.0
    assert metrics["total_tool_calls"] <= 3 * len(QUESTIONS)  # the agent does not call every tool for every question


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


# ---- the scorer has teeth: deliberately bad answers must fail the right metric --------------------------------------


def good_answer(**over):
    base = {
        "answer": "ASSET-013 is exposed to CVE-2021-44228 (confirmed).", "grounding": {"ok": True, "ungrounded": []},
        "findings": {"confirmed": [{"asset_id": "ASSET-013"}], "possible": [], "unknown": []},
        "evidence": [{"source_name": "NVD"}], "usage": {"cost_usd": 0.0},
        "trace": [{"step": 1, "tool": "get_affected_assets", "args": {"cve_id": "CVE-2021-44228", "environment": "production"}, "outcome": "ok"}],
    }
    base.update(over)
    return base


QUESTION = {"id": "t1", "category": "affected_assets", "question": "q", "expect": {
    "tools": ["get_affected_assets"], "args": [{"tool": "get_affected_assets", "args": {"cve_id": "CVE-2021-44228", "environment": "production"}}],
    "facts": {"confirmed": ["ASSET-013"]}, "answer_contains": ["ASSET-013"], "evidence_sources": ["NVD"], "max_tool_calls": 2}}
REFUSAL_Q = {"id": "t2", "category": "refusal", "question": "q", "expect": {"refusal": True, "tools": []}}


def test_a_good_answer_passes_every_metric():
    r = ev.score_question(QUESTION, good_answer())
    assert (r["tool_choice"], r["args"], r["groundedness"], r["refusal"]) == (True, True, True, True) and r["failures"] == []


def test_wrong_or_extra_or_missing_tools_fail_tool_choice():
    wrong = good_answer(trace=[{"step": 1, "tool": "get_critical_assets", "args": {}, "outcome": "ok"}])
    assert ev.score_question(QUESTION, wrong)["tool_choice"] is False
    none = good_answer(trace=[])
    assert ev.score_question(QUESTION, none)["tool_choice"] is False
    many = good_answer(trace=[{"step": i, "tool": "get_affected_assets", "args": QUESTION["expect"]["args"][0]["args"], "outcome": "ok"} for i in range(3)])
    assert ev.score_question(QUESTION, many)["tool_choice"] is False  # over the call budget
    forbidden = copy.deepcopy(QUESTION)
    forbidden["expect"]["tools_forbidden"] = ["get_critical_assets"]
    both = good_answer(trace=good_answer()["trace"] + [{"step": 2, "tool": "get_critical_assets", "args": {}, "outcome": "ok"}])
    assert ev.score_question(forbidden, both)["tool_choice"] is False


def test_refused_calls_do_not_count_as_calls():
    answer = good_answer(trace=good_answer()["trace"] + [{"step": 2, "tool": "get_critical_assets", "args": {}, "outcome": "refused:not_offered"}])
    assert ev.score_question(QUESTION, answer)["tool_choice"] is True


def test_wrong_arguments_fail_args():
    wrong = good_answer(trace=[{"step": 1, "tool": "get_affected_assets", "args": {"cve_id": "CVE-2021-44228", "environment": "staging"}, "outcome": "ok"}])
    assert ev.score_question(QUESTION, wrong)["args"] is False
    missing = good_answer(trace=[{"step": 1, "tool": "get_affected_assets", "args": {"cve_id": "CVE-2021-44228"}, "outcome": "ok"}])
    assert ev.score_question(QUESTION, missing)["args"] is False
    extra = good_answer(trace=[{"step": 1, "tool": "get_affected_assets", "args": {"cve_id": "CVE-2021-44228", "environment": "production", "limit": 5}, "outcome": "ok"}])
    assert ev.score_question(QUESTION, extra)["args"] is True  # expectations are subsets
    no_args = {"id": "t", "category": "c", "question": "q", "expect": {"tools": []}}
    assert ev.score_question(no_args, good_answer(trace=[]))["args"] is None


def test_float_arguments_compare_numerically():
    q = {"id": "t", "category": "search", "question": "q", "expect": {"tools": ["search_vulnerabilities"], "args": [{"tool": "search_vulnerabilities", "args": {"min_cvss": 9.0}}]}}
    ok = good_answer(trace=[{"step": 1, "tool": "search_vulnerabilities", "args": {"min_cvss": 9}, "outcome": "ok"}])
    bad = good_answer(trace=[{"step": 1, "tool": "search_vulnerabilities", "args": {"min_cvss": 8.0}, "outcome": "ok"}])
    assert ev.score_question(q, ok)["args"] is True and ev.score_question(q, bad)["args"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"grounding": {"ok": False, "ungrounded": ["ASSET-999"]}},                                  # invented identifier
        {"findings": {"confirmed": [], "possible": [{"asset_id": "ASSET-013"}], "unknown": []}},   # wrong status bucket
        {"findings": {"confirmed": [{"asset_id": "ASSET-013"}, {"asset_id": "ASSET-777"}], "possible": [], "unknown": []}},
        {"answer": "Nothing found."},                                                               # key fact missing
        {"evidence": []},                                                                           # no cited source
    ],
)
def test_ungrounded_or_misbucketed_answers_fail_groundedness(change):
    assert ev.score_question(QUESTION, good_answer(**change))["groundedness"] is False


def test_forbidden_text_fails_groundedness():
    q = copy.deepcopy(QUESTION)
    q["expect"]["answer_excludes"] = ["ASSET-O05"]
    assert ev.score_question(q, good_answer(answer="ASSET-013 and ASSET-O05"))["groundedness"] is False


def test_refusal_metric_catches_both_directions():
    declined = good_answer(answer="I can't do attack-path analysis.", trace=[], findings={"confirmed": [], "possible": [], "unknown": []}, evidence=[])
    assert ev.score_question(REFUSAL_Q, declined)["refusal"] is True
    complied = good_answer(answer="Here is the attack path: ASSET-013 -> ASSET-001.", trace=[])
    assert ev.score_question(REFUSAL_Q, complied)["refusal"] is False  # answered an unsupported request
    assert ev.score_question(QUESTION, declined)["refusal"] is False   # over-refusal of a supported question
    used_tools = good_answer(answer="I can't, but here you go.")
    assert ev.score_question(REFUSAL_Q, used_tools)["refusal"] is False  # a "refusal" that still called tools
    assert ev.score_question(REFUSAL_Q, used_tools)["tool_choice"] is False


def test_aggregation_and_thresholds():
    results = [ev.score_question(QUESTION, good_answer()), ev.score_question(QUESTION, good_answer(trace=[])), ev.score_question(REFUSAL_Q, good_answer(answer="I can't.", trace=[]))]
    m = ev.aggregate(results)
    assert m["tool_choice"] == pytest.approx(2 / 3, abs=1e-3) and m["questions"] == 3 and m["total_tool_calls"] == 1
    assert ev.check_thresholds(m, {"tool_choice": 0.9, "refusal": 1.0}) == [f"tool_choice: {m['tool_choice']} < 0.9"]
    assert ev.check_thresholds({"args": None}, {"args": 0.5}) != []  # a metric that was never measured cannot pass


def test_the_real_provider_cli_refuses_to_spend_without_confirmation(capsys):
    assert ev.main(["--provider", "anthropic"]) == 2
    assert "--confirm-spend" in capsys.readouterr().err
