"""Evaluation starter for the analyst (roadmap task 7.8).

Scores tool choice, arguments, groundedness and refusals of unsupported requests over `tests/evaluation/questions.json`.
CI runs it with the deterministic mock provider (it checks the pipeline, not model quality). A real-provider run is
manual and spends money:

    uv run python -m agent.evaluation --provider anthropic --confirm-spend
"""

import argparse
import asyncio
import json
import re
import sys
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from agent.agent import AnalystAgent, Caller
from app.config import REPO_ROOT

EVAL_DIR = REPO_ROOT / "tests" / "evaluation"
REFUSAL_MARKERS = re.compile(
    r"can't|cannot|can not|unable to|not able to|not available|not supported|won't|will not|read-only|outside (of )?(my|the)|"
    r"only answer about your own|not something i can",
    re.IGNORECASE,
)
METRICS = ("tool_choice", "args", "groundedness", "refusal")


def load_questions(path: Path | None = None) -> dict[str, Any]:
    return json.loads((path or EVAL_DIR / "questions.json").read_text(encoding="utf-8"))


def load_thresholds(kind: str) -> dict[str, float]:
    return json.loads((EVAL_DIR / "thresholds.json").read_text(encoding="utf-8"))[kind]


def looks_like_refusal(text: str) -> bool:
    return bool(REFUSAL_MARKERS.search(text or ""))


def _executed(answer: dict[str, Any]) -> list[dict[str, Any]]:
    return [t for t in answer["trace"] if not t["outcome"].startswith("refused")]


def _args_match(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    for key, want in expected.items():
        if key not in actual:
            return False
        got = actual[key]
        if isinstance(want, float) or isinstance(got, float):
            if not isinstance(got, (int, float)) or abs(float(got) - float(want)) > 1e-9:
                return False
        elif got != want:
            return False
    return True


def score_question(question: dict[str, Any], answer: dict[str, Any]) -> dict[str, Any]:
    """Per-metric results: True / False, or None when the question does not test that metric."""
    expect = question["expect"]
    executed = _executed(answer)
    called = [t["tool"] for t in executed]
    result: dict[str, Any] = {"id": question["id"], "category": question["category"], "failures": []}

    # tool choice: the expected tools were used, forbidden ones were not, and the call budget was respected
    wanted = set(expect.get("tools", []))
    forbidden = set(expect.get("tools_forbidden", []))
    ok = wanted <= set(called) and not (forbidden & set(called)) and len(called) <= expect.get("max_tool_calls", 3)
    if expect.get("refusal") and called:
        ok = False
    result["tool_choice"] = ok
    if not ok:
        result["failures"].append(f"tool_choice: called {called}, expected {sorted(wanted)} (forbidden {sorted(forbidden)})")

    # arguments: each expectation is a subset of the arguments of some call to that tool
    arg_expectations = expect.get("args")
    if arg_expectations:
        bad = [e for e in arg_expectations if not any(t["tool"] == e["tool"] and _args_match(e["args"], t["args"]) for t in executed)]
        result["args"] = not bad
        if bad:
            result["failures"].append(f"args: no call matched {bad}")
    else:
        result["args"] = None

    # groundedness: nothing unsupported in the narrative, findings as expected, key phrases and sources present
    grounded = bool(answer["grounding"]["ok"])
    problems: list[str] = [] if grounded else [f"ungrounded identifiers {answer['grounding']['ungrounded']}"]
    text = answer["answer"].lower()
    for status, ids in (expect.get("facts") or {}).items():
        got = {f["asset_id"] for f in answer["findings"][status]}
        if got != set(ids):
            problems.append(f"{status} findings {sorted(got)} != {sorted(ids)}")
    for needle in expect.get("answer_contains", []):
        if needle.lower() not in text:
            problems.append(f"answer lacks {needle!r}")
    for needle in expect.get("answer_excludes", []):
        if needle.lower() in text:
            problems.append(f"answer contains forbidden {needle!r}")
    options = expect.get("answer_matches_any")
    if options and not any(o in text for o in options):
        problems.append(f"answer matches none of {options}")
    sources = {e["source_name"] for e in answer["evidence"]}
    for source in expect.get("evidence_sources", []):
        if source not in sources:
            problems.append(f"evidence lacks source {source!r}")
    result["groundedness"] = not problems
    result["failures"].extend(f"groundedness: {p}" for p in problems)

    # refusal: unsupported requests are declined without tools; supported ones are not declined
    expected_refusal = bool(expect.get("refusal", False))
    declined = looks_like_refusal(answer["answer"]) and not called
    result["refusal"] = declined == expected_refusal
    if not result["refusal"]:
        result["failures"].append(f"refusal: expected {expected_refusal}, declined={declined}")

    result["tool_calls"] = len(called)
    result["cost_usd"] = answer["usage"]["cost_usd"]
    return result


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    for name in METRICS:
        scored = [r[name] for r in results if r[name] is not None]
        metrics[name] = round(sum(1 for v in scored if v) / len(scored), 4) if scored else None
    metrics["questions"] = len(results)
    metrics["total_cost_usd"] = round(sum(r["cost_usd"] for r in results), 6)
    metrics["total_tool_calls"] = sum(r["tool_calls"] for r in results)
    return metrics


def check_thresholds(metrics: dict[str, Any], thresholds: dict[str, float]) -> list[str]:
    return [
        f"{name}: {metrics[name]} < {minimum}"
        for name, minimum in thresholds.items()
        if metrics.get(name) is None or metrics[name] < minimum
    ]


async def run_evaluation(
    agent: AnalystAgent, questions: dict[str, Any], caller_for: Callable[[str], Caller] | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    tenant = questions.get("tenant", "TENANT-DEMO")

    def default_caller(qid: str) -> Caller:
        return Caller(subject=f"eval-{qid}", tenant_id=tenant, roles=frozenset({"SECURITY_ANALYST"}), correlation_id=str(uuid.uuid4()))

    results = []
    for q in questions["questions"]:
        answer = await agent.ask(q["question"], (caller_for or default_caller)(q["id"]))
        results.append(score_question(q, answer))
    return results, aggregate(results)


def format_report(results: list[dict[str, Any]], metrics: dict[str, Any], problems: list[str]) -> str:
    lines = [f"{'id':<5}{'category':<22}{'tools':<7}{'args':<7}{'ground':<8}{'refusal':<8}"]
    mark = {True: "ok", False: "FAIL", None: "-"}
    for r in results:
        lines.append(f"{r['id']:<5}{r['category']:<22}{mark[r['tool_choice']]:<7}{mark[r['args']]:<7}{mark[r['groundedness']]:<8}{mark[r['refusal']]:<8}")
        lines.extend(f"      {f}" for f in r["failures"])
    lines.append("")
    lines.append("  ".join(f"{k}={metrics[k]}" for k in (*METRICS, "total_tool_calls", "total_cost_usd")))
    lines.append("PASS" if not problems else "BELOW THRESHOLD: " + "; ".join(problems))
    return "\n".join(lines)


def main(argv: list[str] | None = None, runner: Callable[..., Awaitable[Any]] = run_evaluation) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the ThreatLens analyst against the starter question set.")
    parser.add_argument("--provider", choices=["mock", "anthropic"], default="mock")
    parser.add_argument("--confirm-spend", action="store_true", help="required for a real provider: the run spends money")
    parser.add_argument("--json", type=Path, help="write the full results to this file")
    args = parser.parse_args(argv)
    if args.provider != "mock" and not args.confirm_spend:
        print("A real-provider run calls the paid model API. Re-run with --confirm-spend to proceed.", file=sys.stderr)
        return 2

    import os

    import psycopg

    from agent.factory import build_agent
    from app.config import get_driver, pg_conninfo

    os.environ["MODEL_PROVIDER"] = args.provider
    driver = get_driver()
    try:
        agent = build_agent(driver, lambda: psycopg.connect(pg_conninfo()))
        results, metrics = asyncio.run(runner(agent, load_questions()))
    finally:
        driver.close()
    problems = check_thresholds(metrics, load_thresholds("mock" if args.provider == "mock" else "real"))
    print(format_report(results, metrics, problems))
    if args.json:
        args.json.write_text(json.dumps({"metrics": metrics, "results": results}, indent=2), encoding="utf-8")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
