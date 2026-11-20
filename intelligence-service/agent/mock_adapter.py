"""Deterministic mock provider for tests and CI (ADR 0007).

A small rule-based policy standing in for the model: it picks tools from the question, reads the tool results that
are already in the history, and writes a narrative using only identifiers those results contain. It exercises the
whole pipeline but says nothing about real model quality, which is measured manually with the real adapter.
"""

import json
import re
from typing import Any

from agent.models import ModelTurn, ToolCall, Usage
from agent.registry import TENANT_RE, detect_entities

_REFUSE_ATTACK = re.compile(r"attack path|lateral movement|blast radius|path(s)? to (our )?(critical|domain)", re.I)
_REFUSE_EXPLOIT = re.compile(r"(write|create|give|generate|provide).{0,30}(exploit|payload|poc|malware|ransomware)|weaponi[sz]e", re.I)
_REFUSE_ACTION = re.compile(
    r"\b(apply|install|deploy|roll ?out|shut ?down|isolate|quarantine|disable|delete|remove|reboot|restart|"
    r"modify|rewrite|change the|update the|block the)\b", re.I)
_REFUSE_SECRETS = re.compile(
    r"system prompt|api key|password|secret|credential|ignore (all |any )?(the )?(previous|prior|above)|reveal your|jailbreak", re.I)
_REFUSE_SCOPE = re.compile(r"other tenant|another tenant|other organi[sz]ation|another organi[sz]ation|all tenants|every (customer|tenant)|other customers", re.I)

REFUSAL_TEXT = {
    "attack": "I can't do attack-path analysis: that capability is not available in this version. I can show affected assets, software and evidence.",
    "exploit": "I can't help with that. ThreatLens is a defensive, read-only tool.",
    "action": "I can't make changes: this analyst is read-only. I can show exposure and evidence to help you decide.",
    "secrets": "I can't help with that request.",
    "scope": "I can only answer about your own organization's data. I can't access other tenants or organizations.",
    "nodata": "I can't answer that with the data and tools available here. I can look up a CVE, an asset, installed software, critical assets or evidence.",
}


def _estimate_tokens(obj: Any) -> int:
    return max(1, len(json.dumps(obj, default=str)) // 4)


def _question(messages: list[dict[str, Any]]) -> str:
    first = messages[0]["content"]
    return first if isinstance(first, str) else " ".join(b.get("text", "") for b in first if isinstance(b, dict))


def _history(messages: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any], dict[str, Any] | None]]:
    """[(tool name, arguments, parsed result body)] in call order."""
    calls: dict[str, tuple[str, dict[str, Any]]] = {}
    order: list[str] = []
    results: dict[str, dict[str, Any] | None] = {}
    for m in messages[1:]:
        content = m["content"]
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                calls[block["id"]] = (block["name"], block.get("input", {}))
                order.append(block["id"])
            elif block.get("type") == "tool_result":
                raw = block.get("content")
                text = raw if isinstance(raw, str) else "".join(b.get("text", "") for b in raw or [])
                try:
                    results[block["tool_use_id"]] = json.loads(text)
                except ValueError:
                    results[block["tool_use_id"]] = None
    return [(calls[i][0], calls[i][1], results.get(i)) for i in order]


def _refusal(question: str) -> str | None:
    if _REFUSE_SCOPE.search(question) or (
        TENANT_RE.search(question) and not re.search(r"\byour|my|our\b", question, re.I)
    ):
        return "scope"
    if _REFUSE_SECRETS.search(question):
        return "secrets"
    if _REFUSE_EXPLOIT.search(question):
        return "exploit"
    if _REFUSE_ATTACK.search(question):
        return "attack"
    if _REFUSE_ACTION.search(question):
        return "action"
    return None


def _wanted_calls(question: str, history: list[tuple[str, dict[str, Any], dict[str, Any] | None]]) -> list[tuple[str, dict[str, Any]]]:
    q = question.lower()
    ent = detect_entities(question)
    env = {"environment": ent.environment} if ent.environment else {}
    plan: list[tuple[str, dict[str, Any]]] = []

    if ent.cves:
        cve = ent.cves[0]
        if re.search(r"evidence|source|proof|cite|provenance", q):
            plan.append(("get_vulnerability_evidence", {"cve_id": cve}))
        elif re.search(r"affect|expos|impact|running|vulnerable|which of|our |my |assets|servers|investigate|how sure", q):
            plan.append(("get_affected_assets", {"cve_id": cve, **env}))
            if re.search(r"kev|exploited|cvss|severity|score|how bad|ransomware", q):
                plan.append(("get_vulnerability_details", {"cve_id": cve}))
        else:
            plan.append(("get_vulnerability_details", {"cve_id": cve}))
        return plan

    if ent.assets:
        asset = ent.assets[0]
        if re.search(r"software|install|running|version|vulnerab|finding|exposed|exposure", q):
            plan.append(("get_asset_software", {"asset_id": asset}))
        else:
            plan.append(("get_asset_details", {"asset_id": asset}))
        return plan

    if re.search(r"critical assets|crown jewels|most exposed|worry|riskiest|most at risk", q):
        return [("get_critical_assets", {**env})]

    if re.search(r"investigat", q):
        noun = re.search(r"\b([a-z0-9]+)[ -](?:server|host|asset|api|database|box)\b", q)
        search_args: dict[str, Any] = {"query": noun.group(1)} if noun else {}
        search_args.update(env)
        plan.append(("search_assets", search_args))
        found = next((b for n, _, b in history if n == "search_assets" and b and not b.get("error")), None)
        if found and found.get("results"):
            plan.append(("get_asset_software", {"asset_id": found["results"][0]["asset_id"]}))
        return plan

    if re.search(r"vulnerabilit|kev|known exploited|cvss", q):
        args: dict[str, Any] = {}
        if re.search(r"kev|known exploited|exploited", q):
            args["kev_only"] = True
        score = re.search(r"cvss\s*(?:>=|≥|above|over|at least|of|score of)?\s*(\d+(?:\.\d+)?)", q)
        if score:
            args["min_cvss"] = float(score.group(1))
        if "log4j" in q:
            args["query"] = "log4j"
        return [("search_vulnerabilities", args)]

    if re.search(r"assets|servers|hosts", q):
        args = dict(env)
        if re.search(r"internet[- ]exposed|public[- ]facing|exposed to the internet", q):
            args["internet_exposed"] = True
        crit = re.search(r"\b(critical|high|medium|low)\b[ -](?:criticality|assets|servers)", q)
        if crit:
            args["criticality"] = crit.group(1)
        name = re.search(r"(?:named|called|name contains|containing)\s+['\"]?([\w-]+)", q)
        if name:
            args["query"] = name.group(1)
        return [("search_assets", args)]
    return plan


def _summarize(history: list[tuple[str, dict[str, Any], dict[str, Any] | None]]) -> str:
    lines: list[str] = []
    for name, args, body in history:
        if body is None:
            lines.append(f"The {name} result could not be read.")
            continue
        if "error" in body:
            code = body["error"]["code"]
            lines.append("No matching record was found." if code == "not_found" else f"The lookup failed ({code}).")
            continue
        if name == "get_affected_assets":
            by: dict[str, list[dict[str, Any]]] = {"confirmed": [], "possible": [], "unknown": []}
            for row in body["results"]:
                by.setdefault(row["match_status"], []).append(row)
            lines.append(f"For {body['cve_id']}: {len(by['confirmed'])} confirmed, {len(by['possible'])} possible, {len(by['unknown'])} unknown.")
            for status, label in (("confirmed", "Confirmed exposure"), ("possible", "Possible, needs verification"), ("unknown", "Unknown, version not recorded or comparable")):
                if by[status]:
                    items = ", ".join(f"{r['asset_id']} ({r['asset_name']}, {r['environment']})" for r in by[status])
                    lines.append(f"{label}: {items}.")
            if not body["results"]:
                lines.append("No affected assets were found, which is not proof of safety." + ("" if body["cve_known"] else " This CVE is not in the local database."))
        elif name == "get_vulnerability_details":
            v = body["vulnerability"]
            kev = f"on the CISA KEV list (added {v['kev_date_added']}, due {v['kev_due_date']})" if v["kev_listed"] else "not on the CISA KEV list"
            lines.append(f"{v['cve_id']}: CVSS {v['cvss_score']} ({v['severity']}), {kev}.")
        elif name == "get_vulnerability_evidence":
            sources = ", ".join(f"{e['source_name']} (collected {e['collected_at']})" for e in body["evidence"])
            lines.append(f"Evidence for {body['cve_id']}: {sources}.")
        elif name == "search_vulnerabilities":
            ids = ", ".join(r["cve_id"] for r in body["results"][:8]) or "none"
            lines.append(f"Matching vulnerabilities: {ids}.")
        elif name == "search_assets":
            ids = ", ".join(f"{r['asset_id']} ({r['name']})" for r in body["results"][:10]) or "none"
            lines.append(f"Matching assets: {ids}.")
        elif name == "get_asset_details":
            a = body["asset"]
            lines.append(f"{a['asset_id']} ({a['name']}): {a['environment']}, {a['criticality']} criticality, {a['software_count']} software item(s), {a['confirmed_vulnerabilities']} confirmed vulnerability(ies).")
        elif name == "get_asset_software":
            for sw in body["software"]:
                found = "; ".join(f"{f['cve_id']} {f['match_status']}" for f in sw["findings"]) or "no matched vulnerabilities"
                lines.append(f"{body['asset_id']} runs {sw['product']} {sw['version'] or '(version unknown)'}: {found}.")
        elif name == "get_critical_assets":
            items = ", ".join(f"{r['asset_id']} ({r['confirmed_vulnerabilities']} confirmed)" for r in body["results"]) or "none"
            lines.append(f"Critical assets, most exposed first: {items}.")
        for warning in body.get("warnings", []):
            lines.append(f"Note: {warning}")
    return " ".join(lines) if lines else REFUSAL_TEXT["nodata"]


class MockAdapter:
    provider = "mock"
    model = "mock-analyst-1"

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurn:
        question = _question(messages)
        history = _history(messages)
        offered = {t["name"] for t in tools}
        usage = Usage(input_tokens=_estimate_tokens(messages) + _estimate_tokens(tools))

        reason = _refusal(question)
        if reason and not history:
            return self._final(REFUSAL_TEXT[reason], usage)

        done = {(n, json.dumps(a, sort_keys=True)) for n, a, _ in history}
        for name, args in _wanted_calls(question, history):
            if (name, json.dumps(args, sort_keys=True)) in done or name not in offered:
                continue
            call = ToolCall(id=f"mock_{len(history) + 1}", name=name, input=args)
            usage.output_tokens = _estimate_tokens(args)
            return ModelTurn(
                text="", tool_calls=[call], stop_reason="tool_use", usage=usage, model=self.model,
                assistant_content=[{"type": "tool_use", "id": call.id, "name": name, "input": args}],
            )
        text = _summarize(history) if history else REFUSAL_TEXT["nodata"]
        return self._final(text, usage)

    def _final(self, text: str, usage: Usage) -> ModelTurn:
        usage.output_tokens += _estimate_tokens(text)
        return ModelTurn(
            text=text, tool_calls=[], stop_reason="end_turn", usage=usage, model=self.model,
            assistant_content=[{"type": "text", "text": text}],
        )
