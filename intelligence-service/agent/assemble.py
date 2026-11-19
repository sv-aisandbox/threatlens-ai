"""Builds the structured parts of an answer from tool results. The model never writes these (ADR 0007)."""

from typing import Any

STATUSES = ("confirmed", "possible", "unknown")


def _evidence_ids(evidence: list[dict[str, Any]] | None) -> list[str]:
    return [e["evidence_id"] for e in evidence or [] if e.get("evidence_id")]


def build_findings(results: list[tuple[str, dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Asset-vulnerability matches grouped by status. 'not_affected' is not a finding."""
    groups: dict[str, list[dict[str, Any]]] = {s: [] for s in STATUSES}
    seen: set[tuple[str, str, str]] = set()

    def add(finding: dict[str, Any]) -> None:
        key = (finding["asset_id"], finding["cve_id"], finding["match_status"])
        if finding["match_status"] in groups and key not in seen:
            seen.add(key)
            groups[finding["match_status"]].append(finding)

    for tool, body in results:
        if tool == "get_affected_assets":
            for row in body.get("results", []):
                sw = row.get("software") or {}
                add({
                    "asset_id": row["asset_id"], "asset_name": row.get("asset_name"), "environment": row.get("environment"),
                    "criticality": row.get("criticality"), "internet_exposed": row.get("internet_exposed"),
                    "cve_id": row["cve_id"], "software": {k: sw.get(k) for k in ("vendor", "product", "version")},
                    "match_status": row["match_status"], "reason": row.get("match_reason"),
                    "matched_at": row.get("matched_at"), "evidence_ids": _evidence_ids(row.get("evidence")),
                })
        elif tool == "get_asset_software":
            for sw in body.get("software", []):
                for f in sw.get("findings", []):
                    add({
                        "asset_id": body["asset_id"], "asset_name": None, "environment": None, "criticality": None,
                        "internet_exposed": None, "cve_id": f["cve_id"],
                        "software": {k: sw.get(k) for k in ("vendor", "product", "version")},
                        "match_status": f["match_status"], "reason": f.get("match_reason"),
                        "matched_at": f.get("matched_at"), "evidence_ids": [f["source_ref"]] if f.get("source_ref") else [],
                    })
    return groups


def collect_evidence(results: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """De-duplicated evidence with source, URL and collection time."""
    found: dict[str, dict[str, Any]] = {}

    def add(e: dict[str, Any]) -> None:
        eid = e.get("evidence_id")
        if not eid:
            return
        item = {k: e.get(k) for k in ("evidence_id", "source_name", "source_url", "collected_at", "content_hash")}
        current = found.get(eid)
        if current is None or (item.get("content_hash") and not current.get("content_hash")):
            found[eid] = item

    for tool, body in results:
        if tool == "get_affected_assets":
            for row in body.get("results", []):
                for e in row.get("evidence") or []:
                    add(e)
        elif tool == "get_vulnerability_details":
            for e in (body.get("vulnerability") or {}).get("evidence") or []:
                add(e)
        elif tool == "get_vulnerability_evidence":
            for e in body.get("evidence") or []:
                add(e)
    return [found[k] for k in sorted(found)]


def merge_freshness(results: list[tuple[str, dict[str, Any]]]) -> tuple[dict[str, Any] | None, list[str]]:
    freshness = None
    warnings: list[str] = []
    for _, body in results:
        if body.get("freshness"):
            freshness = body["freshness"]
        for w in body.get("warnings") or []:
            if w not in warnings:
                warnings.append(w)
    return freshness, warnings


def trusted_text(results: list[tuple[str, dict[str, Any]]]) -> str:
    """Identifier-bearing text from tool results with every untrusted text field removed.

    Used to widen tool discovery and to build the grounding allow-list, so hostile text inside a result can
    neither summon a tool nor make an invented identifier look grounded.
    """
    import json

    from agent.guard import strip_untrusted

    return json.dumps([strip_untrusted(body) for _, body in results], default=str, ensure_ascii=False)


def found_identifiers(results: list[tuple[str, dict[str, Any]]]) -> str:
    """Only the identifiers (CVE, asset, evidence) found in trusted fields: the sole input to discovery expansion.

    Field names and values are deliberately left out, so structure words such as 'vulnerability' or 'severity'
    cannot pull in unrelated tools.
    """
    from agent.guard import identifiers

    return " ".join(sorted(identifiers(trusted_text(results))))
