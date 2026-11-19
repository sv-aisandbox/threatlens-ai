"""Writes AFFECTED_BY edges from the pure matcher (ADR 0003).

Only edges with matched_by = MATCHED_BY are created, updated or removed here; edges written by other
actors (the synthetic seed, future scanner evidence) are never overwritten. Unchanged edges keep their
matched_at so reruns are stable.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from neo4j import Driver

from correlation.cpe import normalize_token, parse_cpe23
from correlation.matcher import MATCHED_BY, InstalledSoftware, MatchResult, evaluate

_SOFTWARE_ALL = "MATCH (s:Software) RETURN s.software_id AS id, s.vendor AS vendor, s.product AS product, s.version AS version, s.cpe AS cpe"
_SOFTWARE_SOME = (
    "MATCH (s:Software) WHERE s.software_id IN $ids "
    "RETURN s.software_id AS id, s.vendor AS vendor, s.product AS product, s.version AS version, s.cpe AS cpe"
)
_CANDIDATES = """
MATCH (v:Vulnerability)
WHERE v.configurations_json IS NOT NULL AND v.configurations_json CONTAINS $needle
RETURN v.cve_id AS cve_id, v.configurations_json AS configurations
"""
_EXISTING = """
MATCH (s:Software {software_id: $sid})-[m:AFFECTED_BY]->(v:Vulnerability)
RETURN v.cve_id AS cve_id, m.matched_by AS matched_by, m.match_status AS status,
       m.match_reason AS reason, m.source_ref AS source_ref
"""
_UPSERT = """
UNWIND $rows AS row
MATCH (s:Software {software_id: row.sid}), (v:Vulnerability {cve_id: row.cve_id})
MERGE (s)-[m:AFFECTED_BY]->(v)
SET m.match_status = row.status, m.match_reason = row.reason, m.matched_by = $matched_by,
    m.matched_at = $matched_at, m.source_ref = row.source_ref, m.matched_criteria = row.criteria
"""
_DELETE = """
UNWIND $rows AS row
MATCH (:Software {software_id: row.sid})-[m:AFFECTED_BY {matched_by: $matched_by}]->(:Vulnerability {cve_id: row.cve_id})
DELETE m
"""


@dataclass
class MatchSummary:
    software_considered: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    removed: int = 0
    skipped_foreign: int = 0
    by_status: dict[str, int] | None = None


def _needle(software: InstalledSoftware) -> str | None:
    cpe = parse_cpe23(software.cpe)
    if cpe is not None:
        vendor, product = cpe.vendor, cpe.product
    else:
        vendor, product = normalize_token(software.vendor, vendor=True), normalize_token(software.product)
    return f":{vendor}:{product}:" if vendor and product else None


def run_matching(
    driver: Driver,
    software_ids: list[str] | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> MatchSummary:
    summary = MatchSummary(by_status={})
    matched_at = now().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    with driver.session() as session:
        records = list(session.run(_SOFTWARE_SOME, ids=software_ids) if software_ids is not None else session.run(_SOFTWARE_ALL))
        for rec in records:
            summary.software_considered += 1
            sid = rec["id"]
            software = InstalledSoftware(rec["vendor"] or "", rec["product"] or "", rec["version"], rec["cpe"])
            desired: dict[str, MatchResult] = {}
            needle = _needle(software)
            if needle:
                for cand in session.run(_CANDIDATES, needle=needle):
                    try:
                        configurations = json.loads(cand["configurations"])
                    except ValueError:
                        continue  # unreadable configuration: no edge rather than a guess
                    result = evaluate(software, configurations if isinstance(configurations, list) else [])
                    if result is not None:
                        desired[cand["cve_id"]] = result

            existing = {r["cve_id"]: r for r in session.run(_EXISTING, sid=sid)}
            upserts, deletes = [], []
            for cve_id, result in desired.items():
                source_ref = f"EVID-NVD-{cve_id}"
                row = {"sid": sid, "cve_id": cve_id, "status": result.status, "reason": result.reason,
                       "source_ref": source_ref, "criteria": result.matched_criteria}
                old = existing.get(cve_id)
                if old is None:
                    summary.created += 1
                elif old["matched_by"] != MATCHED_BY:
                    summary.skipped_foreign += 1
                    continue
                elif (old["status"], old["reason"], old["source_ref"]) != (result.status, result.reason, source_ref):
                    summary.updated += 1
                else:
                    summary.unchanged += 1
                    summary.by_status[result.status] = summary.by_status.get(result.status, 0) + 1
                    continue
                summary.by_status[result.status] = summary.by_status.get(result.status, 0) + 1
                upserts.append(row)
            for cve_id, old in existing.items():
                if cve_id not in desired and old["matched_by"] == MATCHED_BY:
                    deletes.append({"sid": sid, "cve_id": cve_id})
                    summary.removed += 1

            if upserts:
                session.execute_write(
                    lambda tx, rows=upserts: tx.run(_UPSERT, rows=rows, matched_by=MATCHED_BY, matched_at=matched_at).consume()
                )
            if deletes:
                session.execute_write(lambda tx, rows=deletes: tx.run(_DELETE, rows=rows, matched_by=MATCHED_BY).consume())
    return summary
