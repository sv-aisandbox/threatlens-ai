"""Tenant-filtered lookup: which of a tenant's assets are affected by a CVE.

The query always starts from a tenant-filtered Asset (ADR 0002). tenant_id must come from trusted
server context, never from model or tool input. All values are passed as parameters.
"""

from collections.abc import Iterable
from typing import Any

from neo4j import Driver

MATCH_STATUSES = frozenset({"confirmed", "possible", "not_affected", "unknown"})
# `not_affected` is excluded unless explicitly requested; `unknown` is surfaced, never treated as affected.
DEFAULT_STATUSES = ("confirmed", "possible", "unknown")
MAX_LIMIT = 500
MAX_EVIDENCE_PER_ROW = 5

_QUERY = """
MATCH (a:Asset {tenant_id: $tenant_id})-[r:RUNS]->(s:Software)-[m:AFFECTED_BY]->(v:Vulnerability {cve_id: $cve_id})
WHERE r.tenant_id = $tenant_id AND m.match_status IN $statuses
WITH a, s, m, v
ORDER BY a.asset_id, s.software_id
LIMIT $limit
OPTIONAL MATCH (e:Evidence)-[:SUPPORTS]->(v)
WITH a, s, m, v, collect(DISTINCT {
    evidence_id: e.evidence_id,
    source_name: e.source_name,
    source_url: e.source_url,
    collected_at: e.collected_at
}) AS evidence
RETURN
    a.asset_id AS asset_id,
    a.name AS asset_name,
    a.tenant_id AS tenant_id,
    a.environment AS environment,
    a.criticality AS criticality,
    a.internet_exposed AS internet_exposed,
    {software_id: s.software_id, vendor: s.vendor, product: s.product, version: s.version, cpe: s.cpe} AS software,
    v.cve_id AS cve_id,
    v.cvss_score AS cvss_score,
    v.severity AS severity,
    m.match_status AS match_status,
    m.match_reason AS match_reason,
    m.matched_by AS matched_by,
    m.matched_at AS matched_at,
    m.source_ref AS source_ref,
    evidence
ORDER BY asset_id, software.software_id
"""


def get_affected_assets(
    driver: Driver,
    tenant_id: str,
    cve_id: str,
    statuses: Iterable[str] = DEFAULT_STATUSES,
    limit: int = 100,
) -> list[dict[str, Any]]:
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("tenant_id is required")
    if not isinstance(cve_id, str) or not cve_id:
        raise ValueError("cve_id is required")
    status_list = list(statuses)
    if not status_list or not set(status_list) <= MATCH_STATUSES:
        raise ValueError(f"statuses must be a non-empty subset of {sorted(MATCH_STATUSES)}")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an integer between 1 and {MAX_LIMIT}")

    with driver.session() as session:
        result = session.run(
            _QUERY, tenant_id=tenant_id, cve_id=cve_id, statuses=status_list, limit=limit
        )
        rows = [record.data() for record in result]
    for row in rows:
        row["evidence"] = [e for e in row["evidence"] if e["evidence_id"] is not None][
            :MAX_EVIDENCE_PER_ROW
        ]
    return rows
