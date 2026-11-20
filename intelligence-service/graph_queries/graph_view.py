"""Graph data for one CVE: asset -> software -> CVE, tenant-scoped (ADR 0002). Feeds the Cytoscape view.

Software and vulnerabilities are global, but they are only reached through the tenant's own assets, so no other
tenant's installation can appear. Match status is carried on the software -> CVE edge; `not_affected` is hidden
unless requested.
"""

from typing import Any

from neo4j import Driver

MAX_ASSETS = 60
DEFAULT_STATUSES = ("confirmed", "possible", "unknown")
ALL_STATUSES = frozenset({"confirmed", "possible", "not_affected", "unknown"})

_QUERY = """
MATCH (a:Asset {tenant_id: $tenant_id})-[r:RUNS]->(s:Software)-[m:AFFECTED_BY]->(v:Vulnerability {cve_id: $cve_id})
WHERE r.tenant_id = $tenant_id AND m.match_status IN $statuses
RETURN a.asset_id AS asset_id, a.name AS asset_name, a.environment AS environment, a.criticality AS criticality,
       a.internet_exposed AS internet_exposed,
       s.software_id AS software_id, s.vendor AS vendor, s.product AS product, s.version AS version,
       m.match_status AS match_status, m.match_reason AS match_reason
ORDER BY a.asset_id, s.software_id
LIMIT $fetch
"""
_VULN = """
MATCH (v:Vulnerability {cve_id: $cve_id})
RETURN v.cve_id AS cve_id, v.severity AS severity, v.cvss_score AS cvss_score, coalesce(v.kev_listed, false) AS kev_listed
"""


def get_vulnerability_graph(
    driver: Driver, tenant_id: str, cve_id: str, include_not_affected: bool = False, limit: int = MAX_ASSETS
) -> dict[str, Any] | None:
    """{"nodes", "edges", "truncated"} or None when the CVE is unknown."""
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("tenant_id is required")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_ASSETS:
        raise ValueError(f"limit must be an integer between 1 and {MAX_ASSETS}")
    statuses = list(ALL_STATUSES if include_not_affected else DEFAULT_STATUSES)
    with driver.session() as session:
        vuln = session.run(_VULN, cve_id=cve_id).single()
        if vuln is None:
            return None
        rows = [r.data() for r in session.run(_QUERY, tenant_id=tenant_id, cve_id=cve_id, statuses=statuses, fetch=limit + 1)]

    truncated = len(rows) > limit
    rows = rows[:limit]
    nodes: dict[str, dict[str, Any]] = {
        cve_id: {"id": cve_id, "type": "vulnerability", "label": cve_id, "severity": vuln["severity"],
                 "cvss_score": vuln["cvss_score"], "kev_listed": vuln["kev_listed"]}
    }
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        asset, software = row["asset_id"], row["software_id"]
        nodes.setdefault(asset, {
            "id": asset, "type": "asset", "label": row["asset_name"], "environment": row["environment"],
            "criticality": row["criticality"], "internet_exposed": row["internet_exposed"],
        })
        nodes.setdefault(software, {
            "id": software, "type": "software", "label": f"{row['product']} {row['version'] or '(version unknown)'}",
            "vendor": row["vendor"], "product": row["product"], "version": row["version"],
        })
        edges[(asset, software, "RUNS")] = {"source": asset, "target": software, "type": "RUNS"}
        edges[(software, cve_id, "AFFECTED_BY")] = {
            "source": software, "target": cve_id, "type": "AFFECTED_BY",
            "match_status": row["match_status"], "reason": row["match_reason"],
        }
    return {"cve_id": cve_id, "nodes": list(nodes.values()), "edges": list(edges.values()), "truncated": truncated}
