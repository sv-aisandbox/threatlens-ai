"""Tenant-scoped asset queries. Every query starts from `Asset {tenant_id: $tenant_id}` (ADR 0002) and any
installation edge is also checked against the tenant. `tenant_id` must come from trusted context."""

import re
from typing import Any

from neo4j import Driver

MAX_LIMIT = 100
MAX_FINDINGS_PER_SOFTWARE = 25
ENVIRONMENTS = frozenset({"production", "staging", "development"})
CRITICALITIES = frozenset({"critical", "high", "medium", "low"})
FINDING_STATUSES = ("confirmed", "possible", "unknown")
ASSET_ID_RE = re.compile(r"^ASSET-[A-Z0-9-]{1,40}$")

_ASSET_FIELDS = """
    a.asset_id AS asset_id, a.name AS name, a.asset_type AS asset_type, a.environment AS environment,
    a.criticality AS criticality, a.internet_exposed AS internet_exposed, a.inventory_imported_at AS inventory_imported_at
"""

_SEARCH = f"""
MATCH (a:Asset {{tenant_id: $tenant_id}})
WHERE ($q IS NULL OR toLower(a.name) CONTAINS toLower($q) OR a.asset_id = $q_upper)
  AND ($environment IS NULL OR a.environment = $environment)
  AND ($criticality IS NULL OR a.criticality = $criticality)
  AND ($internet_exposed IS NULL OR a.internet_exposed = $internet_exposed)
RETURN {_ASSET_FIELDS}
ORDER BY a.asset_id
LIMIT $fetch
"""

_DETAILS = f"""
MATCH (a:Asset {{tenant_id: $tenant_id, asset_id: $asset_id}})
OPTIONAL MATCH (a)-[r:RUNS]->(s:Software) WHERE r.tenant_id = $tenant_id
WITH a, count(DISTINCT s) AS software_count
RETURN {_ASSET_FIELDS}, software_count
"""

_EXPOSURE = """
MATCH (a:Asset {tenant_id: $tenant_id, asset_id: $asset_id})-[r:RUNS]->(:Software)-[m:AFFECTED_BY]->(v:Vulnerability)
WHERE r.tenant_id = $tenant_id AND m.match_status = 'confirmed'
RETURN count(DISTINCT v) AS confirmed
"""

_SOFTWARE = """
MATCH (a:Asset {tenant_id: $tenant_id, asset_id: $asset_id})-[r:RUNS]->(s:Software)
WHERE r.tenant_id = $tenant_id
OPTIONAL MATCH (s)-[m:AFFECTED_BY]->(v:Vulnerability) WHERE m.match_status IN $statuses
WITH s, m, v ORDER BY v.cve_id
RETURN s.software_id AS software_id, s.vendor AS vendor, s.product AS product, s.version AS version, s.cpe AS cpe,
       collect(CASE WHEN v IS NULL THEN NULL ELSE {
           cve_id: v.cve_id, match_status: m.match_status, match_reason: m.match_reason, matched_by: m.matched_by,
           matched_at: m.matched_at, source_ref: m.source_ref, severity: v.severity, cvss_score: v.cvss_score,
           kev_listed: coalesce(v.kev_listed, false)
       } END) AS findings
ORDER BY s.software_id
"""

_CRITICAL = f"""
MATCH (a:Asset {{tenant_id: $tenant_id}})
WHERE a.criticality = 'critical' AND ($environment IS NULL OR a.environment = $environment)
OPTIONAL MATCH (a)-[r:RUNS]->(:Software)-[m:AFFECTED_BY]->(v:Vulnerability)
WHERE r.tenant_id = $tenant_id AND m.match_status = 'confirmed'
WITH a, count(DISTINCT v) AS confirmed_vulnerabilities
RETURN {_ASSET_FIELDS}, confirmed_vulnerabilities
ORDER BY confirmed_vulnerabilities DESC, a.internet_exposed DESC, a.asset_id
LIMIT $fetch
"""


def _check_tenant(tenant_id: str) -> None:
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("tenant_id is required")


def _check_limit(limit: int) -> None:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an integer between 1 and {MAX_LIMIT}")


def _check_environment(environment: str | None) -> None:
    if environment is not None and environment not in ENVIRONMENTS:
        raise ValueError(f"environment must be one of {sorted(ENVIRONMENTS)}")


def _check_asset_id(asset_id: str) -> None:
    if not isinstance(asset_id, str) or not ASSET_ID_RE.fullmatch(asset_id):
        raise ValueError("asset_id is not a valid asset identifier")


def _bounded(rows: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    return {"results": rows[:limit], "truncated": len(rows) > limit}


def search_assets(
    driver: Driver,
    tenant_id: str,
    query: str | None = None,
    environment: str | None = None,
    criticality: str | None = None,
    internet_exposed: bool | None = None,
    limit: int = 25,
) -> dict[str, Any]:
    _check_tenant(tenant_id)
    _check_limit(limit)
    _check_environment(environment)
    if criticality is not None and criticality not in CRITICALITIES:
        raise ValueError(f"criticality must be one of {sorted(CRITICALITIES)}")
    if query is not None and not 1 <= len(query) <= 100:
        raise ValueError("query must be 1 to 100 characters")
    with driver.session() as session:
        rows = [
            r.data()
            for r in session.run(
                _SEARCH, tenant_id=tenant_id, q=query, q_upper=query.upper() if query else None,
                environment=environment, criticality=criticality, internet_exposed=internet_exposed, fetch=limit + 1,
            )
        ]
    return _bounded(rows, limit)


def get_asset(driver: Driver, tenant_id: str, asset_id: str) -> dict[str, Any] | None:
    """Asset details, or None. An asset of another tenant is indistinguishable from a missing one."""
    _check_tenant(tenant_id)
    _check_asset_id(asset_id)
    with driver.session() as session:
        record = session.run(_DETAILS, tenant_id=tenant_id, asset_id=asset_id).single()
        if record is None:
            return None
        asset = record.data()
        asset["confirmed_vulnerabilities"] = session.run(
            _EXPOSURE, tenant_id=tenant_id, asset_id=asset_id
        ).single()["confirmed"]
    return asset


def get_asset_software(
    driver: Driver, tenant_id: str, asset_id: str, statuses: tuple[str, ...] = FINDING_STATUSES
) -> dict[str, Any] | None:
    """Installed software with its matched vulnerabilities. None when the asset is not in the tenant."""
    _check_tenant(tenant_id)
    _check_asset_id(asset_id)
    if not statuses or not set(statuses) <= {"confirmed", "possible", "not_affected", "unknown"}:
        raise ValueError("invalid statuses")
    if get_asset(driver, tenant_id, asset_id) is None:
        return None
    with driver.session() as session:
        rows = [
            r.data()
            for r in session.run(_SOFTWARE, tenant_id=tenant_id, asset_id=asset_id, statuses=list(statuses))
        ]
    truncated = False
    for row in rows:
        if len(row["findings"]) > MAX_FINDINGS_PER_SOFTWARE:
            row["findings"] = row["findings"][:MAX_FINDINGS_PER_SOFTWARE]
            truncated = True
    return {"asset_id": asset_id, "software": rows, "truncated": truncated}


def get_critical_assets(
    driver: Driver, tenant_id: str, environment: str | None = None, limit: int = 25
) -> dict[str, Any]:
    _check_tenant(tenant_id)
    _check_limit(limit)
    _check_environment(environment)
    with driver.session() as session:
        rows = [
            r.data()
            for r in session.run(_CRITICAL, tenant_id=tenant_id, environment=environment, fetch=limit + 1)
        ]
    return _bounded(rows, limit)
