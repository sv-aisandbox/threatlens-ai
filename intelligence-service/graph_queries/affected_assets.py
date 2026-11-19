"""Tenant-filtered lookup: which of a tenant's assets are affected by a CVE.

The query always starts from a tenant-filtered Asset (ADR 0002). tenant_id must come from trusted
server context, never from model or tool input. All values are passed as parameters.
"""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from neo4j import Driver

MATCH_STATUSES = frozenset({"confirmed", "possible", "not_affected", "unknown"})
# `not_affected` is excluded unless explicitly requested; `unknown` is surfaced, never treated as affected.
DEFAULT_STATUSES = ("confirmed", "possible", "unknown")
MAX_LIMIT = 500
MAX_EVIDENCE_PER_ROW = 5
ENVIRONMENTS = frozenset({"production", "staging", "development"})

_QUERY = """
MATCH (a:Asset {tenant_id: $tenant_id})-[r:RUNS]->(s:Software)-[m:AFFECTED_BY]->(v:Vulnerability {cve_id: $cve_id})
WHERE r.tenant_id = $tenant_id AND m.match_status IN $statuses
  AND ($environment IS NULL OR a.environment = $environment)
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
    a.inventory_imported_at AS inventory_imported_at,
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
    environment: str | None = None,
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
    if environment is not None and environment not in ENVIRONMENTS:
        raise ValueError(f"environment must be one of {sorted(ENVIRONMENTS)}")

    with driver.session() as session:
        result = session.run(
            _QUERY, tenant_id=tenant_id, cve_id=cve_id, statuses=status_list, limit=limit,
            environment=environment,
        )
        rows = [record.data() for record in result]
    for row in rows:
        row["evidence"] = [e for e in row["evidence"] if e["evidence_id"] is not None][
            :MAX_EVIDENCE_PER_ROW
        ]
    return rows


STALE_AFTER = timedelta(hours=48)


def get_affected_assets_with_freshness(
    driver: Driver,
    conn: psycopg.Connection,
    tenant_id: str,
    cve_id: str,
    statuses: Iterable[str] = DEFAULT_STATUSES,
    limit: int = 100,
    environment: str | None = None,
    now: datetime | None = None,
    stale_after: timedelta = STALE_AFTER,
) -> dict[str, Any]:
    """Results plus both freshness timestamps (spec 20.3): intelligence sync and inventory import.

    A recent CVE sync does not make an old inventory current, so each is reported and warned on separately.
    """
    from ingestion import source_sync
    from ingestion.inventory_import import latest_import_time

    results = get_affected_assets(driver, tenant_id, cve_id, statuses, limit, environment)
    sources = {r["source_id"]: r for r in source_sync.list_status(conn)}
    now = now or datetime.now(UTC)
    intel = {
        "nvd_last_success_at": (sources.get("nvd") or {}).get("last_success_at"),
        "kev_last_success_at": (sources.get("cisa_kev") or {}).get("last_success_at"),
    }
    inventory_at = latest_import_time(conn, tenant_id)
    if inventory_at is None:  # e.g. the synthetic seed writes the graph without an import record
        with driver.session() as session:
            stamp = session.run(
                "MATCH (a:Asset {tenant_id: $tenant_id}) RETURN max(a.inventory_imported_at) AS at",
                tenant_id=tenant_id,
            ).single()["at"]
        if stamp:
            inventory_at = datetime.fromisoformat(stamp.replace("Z", "+00:00"))

    warnings: list[str] = []
    for label, ts in (("NVD", intel["nvd_last_success_at"]), ("CISA KEV", intel["kev_last_success_at"]),
                      ("Asset inventory", inventory_at)):
        if ts is None:
            warnings.append(f"{label} has never been {'imported' if label.startswith('Asset') else 'synced'}; results may be incomplete.")
        elif now - ts > stale_after:
            warnings.append(f"{label} data is older than {int(stale_after.total_seconds() // 3600)} hours (last: {ts.isoformat()}); results may be stale.")
    return {
        "results": results,
        "freshness": {
            "intelligence": {k: v.isoformat() if v else None for k, v in intel.items()},
            "inventory_last_imported_at": inventory_at.isoformat() if inventory_at else None,
        },
        "warnings": warnings,
    }
