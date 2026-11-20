"""Tenant overview for the dashboard: counts, top exposures and, above all, how fresh the data is (spec 20.3).

Every tenant figure starts from `Asset {tenant_id}` (ADR 0002). Global figures (all CVEs, KEV) are public intelligence.
Nothing here describes stale data as current: each source carries its age and a `stale` flag.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from neo4j import Driver

from ingestion import source_sync
from ingestion.inventory_import import latest_import_time

STALE_AFTER = timedelta(hours=48)
SOURCE_LABELS = {
    "nvd": "NVD (incremental sync)",
    "cisa_kev": "CISA Known Exploited Vulnerabilities",
    "nvd_single_cve": "NVD (single CVE import)",
}
EXPECTED_SOURCES = ("nvd", "cisa_kev")  # shown even when they have never synced

_GLOBAL = """
MATCH (v:Vulnerability)
RETURN count(v) AS total,
       sum(CASE WHEN v.kev_listed = true THEN 1 ELSE 0 END) AS kev,
       sum(CASE WHEN v.cvss_score >= 9.0 THEN 1 ELSE 0 END) AS critical_cvss
"""
_ASSETS = """
MATCH (a:Asset {tenant_id: $tenant_id})
RETURN count(a) AS total, sum(CASE WHEN a.criticality = 'critical' THEN 1 ELSE 0 END) AS critical,
       max(a.inventory_imported_at) AS imported_at
"""
_EXPOSURE = """
MATCH (a:Asset {tenant_id: $tenant_id})-[r:RUNS]->(:Software)-[m:AFFECTED_BY]->(v:Vulnerability)
WHERE r.tenant_id = $tenant_id AND m.match_status IN ['confirmed', 'possible', 'unknown']
WITH m.match_status AS status, a, v
RETURN status, count(DISTINCT a.asset_id + '|' + v.cve_id) AS pairs, count(DISTINCT v.cve_id) AS cves
"""
_AFFECTED_CRITICAL = """
MATCH (a:Asset {tenant_id: $tenant_id, criticality: 'critical'})-[r:RUNS]->(:Software)-[m:AFFECTED_BY {match_status: 'confirmed'}]->(:Vulnerability)
WHERE r.tenant_id = $tenant_id
RETURN count(DISTINCT a.asset_id) AS affected
"""
_TOP = """
MATCH (a:Asset {tenant_id: $tenant_id})-[r:RUNS]->(:Software)-[m:AFFECTED_BY {match_status: 'confirmed'}]->(v:Vulnerability)
WHERE r.tenant_id = $tenant_id
WITH v, count(DISTINCT a.asset_id) AS assets
RETURN v.cve_id AS cve_id, v.cvss_score AS cvss_score, v.severity AS severity,
       coalesce(v.kev_listed, false) AS kev_listed, v.synthetic IS NOT NULL AS synthetic, assets AS confirmed_assets
ORDER BY confirmed_assets DESC, kev_listed DESC, coalesce(v.cvss_score, -1) DESC, cve_id
LIMIT 5
"""


def _age(ts: datetime | None, now: datetime) -> tuple[float | None, bool]:
    """(age in hours, stale?). A source that never succeeded is stale by definition."""
    if ts is None:
        return None, True
    return round((now - ts).total_seconds() / 3600, 1), (now - ts) > STALE_AFTER


def get_overview(driver: Driver, conn: psycopg.Connection, tenant_id: str, now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("tenant_id is required")
    now = now or datetime.now(UTC)
    with driver.session() as s:
        glob = s.run(_GLOBAL).single()
        assets = s.run(_ASSETS, tenant_id=tenant_id).single()
        exposure = {r["status"]: r for r in s.run(_EXPOSURE, tenant_id=tenant_id)}
        affected_critical = s.run(_AFFECTED_CRITICAL, tenant_id=tenant_id).single()["affected"]
        top = [r.data() for r in s.run(_TOP, tenant_id=tenant_id)]

    rows = {r["source_id"]: r for r in source_sync.list_status(conn)}
    sources = []
    for source_id in dict.fromkeys([*EXPECTED_SOURCES, *rows]):
        row = rows.get(source_id)
        ts = row["last_success_at"] if row else None
        age, stale = _age(ts, now)
        sources.append({
            "source_id": source_id, "label": SOURCE_LABELS.get(source_id, source_id),
            "last_status": row["last_status"] if row else None,
            "last_attempt_at": row["last_attempt_at"].isoformat() if row and row["last_attempt_at"] else None,
            "last_success_at": ts.isoformat() if ts else None, "age_hours": age, "stale": stale,
            "records_received": row["records_received"] if row else 0,
            "records_rejected": row["records_rejected"] if row else 0,
        })

    imported = latest_import_time(conn, tenant_id)
    if imported is None and assets["imported_at"]:
        imported = datetime.fromisoformat(assets["imported_at"].replace("Z", "+00:00"))
    inv_age, inv_stale = _age(imported, now)

    warnings = []
    for src in sources:
        if src["source_id"] in EXPECTED_SOURCES and src["stale"]:
            warnings.append(f"{src['label']} has never synced successfully." if src["last_success_at"] is None
                            else f"{src['label']} last synced {src['age_hours']} hours ago; results may be stale.")
    if imported is None:
        warnings.append("No asset inventory has been imported for this organization.")
    elif inv_stale:
        warnings.append(f"The asset inventory was last imported {inv_age} hours ago; results may be stale.")

    def count(status: str, field: str) -> int:
        return int(exposure[status][field]) if status in exposure else 0

    return {
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "vulnerabilities": {"total": glob["total"], "kev": glob["kev"] or 0, "critical_cvss": glob["critical_cvss"] or 0},
        "assets": {"total": assets["total"], "critical": assets["critical"] or 0, "affected_critical": affected_critical},
        "exposure": {
            "confirmed": count("confirmed", "pairs"), "possible": count("possible", "pairs"),
            "unknown": count("unknown", "pairs"), "confirmed_cves": count("confirmed", "cves"),
        },
        "top_exposures": top,
        "sources": sources,
        "inventory": {"last_imported_at": imported.isoformat() if imported else None, "age_hours": inv_age, "stale": inv_stale},
        "stale_after_hours": int(STALE_AFTER.total_seconds() // 3600),
        "warnings": warnings,
    }
