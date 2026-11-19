"""Idempotent loader for the synthetic demo graph (MERGE on stable IDs, parameterized Cypher).

Usage (from intelligence-service/):  uv run python -m ingestion.seed_loader [--reset]
All seed nodes carry synthetic=true so `--reset` removes only synthetic data.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from neo4j import Driver, ManagedTransaction

from app.config import REPO_ROOT, get_driver

SEED_DIR = REPO_ROOT / "data" / "seed"
SCHEMA_FILE = REPO_ROOT / "data" / "schemas" / "inventory.schema.json"
SCHEMA_CYPHER = REPO_ROOT / "database" / "memgraph" / "schema.cypher"
INVENTORY_FILES = ("inventory-demo.json", "inventory-other.json")
VULNERABILITY_FILE = "vulnerabilities.json"


def software_id(vendor: str, product: str, version: str | None) -> str:
    """Deterministic ID so the same product/version is one shared Software node."""

    def slug(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")

    return f"SOFTWARE:{slug(vendor)}:{slug(product)}:{slug(version) if version else 'unknown'}"


def content_hash(obj: dict[str, Any]) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def apply_schema(driver: Driver, path: Path = SCHEMA_CYPHER) -> None:
    lines = [ln for ln in path.read_text().splitlines() if not ln.strip().startswith("//")]
    statements = [s.strip() for s in "\n".join(lines).split(";") if s.strip()]
    with driver.session() as session:
        for stmt in statements:
            session.run(stmt).consume()


def reset_seed(driver: Driver) -> None:
    """Delete synthetic nodes only; real data is never touched."""
    with driver.session() as session:
        session.run("MATCH (n) WHERE n.synthetic = true DETACH DELETE n").consume()


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_inventory(tx: ManagedTransaction, inv: dict[str, Any]) -> None:
    tenant_id = inv["tenant_id"]
    asset_ids = [a["asset_id"] for a in inv["assets"]]
    clash = tx.run(
        "MATCH (n:Asset) WHERE n.asset_id IN $ids AND n.tenant_id <> $tenant_id "
        "RETURN n.asset_id AS asset_id",
        ids=asset_ids,
        tenant_id=tenant_id,
    ).data()
    if clash:
        raise ValueError(f"asset ids already belong to another tenant: {clash}")

    tx.run(
        "MERGE (t:Tenant {tenant_id: $tenant_id}) SET t.name = $name, t.synthetic = true",
        tenant_id=tenant_id,
        name=inv["tenant_name"],
    )
    assets = [{k: v for k, v in a.items() if k != "software"} for a in inv["assets"]]
    tx.run(
        """
        MATCH (t:Tenant {tenant_id: $tenant_id})
        UNWIND $assets AS a
        MERGE (n:Asset {asset_id: a.asset_id})
        SET n.name = a.name, n.asset_type = a.asset_type, n.environment = a.environment,
            n.criticality = a.criticality, n.internet_exposed = a.internet_exposed,
            n.tenant_id = $tenant_id, n.synthetic = true
        MERGE (t)-[o:OWNS]->(n)
        SET o.synthetic = true
        """,
        tenant_id=tenant_id,
        assets=assets,
    )
    installs = [
        {
            "asset_id": a["asset_id"],
            "software_id": software_id(s["vendor"], s["product"], s.get("version")),
            "vendor": s["vendor"],
            "product": s["product"],
            "version": s.get("version"),
            "cpe": s.get("cpe"),
        }
        for a in inv["assets"]
        for s in a.get("software", [])
    ]
    tx.run(
        """
        UNWIND $installs AS i
        MATCH (a:Asset {asset_id: i.asset_id, tenant_id: $tenant_id})
        MERGE (s:Software {software_id: i.software_id})
        SET s.vendor = i.vendor, s.product = i.product, s.version = i.version,
            s.cpe = coalesce(i.cpe, s.cpe), s.synthetic = true
        MERGE (a)-[r:RUNS]->(s)
        SET r.tenant_id = $tenant_id, r.synthetic = true
        """,
        tenant_id=tenant_id,
        installs=installs,
    )


def _load_vulnerabilities(tx: ManagedTransaction, data: dict[str, Any]) -> None:
    for v in data["vulnerabilities"]:
        tx.run(
            """
            MERGE (v:Vulnerability {cve_id: $cve_id})
            SET v.description = $description, v.cvss_score = $cvss_score,
                v.severity = $severity, v.published_at = $published_at, v.synthetic = true
            """,
            cve_id=v["cve_id"],
            description=v["description"],
            cvss_score=v["cvss_score"],
            severity=v["severity"],
            published_at=v["published_at"],
        )
        evidence_times: dict[str, str] = {}
        for e in v["evidence"]:
            evidence_times[e["evidence_id"]] = e["collected_at"]
            tx.run(
                """
                MATCH (v:Vulnerability {cve_id: $cve_id})
                MERGE (e:Evidence {evidence_id: $evidence_id})
                SET e.source_name = $source_name, e.source_url = $source_url,
                    e.collected_at = $collected_at, e.summary = $summary,
                    e.content_hash = $content_hash, e.synthetic = true
                MERGE (e)-[r:SUPPORTS]->(v)
                SET r.synthetic = true
                """,
                cve_id=v["cve_id"],
                evidence_id=e["evidence_id"],
                source_name=e["source_name"],
                source_url=e["source_url"],
                collected_at=e["collected_at"],
                summary=e["summary"],
                content_hash=content_hash(e),
            )
        for m in v["affects"]:
            tx.run(
                """
                MATCH (v:Vulnerability {cve_id: $cve_id})
                MERGE (s:Software {software_id: $software_id})
                ON CREATE SET s.vendor = $vendor, s.product = $product, s.version = $version,
                              s.synthetic = true
                MERGE (s)-[r:AFFECTED_BY]->(v)
                SET r.match_status = $match_status, r.match_reason = $match_reason,
                    r.matched_by = $matched_by, r.matched_at = $matched_at,
                    r.source_ref = $source_ref, r.synthetic = true
                """,
                cve_id=v["cve_id"],
                software_id=software_id(m["vendor"], m["product"], m.get("version")),
                vendor=m["vendor"],
                product=m["product"],
                version=m.get("version"),
                match_status=m["match_status"],
                match_reason=m["match_reason"],
                matched_by=m["matched_by"],
                matched_at=evidence_times[m["source_ref"]],
                source_ref=m["source_ref"],
            )


def load_seed(driver: Driver, seed_dir: Path = SEED_DIR) -> None:
    validator = Draft202012Validator(_load_json(SCHEMA_FILE))
    inventories = [_load_json(seed_dir / name) for name in INVENTORY_FILES]
    for inv in inventories:
        validator.validate(inv)
    vulns = _load_json(seed_dir / VULNERABILITY_FILE)
    with driver.session() as session:
        for inv in inventories:
            session.execute_write(_load_inventory, inv)
        session.execute_write(_load_vulnerabilities, vulns)


def main() -> None:
    parser = argparse.ArgumentParser(description="Load the synthetic ThreatLens seed graph.")
    parser.add_argument("--reset", action="store_true", help="delete synthetic data first")
    args = parser.parse_args()
    driver = get_driver()
    try:
        apply_schema(driver)
        if args.reset:
            reset_seed(driver)
        load_seed(driver)
        with driver.session() as s:
            nodes = s.run("MATCH (n) WHERE n.synthetic = true RETURN count(n) AS c").single()["c"]
            rels = s.run(
                "MATCH (a {synthetic: true})-[r]->(b {synthetic: true}) RETURN count(r) AS c"
            ).single()["c"]
        print(f"Seed loaded: {nodes} synthetic nodes, {rels} relationships")
    finally:
        driver.close()


if __name__ == "__main__":
    main()
