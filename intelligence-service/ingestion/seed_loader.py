"""Idempotent loader for the synthetic demo graph (MERGE on stable IDs, parameterized Cypher).

Usage (from intelligence-service/):  uv run python -m ingestion.seed_loader [--reset]
All seed nodes carry synthetic=true so `--reset` removes only synthetic data.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from neo4j import Driver, ManagedTransaction

from app.config import REPO_ROOT, get_driver
from ingestion.inventory_import import software_id, write_assets

SEED_DIR = REPO_ROOT / "data" / "seed"
SCHEMA_FILE = REPO_ROOT / "data" / "schemas" / "inventory.schema.json"
SCHEMA_CYPHER = REPO_ROOT / "database" / "memgraph" / "schema.cypher"
INVENTORY_FILES = ("inventory-demo.json", "inventory-other.json")
VULNERABILITY_FILE = "vulnerabilities.json"
SEED_IMPORTED_AT = "2026-11-01T00:00:00.000Z"  # fixed so reseeding is deterministic


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
    write_assets(tx, inv["tenant_id"], inv["tenant_name"], inv["assets"], SEED_IMPORTED_AT, synthetic=True)


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
