"""Idempotent graph upserts (MERGE on stable IDs, parameterized). Unchanged records are not rewritten."""

from collections.abc import Sequence
from typing import Any

from neo4j import Driver

_UPSERT = """
UNWIND $rows AS row
MERGE (v:Vulnerability {cve_id: row.props.cve_id})
SET v += row.props
MERGE (e:Evidence {evidence_id: row.evidence.evidence_id})
SET e += row.evidence
MERGE (e)-[:SUPPORTS]->(v)
"""

_EXISTING = """
MATCH (e:Evidence) WHERE e.evidence_id IN $ids
RETURN e.evidence_id AS id, e.content_hash AS hash
"""


def upsert_batch(driver: Driver, rows: Sequence[dict[str, Any]]) -> tuple[int, int]:
    """Write rows ({"props", "evidence"}); return (created, updated). Unchanged rows are skipped."""
    unique = {r["evidence"]["evidence_id"]: r for r in rows}  # last duplicate wins
    if not unique:
        return 0, 0
    with driver.session() as session:
        existing = {rec["id"]: rec["hash"] for rec in session.run(_EXISTING, ids=list(unique))}
        created = updated = 0
        to_write = []
        for evidence_id, row in unique.items():
            if evidence_id not in existing:
                created += 1
            elif existing[evidence_id] != row["evidence"]["content_hash"]:
                updated += 1
            else:
                continue
            to_write.append(row)
        if to_write:
            session.execute_write(lambda tx: tx.run(_UPSERT, rows=to_write).consume())
    return created, updated
