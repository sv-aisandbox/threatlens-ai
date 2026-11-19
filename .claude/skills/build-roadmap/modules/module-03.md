# Module 03 — Graph model and seed (Roadmap Phase 2)

**Duration:** ~1 week · **Checkpoint 2:** Graph slice · **Depends on:** Module 02
**Goal:** a correct, rerunnable synthetic graph for one tenant plus a second tenant for isolation tests.

## Required MCPs
| MCP | Why | Required? |
|---|---|---|
| Memgraph MCP | Run/verify Cypher, constraints, counts | Recommended |
| Context7 (or similar docs MCP) | Check Memgraph syntax for the **pinned** version | Recommended |
| GitHub MCP | PRs | Optional |

## Spec issues addressed here
- **G1** Spec seed example is broken (`CREATE` after `MATCH;` makes loose nodes) → use `MERGE` on stable IDs.
- **G2** Tenant model: CVE/KEV/public evidence are global; assets and installations are tenant-scoped; every tenant query starts from a tenant-filtered `Asset`.
- **G3** Match status properties live on `AFFECTED_BY` (`match_status`, `match_reason`, `matched_by`, `matched_at`, `source_ref`).
- **G4** Give synthetic `Software` a CPE 2.3 string.

## Tasks
- [x] 2.1 **(Claude)** ADR 0002 — tenant model.
- [x] 2.2 **(Claude)** `database/memgraph/schema.cypher`: uniqueness constraints/indexes on `asset_id`, `software_id`, `cve_id`, `evidence_id`, `tenant_id` (verify syntax against pinned version).
- [x] 2.3 **(Claude)** `data/schemas/`: JSON Schemas for the inventory format (including CPE field).
- [x] 2.4 **(Claude)** `data/seed/`: tenants `TENANT-DEMO` and `TENANT-OTHER`, ~10–20 assets, software with CPEs, 2–3 fictional CVEs, Evidence nodes. Include a **negative case** (unaffected version) and an **unknown case** (no version).
- [x] 2.5 **(Claude)** Idempotent seed loader (Python, `MERGE`, parameterized).
- [x] 2.6 **(Claude)** `graph_queries/affected_assets.py`: tenant-filtered, parameterized query returning asset, software, CVE, match status, evidence.
- [x] 2.7 **(Claude)** pytest against real Memgraph: expected asset returned; negative case not returned; tenant B sees nothing of A; reseed creates no duplicates.
- [x] 2.8 **(Claude)** `docs/architecture/graph-model.md`.

## Best practices for this module
- Parameterized Cypher only. Bounded results. Stable IDs. Test-first for the query.
- Separate observed facts from inferred relationships.

## Done when
Seed run twice yields identical node/relationship counts; all graph tests pass.
