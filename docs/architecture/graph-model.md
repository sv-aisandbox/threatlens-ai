# Graph model (MVP slice)

Verified against `memgraph/memgraph-mage:3.14.0`. Tenant rules are in [ADR 0002](../adr/0002-tenant-model.md).

## Nodes

| Label | Key (unique) | Scope | Properties |
|---|---|---|---|
| `Tenant` | `tenant_id` | tenant | `name` |
| `Asset` | `asset_id` | tenant | `name`, `asset_type`, `environment`, `criticality`, `internet_exposed`, `tenant_id` |
| `Software` | `software_id` | global catalogue | `vendor`, `product`, `version` (absent = unknown), `cpe` (CPE 2.3) |
| `Vulnerability` | `cve_id` | global | `description`, `cvss_score`, `severity`, `published_at` |
| `Evidence` | `evidence_id` | global (public) | `source_name`, `source_url`, `collected_at`, `summary`, `content_hash` |

`software_id` is deterministic: `SOFTWARE:<vendor>:<product>:<version|unknown>` with each part lower-cased and reduced to `[a-z0-9_]`. The original vendor, product and version strings are kept as properties.

All synthetic nodes and relationships carry `synthetic: true`. Timestamps are ISO-8601 UTC strings.

## Relationships

| Relationship | Meaning | Properties |
|---|---|---|
| `(Tenant)-[:OWNS]->(Asset)` | ownership, mirrors `Asset.tenant_id` | |
| `(Asset)-[:RUNS]->(Software)` | the installation (tenant-scoped) | `tenant_id` |
| `(Software)-[:AFFECTED_BY]->(Vulnerability)` | product-version match | `match_status`, `match_reason`, `matched_by`, `matched_at`, `source_ref` |
| `(Evidence)-[:SUPPORTS]->(Vulnerability)` | provenance | |

`match_status` is one of `confirmed`, `possible`, `not_affected`, `unknown`. A match is never guessed: a product with no installed version gets `unknown`. `source_ref` points to the `evidence_id` that justifies the match.

Facts (`RUNS` from an inventory, `Evidence`) are kept separate from inferences (`AFFECTED_BY`, which records who made the decision in `matched_by` and why in `match_reason`).

## Schema

[`database/memgraph/schema.cypher`](../../database/memgraph/schema.cypher): uniqueness constraints on `tenant_id`, `asset_id`, `software_id`, `cve_id`, `evidence_id`, and an index on `Asset(tenant_id)`. Re-running is safe.

## Seed data

`data/seed/` holds synthetic data only (fictional vendor, `CVE-DEMO-*` IDs, `example.invalid` URLs):

| File | Content |
|---|---|
| `inventory-demo.json` | `TENANT-DEMO`, 12 assets, validated by `data/schemas/inventory.schema.json` |
| `inventory-other.json` | `TENANT-OTHER`, 4 assets, used for isolation tests |
| `vulnerabilities.json` | 3 fictional CVEs, evidence and matches |

Cases covered: confirmed match (Example Server 1.2.2 / 1.2.3), negative case (fixed 1.3.0, `not_affected`), unknown case (Example Proxy with no version), unaffected software, and an asset with no software.

Load it (stack must be running): `cd intelligence-service && uv run python -m ingestion.seed_loader` (add `--reset` to remove synthetic data first).

## Query

`intelligence-service/graph_queries/affected_assets.py` `get_affected_assets(driver, tenant_id, cve_id, statuses, limit)`:

```cypher
MATCH (a:Asset {tenant_id: $tenant_id})-[r:RUNS]->(s:Software)-[m:AFFECTED_BY]->(v:Vulnerability {cve_id: $cve_id})
WHERE r.tenant_id = $tenant_id AND m.match_status IN $statuses
```

Parameterized, tenant-filtered, bounded (`limit` 1 to 500, at most 5 evidence items per row). `not_affected` is returned only when requested.
