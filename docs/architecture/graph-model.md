# Graph model (MVP slice)

Verified against `memgraph/memgraph-mage:3.14.0`. Tenant rules are in [ADR 0002](../adr/0002-tenant-model.md).

## Nodes

| Label | Key (unique) | Scope | Properties |
|---|---|---|---|
| `Tenant` | `tenant_id` | tenant | `name` |
| `Asset` | `asset_id` | tenant | `name`, `asset_type`, `environment`, `criticality`, `internet_exposed`, `tenant_id`, `inventory_imported_at` |
| `Software` | `software_id` | global catalogue | `vendor`, `product`, `version` (absent = unknown), `cpe` (CPE 2.3) |
| `Vulnerability` | `cve_id` | global | `description`, `cvss_score`, `severity`, `published_at`; NVD sync adds `cvss_version`, `cvss_vector`, `last_modified_at`, `vuln_status`, `configurations_json`; KEV sync adds `kev_*` (see [nvd-field-mapping](nvd-field-mapping.md)) |
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

Matching is done by `correlation/matcher.py` under [ADR 0003](../adr/0003-product-identity-and-version-matching.md); its edges have `matched_by = cpe-matcher/1` and also carry `matched_criteria` (the NVD `matchCriteriaId`). `match_status` is one of `confirmed`, `possible`, `not_affected`, `unknown`. A match is never guessed: a product with no installed version gets `unknown`. `source_ref` points to the `evidence_id` that justifies the match.

Facts (`RUNS` from an inventory, `Evidence`) are kept separate from inferences (`AFFECTED_BY`, which records who made the decision in `matched_by` and why in `match_reason`).

## Schema

[`database/memgraph/schema.cypher`](../../database/memgraph/schema.cypher): uniqueness constraints on `tenant_id`, `asset_id`, `software_id`, `cve_id`, `evidence_id`, and an index on `Asset(tenant_id)`. Re-running is safe.

## Seed data

`data/seed/` holds synthetic data only (fictional vendor, `CVE-DEMO-*` IDs, `example.invalid` URLs):

| File | Content |
|---|---|
| `inventory-demo.json` | `TENANT-DEMO`, 16 assets (12 fictional-vendor plus 4 Apache Log4j assets for matching against the real CVE-2021-44228), validated by `data/schemas/inventory.schema.json` |
| `inventory-other.json` | `TENANT-OTHER`, 5 assets (one runs Apache Log4j 2.14.1), used for isolation tests |
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

## Inventory import and matching

- `ingestion/inventory_import.py` imports JSON or CSV inventories for a tenant supplied by trusted context. Rows are validated one by one; rejected rows are reported by file position with field names and error types (never cell values) and are not imported. Each attempt is recorded in PostgreSQL `inventory_import` (migration `V2`).
- `correlation/match_service.py` evaluates installed software against each CVE's `configurations_json` and writes `AFFECTED_BY`. It only creates, updates or removes edges it owns, and an unchanged edge keeps its `matched_at`.
- If a CVE does not name the product, no edge is written. If it names the product but the version cannot be compared or is missing, the status is `unknown`.
- `get_affected_assets_with_freshness` returns the results plus the last successful NVD and KEV sync times and the tenant's last inventory import time, with a warning for each source that is missing or older than 48 hours.

CLI: `uv run python -m ingestion.cli import-inventory --tenant TENANT-DEMO --file inventory.csv` and `uv run python -m ingestion.cli match`.

CSV columns: `asset_id,name,asset_type,environment,criticality,internet_exposed` (required) and `vendor,product,version,cpe` (optional; one row per installed software, repeat the asset columns).
