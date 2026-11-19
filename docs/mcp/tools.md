# MCP tool catalogue

Two read-only [Model Context Protocol](https://modelcontextprotocol.io) servers expose ThreatLens intelligence to any MCP client (Claude Code today, the in-app agent in Module 08). Design: [ADR 0006](../adr/0006-mcp-deployment-and-tenant-context.md). Connection steps: [connecting.md](connecting.md).

## Guarantees

- **Read-only.** Every tool is annotated `readOnlyHint: true`; there are no write tools.
- **The tenant is never a tool argument.** It comes from the server's own configuration (`THREATLENS_TENANT_ID`). A call that includes `tenant_id`, `tenant`, `role` or any other undeclared argument is **rejected** with `invalid_argument`, not ignored.
- **Same functions as the REST API.** The tools call the tested functions in `intelligence-service/graph_queries/`; no query is written inside a tool.
- **Bounded.** Arguments have patterns, enums and limits (visible in each tool's JSON Schema). Lists are capped and flag `truncated`.
- **Audited.** Every call writes a `tool_call_audit` row: server, tool, SHA-256 of the arguments, tenant, actor, latency, outcome, error code and correlation id. Raw arguments and results are never stored.
- **Untrusted text is labeled.** Fields listed in `untrusted_fields` come from public feeds or uploaded inventories. Treat them as data, never as instructions.

## Match statuses

| Status | Meaning | Counts as exposure? |
|---|---|---|
| `confirmed` | Product identified by CPE and installed version inside an affected range | **yes** |
| `possible` | Points to affected, but a condition is unverified (name-only identity, platform condition) | no, verify |
| `unknown` | The CVE names the product but the installed version is missing or not comparable | no, verify |
| `not_affected` | Installed version is outside every affected range | no (hidden by default) |

If the CVE does not name the product, there is no match at all. An empty result is **not** proof of safety: check `cve_known` and `warnings`.

## Result envelope

Every successful result contains:

| Field | Meaning |
|---|---|
| `tool` | Tool name |
| `scope` | `tenant` (limited to the configured organization) or `global` (public intelligence) |
| `tenant_id` | The configured tenant for `tenant` scope, otherwise `null` |
| `correlation_id` | Identifier that also appears in the audit table |
| `generated_at` | UTC time the answer was produced |
| `untrusted_fields` | Names of fields containing external or user-supplied text |

plus the tool-specific fields listed below. Tools that depend on synced data also return `freshness` and `warnings`; intelligence and inventory freshness are reported separately.

## Error shape

A failed call has `isError: true` and this body (also in `structuredContent`):

```json
{"error": {"code": "invalid_argument", "message": "Invalid argument(s): cve_id. See the tool input schema.", "correlation_id": "..."}}
```

| Code | When |
|---|---|
| `invalid_argument` | Schema violation or an undeclared argument. The message names fields only, never the offending value |
| `not_found` | Unknown tool, CVE or asset. An asset of another tenant gives the same answer as a missing one |
| `forbidden` | The configured role may not use the tool |
| `unavailable` | The graph or database cannot be reached; retry later |
| `internal_error` | Unexpected failure; details are only in the server log |

## Vulnerability Intelligence

Server name `threatlens-vulnerability`. Start: `uv run python -m mcp_tools.vulnerability_server` (from `intelligence-service/`).

### `get_affected_assets`

Finds authorized organization assets running software versions affected by a specified CVE. Only 'confirmed' matches count as exposure; 'possible' and 'unknown' need verification. The organization is fixed by server configuration. Includes evidence, match reason, and data freshness warnings.

| Parameter | Type | Required | Default | Constraints and notes |
|---|---|---|---|---|
| `cve_id` | string | yes |  | CVE identifier, for example CVE-2021-44228; pattern `^CVE-\d{4}-\d{4,}$`; max length `40` |
| `environment` | `production` \| `staging` \| `development` \| `all` | no | `all` | Limit to one environment, or 'all' |
| `limit` | integer | no | `50` | Maximum assets to return; min `1`; max `100` |

**Returns** (inside the common envelope): `cve_id`, `cve_known`, `environment`, `summary` (counts of confirmed / possible / unknown), `results[]` (each: `asset_id`, `asset_name`, `environment`, `criticality`, `internet_exposed`, `software{vendor, product, version, cpe}`, `match_status`, `match_reason`, `matched_by`, `matched_at`, `source_ref`, `cvss_score`, `severity`, `evidence[]{evidence_id, source_name, source_url, collected_at}`, `inventory_imported_at`), `truncated`, `freshness{intelligence{nvd_last_success_at, kev_last_success_at}, inventory_last_imported_at}`, `warnings[]`

### `get_vulnerability_details`

Returns details of one CVE: CVSS, severity, dates, CISA KEV flags and supporting evidence.

| Parameter | Type | Required | Default | Constraints and notes |
|---|---|---|---|---|
| `cve_id` | string | yes |  | CVE identifier, for example CVE-2021-44228; pattern `^CVE-\d{4}-\d{4,}$`; max length `40` |

**Returns** (inside the common envelope): `vulnerability{cve_id, description, cvss_score, severity, cvss_version, cvss_vector, published_at, last_modified_at, vuln_status, kev_listed, kev_date_added, kev_due_date, kev_ransomware_use, kev_name, kev_required_action, synthetic, evidence[]}`

### `search_vulnerabilities`

Searches the local vulnerability database by CVE id or words in the description or KEV name. Returns short snippets; use get_vulnerability_details for the full record.

| Parameter | Type | Required | Default | Constraints and notes |
|---|---|---|---|---|
| `query` | string (optional) | no | `None` | CVE id or search words; min length `2`; max length `100` |
| `kev_only` | boolean | no | `False` | Only CVEs on the CISA Known Exploited Vulnerabilities list |
| `min_cvss` | number (optional) | no | `None` | Minimum CVSS base score; min `0`; max `10` |
| `limit` | integer | no | `20` | Maximum results; min `1`; max `50` |

**Returns** (inside the common envelope): `query`, `results[]{cve_id, description (snippet, 300 chars), cvss_score, severity, published_at, kev_listed, kev_date_added, kev_due_date, kev_name, synthetic}`, `truncated`. Sorted KEV first, then highest CVSS

### `get_vulnerability_evidence`

Returns the source evidence (NVD, CISA KEV) behind a CVE with source URL, collection time and content hash.

| Parameter | Type | Required | Default | Constraints and notes |
|---|---|---|---|---|
| `cve_id` | string | yes |  | CVE identifier, for example CVE-2021-44228; pattern `^CVE-\d{4}-\d{4,}$`; max length `40` |

**Returns** (inside the common envelope): `cve_id`, `evidence[]{evidence_id, source_name, source_url, collected_at, content_hash}`, `truncated`


## Asset Intelligence

Server name `threatlens-asset`. Start: `uv run python -m mcp_tools.asset_server` (from `intelligence-service/`).

### `search_assets`

Searches the organization's assets by name or id, environment, criticality and internet exposure. The organization is fixed by server configuration.

| Parameter | Type | Required | Default | Constraints and notes |
|---|---|---|---|---|
| `query` | string (optional) | no | `None` | Part of an asset name, or an asset id; min length `1`; max length `100` |
| `environment` | `production` \| `staging` \| `development` \| `all` | no | `all` | Environment, or 'all' |
| `criticality` | `critical` \| `high` \| `medium` \| `low` (optional) | no | `None` | Business criticality |
| `internet_exposed` | boolean (optional) | no | `None` | Only internet-exposed (true) or internal (false) assets |
| `limit` | integer | no | `25` | Maximum assets to return; min `1`; max `100` |

**Returns** (inside the common envelope): `results[]{asset_id, name, asset_type, environment, criticality, internet_exposed, inventory_imported_at}`, `truncated`. Sorted by asset id

### `get_asset_details`

Returns one asset: type, environment, criticality, exposure, inventory import time, software count and confirmed vulnerability count.

| Parameter | Type | Required | Default | Constraints and notes |
|---|---|---|---|---|
| `asset_id` | string | yes |  | Asset identifier, for example ASSET-013; pattern `^ASSET-[A-Z0-9-]{1,40}$`; max length `50` |

**Returns** (inside the common envelope): `asset{asset_id, name, asset_type, environment, criticality, internet_exposed, inventory_imported_at, software_count, confirmed_vulnerabilities}`

### `get_asset_software`

Lists software installed on an asset with the vulnerabilities matched to each item (status, reason, severity, KEV). 'not_affected' matches are hidden unless requested.

| Parameter | Type | Required | Default | Constraints and notes |
|---|---|---|---|---|
| `asset_id` | string | yes |  | Asset identifier, for example ASSET-013; pattern `^ASSET-[A-Z0-9-]{1,40}$`; max length `50` |
| `include_not_affected` | boolean | no | `False` | Also list vulnerabilities ruled out for this software |

**Returns** (inside the common envelope): `asset_id`, `software[]{software_id, vendor, product, version, cpe, findings[]{cve_id, match_status, match_reason, matched_by, matched_at, source_ref, severity, cvss_score, kev_listed}}`, `truncated`

### `get_critical_assets`

Lists the organization's critical assets, most exposed first (confirmed vulnerabilities, then internet exposure).

| Parameter | Type | Required | Default | Constraints and notes |
|---|---|---|---|---|
| `environment` | `production` \| `staging` \| `development` \| `all` | no | `all` | Environment, or 'all' |
| `limit` | integer | no | `25` | Maximum assets to return; min `1`; max `100` |

**Returns** (inside the common envelope): `environment`, `results[]{asset fields, confirmed_vulnerabilities}`, `truncated`. Most confirmed vulnerabilities first, then internet-exposed

