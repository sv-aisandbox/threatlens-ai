# NVD and CISA KEV field mapping

Feed content is untrusted. Every record is validated (pydantic) before it touches the graph; invalid records are rejected, counted in `source_sync.records_rejected`, and never echoed into logs or error summaries. Timestamps are ISO-8601 UTC strings (NVD timestamps carry no zone and are UTC).

## NVD CVE API 2.0 record -> `Vulnerability` + `Evidence`

Code: `intelligence-service/normalization/nvd.py`.

| NVD field | Graph property | Notes |
|---|---|---|
| `id` | `Vulnerability.cve_id` | must match `^CVE-\d{4}-\d{4,}$`, otherwise rejected |
| `descriptions[lang=en]` | `description` | falls back to the first description; at least one is required |
| `published` | `published_at` | required |
| `lastModified` | `last_modified_at` | required |
| `vulnStatus` | `vuln_status` | for example `Analyzed`, `Awaiting Analysis` |
| `metrics.cvssMetricV31` / `V40` / `V30` / `V2` | `cvss_score`, `severity`, `cvss_version`, `cvss_vector` | first available in that order; NVD `Primary` source preferred over `Secondary`. No metric means these stay empty (never defaulted). Severity is lower-cased. |
| `configurations` | `configurations_json` | verbatim JSON (CPE match criteria and version-range operators), kept for matching in Module 05. It is data, never rendered. |
| whole `cve` object | `Evidence.content_hash` | SHA-256 of the canonical JSON; used to detect changes |
| (constant) | `Evidence.evidence_id` = `EVID-NVD-<cve_id>`, `source_name` = `NVD`, `source_url` = NVD detail page, `collected_at` | `(Evidence)-[:SUPPORTS]->(Vulnerability)` |

Not mapped in the MVP: references, weaknesses, `cisa*` fields on the NVD record (the KEV feed is the authority), SSVC metrics. A CVE record alone never creates any link to an internal asset.

## CISA KEV entry -> `Vulnerability` KEV properties + `Evidence`

Code: `intelligence-service/normalization/kev.py`.

| KEV field | Graph property | Notes |
|---|---|---|
| `cveID` | `cve_id` | same pattern check. If the CVE is not yet in the graph a KEV-only node is created and NVD fills it in later. |
| (present in feed) | `kev_listed` = `true` | |
| `dateAdded` | `kev_date_added` | |
| `dueDate` | `kev_due_date` | |
| `knownRansomwareCampaignUse` | `kev_ransomware_use` | `known` or `unknown`, as reported. `unknown` is not a claim that ransomware is unused. |
| `vulnerabilityName` | `kev_name` | |
| `requiredAction` | `kev_required_action` | truncated to 1000 characters |
| entry | `Evidence` `EVID-KEV-<cve_id>` | `source_url` is the feed URL, `content_hash` of the entry |

NVD and KEV writers set disjoint properties, so an NVD re-sync never clears KEV flags and vice versa. Limitation: a CVE removed from the KEV catalogue keeps its flags until a cleanup step is added.

## Sync behaviour

| Aspect | Rule |
|---|---|
| NVD incremental | `lastModStartDate`/`lastModEndDate`, split into windows of at most 120 days, `resultsPerPage` up to 2000, paged with `startIndex` |
| First NVD sync | no cursor: last 7 days. A larger backfill needs an explicit `--since` |
| Cursor | `source_sync.sync_cursor_at`, advanced only after a success or partial run |
| Rate limit | client waits 0.6 s between requests with a key, 6 s without |
| Retry | 403, 429, 5xx and network errors: exponential backoff from 2 s (honours `Retry-After`), 5 retries |
| Idempotency | `MERGE` on `cve_id` and `evidence_id`; a record whose `content_hash` is unchanged is not rewritten |
| Counters | `records_created` = new evidence ids, `records_updated` = changed hash; they describe the latest run only |
| Status | `success`, `partial` (some records rejected), `failed`. `last_success_at` and the cursor are kept on failure |
