# Module 04 — External intelligence: NVD + CISA KEV (Roadmap Phase 3)

**Duration:** ~1–1½ weeks · **Checkpoint 3:** External intelligence · **Depends on:** Module 03
**Goal:** real CVE and KEV data refreshes on demand, with provenance and sync status.

## Required MCPs
| MCP | Why | Required? |
|---|---|---|
| Fetch / web-fetch MCP | Read NVD 2.0 API docs and the KEV schema; capture fixtures (read-only) | Recommended |
| Memgraph MCP | Inspect imported `Vulnerability`/`Evidence` nodes | Recommended |
| PostgreSQL MCP | Inspect `source_sync` rows | Recommended |
| Context7 (docs MCP) | pydantic, httpx, Flyway/Alembic docs | Optional |

## Accounts / manual actions
- **A3 (you):** Request an NVD API key (free; activated by email; ~10× rate limit). Put in local `.env` as `NVD_API_KEY`.
- **A4:** CISA KEV needs no account (public JSON feed).

## Tasks
- [ ] 3.1 **(you)** Request NVD key; add to `.env`.
- [ ] 3.2 **(Claude)** Field-mapping doc: NVD CVE 2.0 JSON → `Vulnerability` + `Evidence` (id, descriptions, CVSS v3.1/v4, published/lastModified, configurations/CPE match criteria).
- [ ] 3.3 **(Claude)** Postgres migration (Flyway or Alembic — record choice) for `source_sync` with all fields from spec §20.3.
- [ ] 3.4 **(Claude)** NVD connector: pagination (`startIndex`/`resultsPerPage`), incremental sync via `lastModStartDate/EndDate` (respect max window), rate limiting, retry/backoff, pydantic validation, content hash, idempotent upsert.
- [ ] 3.5 **(Claude)** KEV connector: fetch + validate JSON feed, set `kev_listed`, `kev_date_added`, `kev_due_date`, `kev_ransomware_use` (G10), record Evidence and sync status.
- [ ] 3.6 **(Claude)** Manual sync trigger (CLI + internal FastAPI endpoint).
- [ ] 3.7 **(Claude)** Tests with **recorded fixtures** (no live network in CI): pagination, backoff, malformed record rejected and counted, reimport has no duplicates, secrets never logged.
- [ ] 3.8 **(Claude)** Allowlisted "import a single real CVE" path for the demo (spec §17 step 1).

## Best practices for this module
- Treat feed content as untrusted; validate schema; never render as HTML.
- Never log the API key; sanitize `error_summary`.
- Do not infer affected internal assets from a CVE record alone.

## Done when
A sync populates CVEs and KEV flags; a rerun updates counts without duplicates; `source_sync` shows correct timestamps and counters.
