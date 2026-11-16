# Module 05 — Asset inventory import and matching (Roadmap Phase 4)

**Duration:** ~1 week · **Checkpoint 4:** Asset matching · **Depends on:** Module 04
**Goal:** an imported synthetic inventory is matched to CVEs with honest statuses.

## Required MCPs
| MCP | Why | Required? |
|---|---|---|
| Memgraph MCP | Verify `AFFECTED_BY` properties and counts | Recommended |
| PostgreSQL MCP | Inspect import job records | Optional |
| Context7 (docs MCP) | `packaging` / version-comparison docs | Optional |

## Spec issues addressed here
- **G3/G4** Match status on `AFFECTED_BY`; CPE-based matching.
- Spec §20.4: `confirmed` / `possible` / `not_affected` / `unknown`; return `unknown` rather than guessing.

## Tasks
- [ ] 4.1 **(Claude)** ADR 0003 — CPE comparison, NVD version-range operators (`versionStartIncluding/Excluding`, `versionEndIncluding/Excluding`), version comparison strategy with documented fallback to `unknown`.
- [ ] 4.2 **(Claude)** CSV/JSON inventory importer: schema validation, row-level reject report, import only accepted rows, keep original values.
- [ ] 4.3 **(Claude)** Matching service writing `AFFECTED_BY` with `match_status`, `match_reason`, `matched_by`, `matched_at`; never `confirmed` without product + version match.
- [ ] 4.4 **(Claude)** Table-driven tests: confirmed, possible, not_affected, unknown, every range-boundary case, vendor-name normalization.
- [ ] 4.5 **(Claude)** Affected-assets service returns both timestamps: intel `last_success_at` and inventory import time (spec §20.3).

## Best practices for this module
- Test-first; pure-logic matching is the highest-credibility risk — default to `unknown`.
- Only `confirmed` counts as exposure in answers.

## Done when
All four statuses are covered by tests; the query returns only tenant-scoped assets with reason and evidence.
