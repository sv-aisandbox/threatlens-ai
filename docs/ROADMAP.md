# ThreatLens AI — Development Roadmap

**Source of truth:** `ThreatLens_Project_Spec.md` (to be moved to `docs/PROJECT_SPEC.md` in Task 0.3)
**Created:** 2026-11-15
**Status:** Draft — review the "Decisions" section before starting Phase 1.

This roadmap turns the specification into ordered phases and checkable
tasks. Every phase ends at one of the spec's checkpoints (Section 21.5), so
you always have a working, demonstrable state before moving on.

Legend: `[ ]` todo · **(you)** = needs a manual action from you (account,
key, approval) · **(Claude)** = can be implemented with Claude Code.

---

## 1. Spec analysis — what matters before building

### 1.1 What the MVP actually is

The spec is ambitious (10 modules, 6 MCP groups, 46 tools), but Section 20
narrows the **first release** to one vertical slice:

> NVD CVE + CISA KEV → synthetic assets/software → version matching in
> Memgraph → `get_affected_assets` service → Spring Boot API + MCP tool →
> AI agent discovers and calls it → UI shows answer + tool trace + evidence
> → cross-tenant access denied.

Everything else (ATT&CK, attack paths, incidents, STIX, URL import, OIDC
SSO, semantic tool search, deployment hardening) is **post-MVP**. This
roadmap keeps it that way.

### 1.2 Gaps and issues found in the spec

These need a decision (see Section 4) or a fix during implementation.

| # | Issue | Where | Recommendation |
|---|---|---|---|
| G1 | **Seed Cypher example is broken.** `MATCH ... CREATE (a)-[:RUNS]->(s);` ends the statement, so the next `CREATE (s)-[:AFFECTED_BY]->(v);` creates new, unlabeled nodes. | §5 seed example | Use `MERGE` on stable IDs in a single statement per relationship. Never copy the example verbatim. |
| G2 | **Tenant model for shared intel is undefined.** `Asset` has `tenant_id`, but `Software` and `Vulnerability` do not. CVEs are global; installed software is per tenant. | §5 node labels | CVE/KEV/Evidence-from-public-sources = global nodes. Assets and their installations = tenant-scoped. Every tenant query must start from a tenant-filtered `Asset`. |
| G3 | **Match status has nowhere to live.** §20.4 needs `confirmed/possible/not_affected/unknown` + reason, but `(Software)-[:AFFECTED_BY]->(Vulnerability)` has no properties defined. | §5 vs §20.4 | Store `match_status`, `match_reason`, `matched_by`, `matched_at`, `source_ref` on the `AFFECTED_BY` relationship. Only `confirmed` counts as exposure in answers. |
| G4 | **Product identity is vague.** Matching on free-text vendor/product is unreliable. | §20.4 | Give synthetic `Software` a CPE 2.3 string; NVD configurations use CPE match criteria + version ranges, so matching becomes deterministic and testable. |
| G5 | **Where the agent runs is unspecified.** Spring Boot, Python and MCP all appear in the chat path. | §4, §7 | Agent runs in the **Python** service (MCP SDK is Python). Spring Boot authenticates the user, then forwards to Python with a signed internal token carrying tenant + role. |
| G6 | **Spring Boot ↔ Python contract is undefined.** | §4 | Internal REST over the private Docker network, OpenAPI-documented, authenticated with a short-lived service JWT. Never exposed publicly. |
| G7 | **MCP tenant context.** Spec says tenant must come from trusted context, but local stdio MCP servers have no user session. | §6 | Local/demo: tenant comes from server config (env), never from a tool argument. Remote (post-MVP): from the authenticated MCP session token. |
| G8 | **Auth is in MVP scope but the provider is left open.** | §20.1 vs §22 | Use **Keycloak in Docker** locally: real OIDC/JWT, free, no account needed. Swap later if you want. |
| G9 | **Spring Boot version.** Spec says Spring Boot 3; Spring Boot 4 now exists. | §4 | Stay on the latest **3.x** as specified, unless you choose otherwise (record it in an ADR). |
| G10 | **KEV representation not defined.** | §5 | Properties on `Vulnerability` (`kev_listed`, `kev_date_added`, `kev_due_date`, `kev_ransomware_use`) plus an `Evidence` node pointing to the KEV feed + content hash. |

### 1.3 Architecture for the MVP

```text
Browser ─► Next.js ─► Spring Boot API ──(service JWT)──► Python intelligence service
              │        (auth, RBAC,                       ├─ ingestion (NVD, KEV, asset CSV/JSON)
              │         tenant, audit)                    ├─ matching service
              │             │                             ├─ graph query services ──► Memgraph
              │             └─► PostgreSQL                ├─ tool registry + agent ──► model provider
              │                 (users, jobs,             └─ MCP servers (asset, vulnerability)
              │                  sync status, audit)            ▲
              ▼                                                 │ stdio / streamable HTTP
          Keycloak (OIDC)                          External MCP host (e.g. Claude Code)
```

The key rule is that **one tested Python service function** (for example
`find_affected_assets(tenant, cve_id, env)`) is called by the REST API, the
MCP tool and the agent. Nobody writes the query a second time.

---

## 2. Accounts and access checklist

| # | Account / access | Needed by | Cost | How to get it | Where the secret lives |
|---|---|---|---|---|---|
| A1 | **GitHub** account + new repo `threatlens-ai` **(you)** | Phase 0 | Free | github.com. Enable 2FA. Private repo until the demo is ready. | — |
| A2 | **Docker Desktop** (WSL 2 backend on Windows) **(you)** | Phase 1 | Free for personal use | docker.com. A Docker Hub login is optional (only for higher pull limits). | — |
| A3 | **NVD API key** **(you)** | Phase 3 | Free | nvd.nist.gov/developers/request-an-api-key. Activated by email. Raises the rate limit roughly 10x (about 50 vs 5 requests per 30 s). | `.env` → `NVD_API_KEY` |
| A4 | CISA KEV | Phase 3 | Free | **No account.** Public JSON feed (`known_exploited_vulnerabilities.json` on cisa.gov). | — |
| A5 | **AI model provider API key** **(you)** | Phase 7 (a mock provider covers earlier work) | Pay per use | Recommended: Anthropic Console (Claude), matching your Claude Code workflow. **Set a monthly spend limit** on creation. | `.env` → `MODEL_API_KEY`. Never sent to the browser or the model. |
| A6 | Keycloak (local OIDC) | Phase 5 | Free | **No account.** Docker image. Realm config committed with dummy users only. | `.env` → admin password |
| A7 | MITRE ATT&CK data | Post-MVP R2 | Free | **No account.** STIX bundles from the `mitre-attack/attack-stix-data` GitHub repo. | — |
| A8 | Hosting (Vercel, Render or Fly.io, managed Postgres such as Neon/Supabase, a VM for Memgraph) **(you)** | Post-MVP R5 | Free tiers or low cost | Choose only after local verification (spec §22). | Host secret stores |
| A9 | Domain name (optional) **(you)** | Post-MVP R5 | ~$10–15/yr | Any registrar. Gives `app.`, `api.`, `mcp.` subdomains. | — |
| A10 | GitHub Actions secrets | Phase 9 | Free | Repo → Settings → Secrets. CI should need **no real keys**: tests use fixtures and a mock model. | GitHub Secrets |

**Not needed:** a Memgraph account (local Docker and Memgraph Lab are free), any
real company's systems, or a paid OIDC provider.

---

## 3. Local toolchain (Windows 11)

| Tool | Version guidance | Notes |
|---|---|---|
| Git | latest | Set `core.autocrlf=input`; add `.gitattributes` with `* text=auto eol=lf` so shell scripts don't break in containers. |
| Docker Desktop | latest | WSL 2 backend; give it ≥ 8 GB RAM (Memgraph + Postgres + Keycloak + services). |
| JDK | 21 LTS (Eclipse Temurin) | Use the Maven wrapper (`mvnw`) so the Maven version is pinned in the repo. |
| Python | 3.12+ | Use **uv** for environments and lockfiles. |
| Node.js | current LTS | Use **pnpm** (or npm) with a committed lockfile. |
| VS Code extensions | per spec §11 | Java Pack, Python + Pylance, Docker, GitHub Actions, ESLint, Prettier, YAML, REST Client. |

Pin exact versions in `docs/architecture/decisions/0001-toolchain.md` when
Phase 0 starts.

---

## 4. Decisions to record (ADRs)

Each becomes a short file in `docs/architecture/decisions/`. Recommendations
are proposals. Change them before the phase that needs them.

| ADR | Decision | Recommendation | Needed by |
|---|---|---|---|
| 0001 | Toolchain and versions | Section 3 above | Phase 0 |
| 0002 | Tenant model for global vs tenant data | G2 | Phase 2 |
| 0003 | Product identity and version matching | CPE 2.3 + documented range rules (G3, G4) | Phase 4 |
| 0004 | Spring Boot ↔ Python contract and service auth | G5, G6 | Phase 5 |
| 0005 | Auth provider | Keycloak local (G8) | Phase 5 |
| 0006 | MCP deployment shape and tenant context | One Python package, two server entrypoints, stdio first (G7) | Phase 6 |
| 0007 | AI provider and adapter interface | Anthropic behind an adapter, plus a mock provider for tests | Phase 7 |
| 0008 | Scheduling | Manual sync for MVP; scheduler post-MVP | Post-MVP |
| 0009 | Hosting | Decide after local MVP works | Post-MVP |

---

## 5. Roadmap

Rough pace from the spec: **8–10 weeks part-time** for the MVP (Phases 0–9).

### Phase 0 — Repository and workspace (½ week)

**Goal:** a clean repo Claude Code can work in safely.

- [ ] 0.1 **(you)** Create the GitHub repo (A1); clone it; open it in VS Code.
- [ ] 0.2 **(Claude)** Create the folder skeleton from spec §11. Only create folders that Phases 1–9 use (no empty future-scope modules).
- [ ] 0.3 **(Claude)** Move the spec to `docs/PROJECT_SPEC.md`; add this roadmap under `docs/`.
- [ ] 0.4 **(Claude)** Add `CLAUDE.md` from spec §21.2, plus a pointer to this roadmap and the ADR folder.
- [ ] 0.5 **(Claude)** Add `.gitignore` (Java, Python, Node, `.env`, IDE files), `.gitattributes`, `.editorconfig` and `.env.example` (placeholders only).
- [ ] 0.6 **(Claude)** Add `README.md` with the project purpose, safety boundary, and an empty "Quick start" section.
- [ ] 0.7 **(Claude)** ADR 0001 (toolchain).
- [ ] 0.8 **(you)** Turn on GitHub branch protection for `main` (require a PR and passing CI once CI exists) and secret scanning / push protection.

**Done when:** the first commit is on `main`, `.env` is ignored, and `git status` is clean.

### Phase 1 — Local infrastructure → *Checkpoint 1* (½ week)

**Goal:** Memgraph and PostgreSQL run locally and healthy.

- [ ] 1.1 **(you)** Install Docker Desktop (A2).
- [ ] 1.2 **(Claude)** `docker-compose.yml` with `memgraph/memgraph-mage`, `memgraph/lab`, `postgres`, a private network, named volumes, and ports bound to `127.0.0.1` only.
- [ ] 1.3 **(Claude)** Health checks for both databases; pinned image tags (no `latest`).
- [ ] 1.4 **(Claude)** A `scripts/verify-infra` script that runs `RETURN 1` on Memgraph and `SELECT 1` on Postgres.
- [ ] 1.5 **(Claude)** README Quick-start: start, verify, stop, reset volumes.

**Done when:** `docker compose up -d` plus the verify script pass on a fresh clone.

### Phase 2 — Graph model and seed → *Checkpoint 2* (1 week)

**Goal:** a correct, rerunnable synthetic graph for one tenant (plus a second tenant for isolation tests).

- [ ] 2.1 **(Claude)** ADR 0002 (tenant model).
- [ ] 2.2 **(Claude)** `database/memgraph/schema.cypher`: uniqueness constraints and indexes on stable IDs (`asset_id`, `software_id`, `cve_id`, `evidence_id`, `tenant_id`). Check the syntax against the pinned Memgraph version.
- [ ] 2.3 **(Claude)** `data/schemas/`: JSON Schemas for the synthetic asset/software inventory format (including the CPE field).
- [ ] 2.4 **(Claude)** `data/seed/`: two tenants (`TENANT-DEMO`, `TENANT-OTHER`), ~10–20 assets, software with real-looking CPEs, 2–3 fictional CVEs and Evidence nodes. Include a **negative case** (same product, unaffected version) and an **unknown case** (no version).
- [ ] 2.5 **(Claude)** Idempotent seed loader (Python, `MERGE` on IDs, parameterized). Fixes G1.
- [ ] 2.6 **(Claude)** `graph_queries/affected_assets.py`: a tenant-filtered, parameterized query returning asset, software, CVE, match status and evidence.
- [ ] 2.7 **(Claude)** pytest against a real Memgraph (Testcontainers or Compose): expected asset returned; negative case not returned; tenant B sees nothing of tenant A; reseed creates no duplicates.
- [ ] 2.8 **(Claude)** `docs/architecture/graph-model.md`.

**Done when:** the seed can be run twice with identical node/relationship counts, and all graph tests pass.

### Phase 3 — External intelligence: NVD + CISA KEV → *Checkpoint 3* (1–1½ weeks)

**Goal:** real CVE and KEV data refreshes on demand, with provenance and sync status.

- [ ] 3.1 **(you)** Request the NVD API key (A3); put it in your local `.env`.
- [ ] 3.2 **(Claude)** Field-mapping doc: NVD CVE 2.0 JSON → `Vulnerability` + `Evidence` (id, descriptions, CVSS v3.1/v4 metrics, published/lastModified, configurations/CPE match criteria).
- [ ] 3.3 **(Claude)** Postgres migration (Flyway or Alembic; record the choice) for `source_sync` with every field from spec §20.3.
- [ ] 3.4 **(Claude)** NVD connector: pagination (`startIndex`/`resultsPerPage`), incremental sync by `lastModStartDate`/`lastModEndDate` (respecting the API's maximum date-range window), rate limiting, retry with backoff, response validation (pydantic), content hash, idempotent upsert.
- [ ] 3.5 **(Claude)** KEV connector: fetch the JSON feed, validate it, set KEV properties on matching `Vulnerability` nodes (G10), record Evidence and sync status.
- [ ] 3.6 **(Claude)** A manual sync trigger (CLI and FastAPI endpoint), internal only.
- [ ] 3.7 **(Claude)** Tests using **recorded fixtures**, with no live network in CI: pagination, rate-limit/backoff, a malformed record rejected and counted, reimport updates without duplicating, secrets never in logs.
- [ ] 3.8 **(Claude)** A small allowlisted "import a single real CVE" path for the demo (spec §17 step 1).

**Done when:** a sync populates CVEs and KEV flags, a rerun updates counts without duplicates, and `source_sync` shows correct timestamps and counters.

### Phase 4 — Asset inventory import and matching → *Checkpoint 4* (1 week)

**Goal:** an imported synthetic inventory is matched to CVEs with honest statuses.

- [ ] 4.1 **(Claude)** ADR 0003 (matching rules): CPE comparison, the version-range operators NVD uses (`versionStartIncluding`/`Excluding`, `versionEndIncluding`/`Excluding`), how to compare versions (for example the `packaging` library, with a documented fallback to `unknown`).
- [ ] 4.2 **(Claude)** CSV/JSON inventory importer: validate against the schema, give a row-level reject report, import only accepted rows, keep the original values.
- [ ] 4.3 **(Claude)** Matching service: writes `AFFECTED_BY` with `match_status`, `match_reason`, `matched_by`, `matched_at` (G3). Never sets `confirmed` without a product and version match.
- [ ] 4.4 **(Claude)** Table-driven tests: confirmed, possible, not_affected, unknown, each version-boundary case, and a vendor-name normalization case.
- [ ] 4.5 **(Claude)** The affected-assets service returns both timestamps: intel `last_success_at` and inventory import time (spec §20.3).

**Done when:** all four statuses are covered by tests, and the query returns only tenant-scoped assets with a reason and evidence.

### Phase 5 — Backend API and security boundary → *Checkpoint 5* (1–1½ weeks)

**Goal:** an authenticated, tenant-aware API returns affected assets.

- [ ] 5.1 **(Claude)** ADRs 0004 and 0005.
- [ ] 5.2 **(Claude)** Add Keycloak to Compose with a realm export: roles `ADMIN`, `SECURITY_ANALYST`, `VIEWER`; demo users in two tenants (dummy passwords, local only).
- [ ] 5.3 **(Claude)** Spring Boot 3 app (Java 21, Maven wrapper): an OAuth2 resource server validating Keycloak JWTs; tenant and role taken from token claims only.
- [ ] 5.4 **(Claude)** Endpoints: `GET /api/vulnerabilities/{cveId}`, `GET /api/vulnerabilities/{cveId}/affected-assets?environment=`, `GET /api/sources/status`, `POST /api/sources/{id}/sync` (admin only).
- [ ] 5.5 **(Claude)** Python client in Spring Boot calling the intelligence service with a short-lived service JWT (G6). FastAPI rejects calls without it.
- [ ] 5.6 **(Claude)** Audit table and filter: user, tenant, action, outcome, correlation ID, time. Correlation ID propagated to Python.
- [ ] 5.7 **(Claude)** Input validation (CVE id regex, enum for environment), rate limits, timeouts, a consistent error format (RFC 9457 problem details).
- [ ] 5.8 **(Claude)** Tests: JUnit 5 + Testcontainers + REST Assured. 401 without a token; 403 for the wrong role; **tenant A cannot read tenant B**; invalid CVE gives 400.
- [ ] 5.9 **(Claude)** OpenAPI docs exported to `docs/api/`.

**Done when:** all authorization and tenant tests pass, and a REST Client file in `docs/api/` demonstrates the flow.

### Phase 6 — MCP tools → *Checkpoint 6* (1 week)

**Goal:** `get_affected_assets` (and a small set of companions) is callable by any MCP client.

- [ ] 6.1 **(Claude)** ADR 0006.
- [ ] 6.2 **(Claude)** A Python package using the official MCP SDK with two servers:
  - Vulnerability Intelligence: `get_affected_assets`, `get_vulnerability_details`, `search_vulnerabilities`, `get_vulnerability_evidence`.
  - Asset Intelligence: `search_assets`, `get_asset_details`, `get_asset_software`, `get_critical_assets`.
- [ ] 6.3 **(Claude)** Each tool calls the **same service functions** as the REST API; JSON Schemas match spec §6; tenant comes from trusted config/context, never from arguments (G7).
- [ ] 6.4 **(Claude)** Results include evidence, source, collection time and match status in a stable structure.
- [ ] 6.5 **(Claude)** Tool-call audit records (tool, args hash, tenant, latency, outcome).
- [ ] 6.6 **(Claude)** MCP integration tests using the SDK client: tool listing, schemas, valid call, malformed arguments rejected, cross-tenant blocked, error shape.
- [ ] 6.7 **(you)** Connect the MCP server to Claude Code locally and ask the demo question (a good early manual check).
- [ ] 6.8 **(Claude)** `docs/mcp/` with tool catalogue and connection instructions.

**Done when:** the MCP tests pass and Claude Code can call `get_affected_assets` against the seeded data.

### Phase 7 — Tool registry and AI agent → *Checkpoint 7* (1–1½ weeks)

**Goal:** the in-app analyst discovers the right tool, calls it, and answers with evidence.

- [ ] 7.1 **(Claude)** ADR 0007. Model adapter interface plus a **mock provider** (deterministic, used in tests and CI).
- [ ] 7.2 **(you)** Create the model provider key (A5) with a spend limit.
- [ ] 7.3 **(Claude)** Tool registry: metadata from spec §7 (domain, entities, risk_level, permissions, tags) for the Phase 6 tools.
- [ ] 7.4 **(Claude)** Discovery pipeline, MVP version: filter by permission/risk → keyword/entity match → top-k schemas to the model. (Semantic search is post-MVP.)
- [ ] 7.5 **(Claude)** Agent loop: bounded steps (for example ≤ 6 tool calls), validated arguments, server-side authorization, retrieved content treated as untrusted data (prompt-injection guard in the system prompt and by structure).
- [ ] 7.6 **(Claude)** Response format: answer, confirmed vs possible vs unknown separated, cited evidence with source and timestamps, staleness warning when the sync is old, and a full tool trace.
- [ ] 7.7 **(Claude)** Spring Boot `POST /api/analyst/ask` proxy (auth + audit), streaming optional.
- [ ] 7.8 **(Claude)** Evaluation starter: 15–20 questions in `tests/evaluation/` (grows to 50–100 post-MVP) scoring tool choice, arguments, groundedness and refusals of unsupported claims. Run with the mock provider in CI and the real provider manually.
- [ ] 7.9 **(Claude)** Usage/cost logging per request (spec §22).

**Done when:** the demo question gives a correct, evidence-backed answer through the real provider, and the evaluation set passes its thresholds.

### Phase 8 — Basic web UI → *Checkpoint 8* (1½–2 weeks)

**Goal:** the end-to-end demo works in a browser.

- [ ] 8.1 **(Claude)** Next.js (App Router, TypeScript, Tailwind), OIDC login via Keycloak (Auth.js or similar). The browser talks only to Spring Boot.
- [ ] 8.2 **(Claude)** Security Overview: vulnerability counts, KEV count, affected critical assets, **last successful sync per source** (spec §20.3).
- [ ] 8.3 **(Claude)** Data Sources page: sync status table, manual sync (admin), inventory upload with reject report.
- [ ] 8.4 **(Claude)** Vulnerability detail and affected-assets view with match status badges and evidence links.
- [ ] 8.5 **(Claude)** AI Analyst: chat, expandable tool trace (tool, arguments, result summary), evidence panel, staleness banner.
- [ ] 8.6 **(Claude)** Small Cytoscape.js view: asset → software → CVE for one CVE (a taste of the Graph Explorer).
- [ ] 8.7 **(Claude)** Playwright tests: login, overview loads, affected-assets view, analyst answer shows trace, a viewer cannot trigger a sync.

**Done when:** a fresh clone can run the spec §18 demo steps 1–6 and 9 locally.

### Phase 9 — Quality, CI and portfolio readiness → *Checkpoint 9* (1 week)

- [ ] 9.1 **(Claude)** GitHub Actions: lint + unit tests per service, integration tests with service containers, Playwright on main, dependency and secret scanning (Dependabot, CodeQL or similar).
- [ ] 9.2 **(Claude)** Security tests in `tests/security/`: tenant isolation across REST, MCP and agent; malformed tool args; JWT tampering.
- [ ] 9.3 **(Claude)** Structured JSON logs with correlation IDs; secrets redacted; basic metrics endpoint.
- [ ] 9.4 **(Claude)** `docs/threat-model/` STRIDE-style threat model for the MVP.
- [ ] 9.5 **(Claude)** README: architecture diagram, quick start, demo script, **implemented vs planned** table (spec §18).
- [ ] 9.6 **(you)** Record a 5-minute demo video and screenshots; make the repo public when ready.

**Done when:** CI is green on `main`, and someone else reproduces the demo from the README (spec §19).

---

## 6. Post-MVP releases (backlog order)

| Release | Contents | Spec refs |
|---|---|---|
| **R2 — Threat intel breadth** | MITRE ATT&CK import (A7), Threat Intelligence MCP group, restricted URL import with full SSRF protections (allowlist, DNS/IP checks, redirect revalidation, size/time limits, restricted parser worker), STIX 2.1 bundle upload. | §2B, §2D, §8 |
| **R3 — Analysis** | Attack Path MCP + page (bounded BFS/shortest path, weighted ranking with MAGE), Incident Investigation MCP + timeline, Risk & Reporting with an explainable score. | §6, §9 |
| **R4 — Platform** | Scheduler + Redis queues, retries/dead-letter, semantic tool search + reranking, 50–100 question evaluation suite, multi-provider adapter, k6 performance tests, OWASP ZAP. | §7, §13, §20.2 |
| **R5 — Deployment** | Hosting decision (ADR 0009), HTTPS, private databases, managed secrets, backups, monitoring, remote authenticated MCP endpoint. | §16 |
| **R6 — Enterprise** | Real OIDC/SSO, granular RBAC, tenant admin, authorized internal integrations (SIEM/EDR/scanner), human-approved ticket creation. | §2E, §20.2 |

---

## 7. Best practices

### Working with Claude Code
- One task (from this roadmap) per session or PR. Ask for a plan first on anything larger than a task.
- Keep `CLAUDE.md` short and point it at the spec, this roadmap and the ADRs.
- Commit a working state before each task; review every diff, especially auth, tenant filtering and anything touching secrets.
- Ask for the completion report from spec §21.2 every time.
- Review every new dependency (name, maintainer, version) before accepting it.

### Git and repository
- Branch per task (`phase3/nvd-connector`), small PRs, squash-merge, Conventional Commit messages.
- Protected `main`, required CI, secret scanning with push protection.
- Never commit `.env`, real keys, real company data or recorded fixtures that contain an API key.

### Secrets
- Local: `.env` (git-ignored) loaded by Compose. CI: GitHub Secrets. Hosted: the host's secret store.
- The model never sees credentials. Logs redact tokens. Errors stored in `error_summary` are sanitized.

### Security (defensive and read-only)
- Every query takes the tenant from trusted context and filters on it, enforced in the service layer, not only the controller.
- Parameterized Cypher and SQL everywhere; no string concatenation.
- Bounded traversals (hop limits, result limits, timeouts).
- External feed content is untrusted: validate its schema and never execute or render it as HTML.
- The LLM is never the authorization authority; tools re-check permissions.

### Data integrity
- Stable IDs + `MERGE` = idempotent imports. Test reimports explicitly.
- Provenance on every fact: source, URL/reference, collected_at, content_hash.
- Separate observed facts (`confirmed`) from inferred ones (`possible`) in storage, API, MCP and UI wording.

### Testing
- Test-first for parsers, matching and the risk formula (pure logic).
- Real databases in integration tests (Testcontainers); no mocking Memgraph for query tests.
- No live external calls in CI: recorded fixtures for NVD/KEV, mock provider for AI.
- Keep a regression test for each spec §13 "important test case".

### Code
- Python: type hints, pydantic models at boundaries, `ruff` + `mypy`, `uv` lockfile.
- Java: records for DTOs, constructor injection, Spotless/Checkstyle, Maven wrapper.
- Frontend: strict TypeScript, ESLint + Prettier, no secrets in `NEXT_PUBLIC_*`.
- Shared contracts: OpenAPI for REST; JSON Schema for tool inputs and import formats.

---

## 8. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Three languages and five runtimes slow early progress | High | Strict vertical slice; no module is started before its phase; Compose starts everything with one command. |
| NVD rate limits or outages during development | Medium | API key, recorded fixtures, incremental sync, single-CVE import for demos. |
| Version matching edge cases produce false "affected" claims | High (credibility) | Default to `unknown`; table-driven tests; only `confirmed` counts as exposure. |
| AI hallucinating assets or CVEs | High | Answers built only from tool results; evaluation set checks groundedness; mock provider in CI. |
| Model cost overrun | Low–Medium | Provider spend limit, step caps, usage logging. |
| Docker memory pressure on a laptop | Medium | Allocate ≥ 8 GB; Compose profiles so Keycloak/Lab start only when needed. |
| Scope creep toward the 46-tool vision | High | This roadmap's phase gates; future items stay in Section 6 until the MVP is done. |

---

## 9. Definition of done (every task)

1. Code and tests written; the relevant test command was run and passed (paste the command and result).
2. No secrets added; `.env.example` updated if new config was added.
3. Docs/ADR updated if commands, APIs, schemas or architecture changed.
4. Tenant isolation considered for any new data access.
5. Merged via PR with CI green.

---

## 10. Immediate next steps

1. **(you)** Review Sections 1.2 and 4; change any recommendation you disagree with.
2. **(you)** Create the GitHub repo (A1) and install Docker Desktop (A2). Request the NVD key (A3) now, since activation can take a while.
3. **(Claude)** Write a detailed implementation plan for **Phases 0–2** and execute it task by task.
