---
name: build-roadmap
description: Master tracker for the ThreatLens AI MVP build. Use when starting, resuming or reporting progress on any ThreatLens development module (repo setup, Docker infra, Memgraph graph, NVD/KEV ingestion, matching, Spring Boot API, MCP tools, AI agent, web UI, CI/portfolio). Lists the 10 modules, their status, and the MCP servers each one needs.
---

# ThreatLens AI — Build Roadmap Tracker

Source documents: `docs/ROADMAP.md` (full roadmap, gaps G1–G10, ADR list) and the spec (`docs/PROJECT_SPEC.md`, §20 is the scope baseline). Each module's detailed tasks live in `modules/module-NN.md` in this folder.

## How to use this skill

1. Find the first module below whose status is not `done`.
2. Read its `modules/module-NN.md` fully. Confirm the previous module's "Done when" is met.
3. Check the **Required MCPs** for that module are connected (see the matrix). If one is missing, tell the user and use the CLI fallback noted in the module file — don't silently skip verification.
4. Do **one task at a time**: explain files to be touched, implement, run tests, report exact commands and results.
5. Tick the task checkbox in the module file and update the status table below. Never mark a module `done` unless its "Done when" was actually run and passed.
6. Stop at manual steps marked **(you)** (accounts, keys, approvals) and ask the user.

## Ground rules (from CLAUDE.md / spec §20–21)
- MVP scope only; defensive and read-only; synthetic data.
- Never invent CVE↔product or product↔asset matches; default to `unknown`.
- Tenant comes from trusted context, never from tool arguments or the model.
- Parameterized queries; secrets only in `.env`/secret stores; external content is untrusted.
- Commit working state before each larger task; small PRs.

## Module tracker

Status values: `todo` · `in-progress` · `done`

| # | Module | Roadmap phase | Checkpoint | Est. | Status | File |
|---|---|---|---|---|---|---|
| 01 | Repository and workspace | 0 | — | ½ wk | in-progress | [module-01](modules/module-01.md) |
| 02 | Local infrastructure | 1 | 1 Local foundation | ½ wk | done | [module-02](modules/module-02.md) |
| 03 | Graph model and seed | 2 | 2 Graph slice | 1 wk | done | [module-03](modules/module-03.md) |
| 04 | NVD + CISA KEV ingestion | 3 | 3 External intelligence | 1–1½ wk | done | [module-04](modules/module-04.md) |
| 05 | Inventory import and matching | 4 | 4 Asset matching | 1 wk | done | [module-05](modules/module-05.md) |
| 06 | Backend API and security boundary | 5 | 5 Backend API | 1–1½ wk | done | [module-06](modules/module-06.md) |
| 07 | MCP tools | 6 | 6 MCP | 1 wk | in-progress | [module-07](modules/module-07.md) |
| 08 | Tool registry and AI agent | 7 | 7 AI investigation | 1–1½ wk | todo | [module-08](modules/module-08.md) |
| 09 | Basic web UI | 8 | 8 Basic web UI | 1½–2 wk | todo | [module-09](modules/module-09.md) |
| 10 | Quality, CI, portfolio readiness | 9 | 9 Portfolio readiness | 1 wk | todo | [module-10](modules/module-10.md) |

## Required MCPs per module

Legend: **R** required · **Rec** recommended · **O** optional · **Own** built by this project in the named module.
MCP names are generic; confirm the exact server/package and install steps before use. Where none is available, the module file lists a CLI fallback (`gh`, `docker`, `psql`, `mgconsole`).

| Module | GitHub | Memgraph | PostgreSQL | Context7 / docs | Fetch / web | Playwright | threatlens-* (own) |
|---|---|---|---|---|---|---|---|
| 01 Repo | Rec | — | — | — | — | — | — |
| 02 Infra | O | Rec | Rec | — | — | — | — |
| 03 Graph | O | Rec | — | Rec (Memgraph syntax) | — | — | — |
| 04 Ingestion | — | Rec | Rec | O | Rec | — | — |
| 05 Matching | — | Rec | O | O | — | — | — |
| 06 Backend API | O | — | Rec | Rec (Spring/Keycloak) | — | — | — |
| 07 MCP tools | — | O | — | Rec (MCP SDK) | — | — | **Own (produced)** |
| 08 Agent | — | — | O | Rec (model SDK) | — | — | **R** (from 07) |
| 09 Web UI | — | — | — | Rec (Next.js etc.) | — | Rec | R (via API) |
| 10 CI/portfolio | Rec | — | — | O | — | Rec | — |

### Accounts and secrets by module

| Module | Account / key | Owner | Notes |
|---|---|---|---|
| 01 | GitHub + 2FA, repo, branch protection | you | A1 |
| 02 | Docker Desktop | you | A2, WSL 2, ≥ 8 GB RAM |
| 04 | NVD API key | you | A3, free, activation by email; request early |
| 06 | Keycloak (Docker) | — | A6, no account |
| 08 | AI model provider key + spend limit | you | A5, e.g. Anthropic Console |
| 10 | GitHub Actions secrets (should need none) | you | A10 |
| Post-MVP | Hosting, domain | you | A8/A9, decide after local MVP |

## Decision records (ADRs) by module

| ADR | Topic | Module |
|---|---|---|
| 0001 | Toolchain and versions | 01 |
| 0002 | Tenant model (global vs tenant data) | 03 |
| 0003 | Product identity and version matching | 05 |
| 0004 | Spring ↔ Python contract and service auth | 06 |
| 0005 | Auth provider (Keycloak) | 06 |
| 0006 | MCP deployment shape and tenant context | 07 |
| 0007 | AI provider and adapter | 08 |
| 0008 / 0009 | Scheduling / hosting | post-MVP |

## Progress log

Append one line per completed task or module: `YYYY-MM-DD · module · task · result (commands run, pass/fail)`.

- 2026-11-15 · 01 · 0.1–0.7 · repo threatlens-ai created (private), skeleton, docs, CLAUDE.md, config files, README, ADR 0001 committed and pushed to main; .env verified ignored, git status clean. 0.8 pending (you).
- 2026-11-19 · 02 · 1.1–1.5 · Docker Desktop + WSL 2 installed; compose (memgraph-mage 3.14.0, postgres 17.12, lab profile) healthy; scripts/verify-infra.sh passes on a fresh clone of feat/local-infra (up --wait, verify exit 0, down -v). PR #1 merged; module done.
- 2026-11-19 · 03 · 2.1–2.8 · ADR 0002, schema.cypher, inventory JSON Schema, synthetic seed (2 tenants, 16 assets, 3 CVEs), idempotent loader, affected_assets query; `uv run pytest` 16 passed against Memgraph 3.14.0; mutation check (tenant filter removed) failed 5 tests as expected; seed CLI x3 gave 33 nodes / 40 rels each time. PR #2 merged; module done.
- 2026-11-19 · 04 · 3.2–3.8 · NVD+KEV connectors, source_sync (Flyway V1), CLI + internal API, single-CVE import. `uv run pytest` 65 passed (fixtures, no live network). Live: KEV 1786 received/created, rerun 0 created/0 updated; NVD 12h window 910 created, rerun 0; real CVE-2021-44228 has NVD+KEV props. 3.1 (NVD key) pending (you); runs used keyless limits. PR #3 merged.
- 2026-11-19 · 05 · 4.1–4.5 · ADR 0003, CPE/version matcher, CSV/JSON importer with reject report (Flyway V2), match service, freshness query. `uv run pytest` 205 passed; mutation checks (bound off-by-one, name-only cap removed, missing version -> in-range) each failed tests. Live: real CVE-2021-44228 vs demo log4j assets gave confirmed/not_affected/unknown/possible; rematch 0 created/4 unchanged. PR #4 merged; module done.
- 2026-11-19 · 06 · 5.1–5.9 · ADRs 0004/0005/0011 (Spring Boot 4.1.2 chosen over 3.x by the owner), Keycloak 26.8.2 realm (3 roles, 2 tenants, 6 dummy users), Spring Boot resource server, service-JWT client, audit table (Flyway V3), rate limits, RFC 9457 problems, OpenAPI export + REST Client file. `./mvnw test` 70 passed (Testcontainers + REST Assured); Python 245 passed; mutation checks (viewer may sync / missing-tenant fallback / open /api/**; Python trusting a tenant_id query param) each failed tests. Live with real Keycloak tokens: 401/403 correct, dave (TENANT-OTHER) sees only ASSET-O05 even when spoofing, bob sees ASSET-013/015/016, correlation id traced Spring -> Python. PR #5 merged; module done.
- 2026-11-19 · 07 · 6.1–6.6, 6.8 · ADR 0006, `mcp_tools` package (official MCP SDK 2.3.0, two stdio servers, 8 read-only tools), strict arguments (injected tenant_id rejected), stable envelope and error shape, `tool_call_audit` (Flyway V4), docs/mcp catalogue (drift-tested) and `.mcp.json`. `uv run pytest` 336 passed (incl. real stdio subprocess runs); 4 mutation checks (tenant filter, strict args, error-text leak, role check) each failed tests. Live via stdio from `.mcp.json`: DEMO sees ASSET-013 confirmed/016 possible/015 unknown, TENANT-OTHER sees only ASSET-O05, injected tenant rejected, audit rows written. 6.7 (connect Claude Code and ask the demo question) pending (you). PR pending merge.
