# Module 10 — Quality, CI and portfolio readiness (Roadmap Phase 9)

**Duration:** ~1 week · **Checkpoint 9:** Portfolio readiness · **Depends on:** Module 09
**Goal:** reproducible, tested, documented demo.

## Required MCPs
| MCP | Why | Required? |
|---|---|---|
| GitHub MCP | Workflows, CI runs, secrets, Dependabot/code scanning | Recommended |
| Playwright MCP | Screenshots, E2E in CI | Recommended |
| Context7 (docs MCP) | GitHub Actions, CodeQL docs | Optional |

## Accounts / manual actions
- **A10 (you):** GitHub Actions secrets (CI should need **no real keys** — fixtures + mock model).
- Hosting/domain (A8/A9) are **post-MVP**; decide only after local verification.

## Tasks
- [x] 9.1 **(Claude)** GitHub Actions: lint + unit tests per service, integration tests with service containers, Playwright on main, dependency and secret scanning (Dependabot, CodeQL or similar).
- [x] 9.2 **(Claude)** `tests/security/`: tenant isolation across REST, MCP and agent; malformed tool args; JWT tampering.
- [x] 9.3 **(Claude)** Structured JSON logs with correlation IDs; secrets redacted; basic metrics endpoint.
- [x] 9.4 **(Claude)** `docs/threat-model/` STRIDE-style threat model for the MVP.
- [x] 9.5 **(Claude)** README: architecture diagram, quick start, demo script, **implemented vs planned** table (spec §18).
- [ ] 9.6 **(you)** Record 5-minute demo video and screenshots; make repo public when ready.

## Post-MVP backlog (do NOT start before this module is done)
R2 Threat-intel breadth (ATT&CK, URL import + SSRF protections, STIX) · R3 Analysis (attack paths, incidents, risk) · R4 Platform (scheduler/Redis, semantic tool search, 50–100 evals, k6, ZAP) · R5 Deployment (ADR 0009) · R6 Enterprise (SSO, integrations). See `docs/ROADMAP.md` §6.

## Done when
CI is green on `main` and someone else reproduces the demo from the README (spec §19).
