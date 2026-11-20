# Module 09 — Basic web UI (Roadmap Phase 8)

**Duration:** ~1½–2 weeks · **Checkpoint 8:** Basic web UI · **Depends on:** Module 08
**Goal:** the end-to-end demo works in a browser.

## Required MCPs
| MCP | Why | Required? |
|---|---|---|
| Playwright MCP | Drive and verify UI flows, screenshots | Recommended |
| Context7 (docs MCP) | Next.js App Router, Auth.js, Tailwind, Cytoscape.js docs | Recommended |
| Built-in browser / Claude in Chrome | Visual check of pages | Optional |

## Tasks
- [x] 8.1 **(Claude)** Next.js (App Router, TypeScript, Tailwind); OIDC login via Keycloak (Auth.js or similar). Browser talks only to Spring Boot.
- [x] 8.2 **(Claude)** Security Overview: vulnerability counts, KEV count, affected critical assets, **last successful sync per source** (spec §20.3).
- [x] 8.3 **(Claude)** Data Sources page: sync status table, manual sync (admin), inventory upload with reject report.
- [x] 8.4 **(Claude)** Vulnerability detail + affected-assets view with match-status badges and evidence links.
- [x] 8.5 **(Claude)** AI Analyst: chat, expandable tool trace (tool, args, result summary), evidence panel, staleness banner.
- [x] 8.6 **(Claude)** Small Cytoscape.js view: asset → software → CVE for one CVE.
- [x] 8.7 **(Claude)** Playwright tests: login, overview loads, affected-assets view, analyst answer shows trace, viewer cannot trigger a sync.

## Best practices for this module
- Strict TypeScript, ESLint + Prettier; no secrets in `NEXT_PUBLIC_*`.
- UI never describes stale data as live; show both intel and inventory timestamps.
- Distinguish confirmed vs possible vs unknown visually.

## Done when
A fresh clone can run spec §18 demo steps 1–6 and 9 locally.
