# Web UI

Design decision: [ADR 0012](../adr/0012-web-ui-bff.md). Code: `frontend/`.

```
Browser ──cookie──> Next.js (127.0.0.1:3000) ──Bearer user token──> Spring Boot (8080) ──service JWT──> Python (8000) ──> Memgraph / PostgreSQL
   │                    │
   └── Keycloak login (PKCE) ◄─── next-auth refreshes the token server-side
```

## Pages
| Path | Shows | Who |
|---|---|---|
| `/login` | Sign in with Keycloak | everyone |
| `/` | Counts, KEV, affected critical assets, per-source last successful sync, inventory timestamp, stale banner, top exposures | all roles |
| `/vulnerabilities` | Search by CVE id or keyword, KEV only, minimum score | all roles |
| `/vulnerabilities/CVE-…` | Details, source evidence links, your affected assets with match badges, Cytoscape graph (asset → software → CVE) | all roles |
| `/sources` | Sync status table, manual sync, inventory upload with reject report, import history | sync and upload: ADMIN; history: ADMIN and SECURITY_ANALYST |
| `/analyst` | Chat, findings grouped confirmed / possible / unknown, evidence panel, expandable tool trace (tool, arguments, result summary) | SECURITY_ANALYST, ADMIN (a viewer can try and sees the server's refusal) |

## Calls the browser may make through `/api/backend/…`
The list is in `frontend/src/lib/proxy-policy.ts` (overview, source status and sync, vulnerability search, detail, graph and affected assets, inventory import and history, analyst ask). Anything else returns 404 before reaching Spring.

## Settings (server-side only)
`NEXTAUTH_URL`, `NEXTAUTH_SECRET`, `KEYCLOAK_ISSUER`, `KEYCLOAK_WEB_CLIENT_ID`, `BACKEND_URL` (see `frontend/.env.example`).

## Checks
```bash
cd frontend
pnpm test         # unit tests (token claims, proxy allowlist, formatting, graph conversion)
pnpm typecheck && pnpm lint && pnpm format:check
pnpm build
pnpm e2e          # needs the running stack (scripts/start-all.ps1) and Google Chrome
```
