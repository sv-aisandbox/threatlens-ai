# Module 06 — Backend API and security boundary (Roadmap Phase 5)

**Duration:** ~1–1½ weeks · **Checkpoint 5:** Backend API · **Depends on:** Module 05
**Goal:** an authenticated, tenant-aware API returns affected assets.

## Required MCPs
| MCP | Why | Required? |
|---|---|---|
| PostgreSQL MCP | Inspect audit table, Flyway state | Recommended |
| Context7 (docs MCP) | Spring Boot 3 / Spring Security resource server, Keycloak docs | Recommended |
| GitHub MCP | PRs, CI status | Optional |

## Accounts / manual actions
- **A6:** Keycloak runs in Docker — no account. Realm export with dummy users only.

## Spec issues addressed here
- **G5** Agent/service runs in Python; Spring Boot authenticates and forwards.
- **G6** Internal REST over the private network with short-lived service JWT.
- **G8** Keycloak local OIDC.
- **G9** Stay on latest Spring Boot **3.x** unless decided otherwise (record in an ADR).

## Tasks
- [ ] 5.1 **(Claude)** ADRs 0004 (Spring ↔ Python contract) and 0005 (auth provider).
- [ ] 5.2 **(Claude)** Keycloak in Compose; realm with roles `ADMIN`, `SECURITY_ANALYST`, `VIEWER`; demo users in two tenants.
- [ ] 5.3 **(Claude)** Spring Boot 3 (Java 21, Maven wrapper) OAuth2 resource server; tenant and role from token claims only.
- [ ] 5.4 **(Claude)** Endpoints: `GET /api/vulnerabilities/{cveId}`, `GET /api/vulnerabilities/{cveId}/affected-assets?environment=`, `GET /api/sources/status`, `POST /api/sources/{id}/sync` (admin).
- [ ] 5.5 **(Claude)** Spring → Python client with short-lived service JWT; FastAPI rejects calls without it.
- [ ] 5.6 **(Claude)** Audit table + filter: user, tenant, action, outcome, correlation ID, time; correlation ID propagated to Python.
- [ ] 5.7 **(Claude)** Validation (CVE regex, environment enum), rate limits, timeouts, RFC 9457 problem details.
- [ ] 5.8 **(Claude)** JUnit 5 + Testcontainers + REST Assured: 401 no token, 403 wrong role, **tenant A cannot read tenant B**, invalid CVE → 400.
- [ ] 5.9 **(Claude)** Export OpenAPI to `docs/api/` with a REST Client file.

## Best practices for this module
- Authorization enforced server-side in the service layer, not only controllers.
- Never trust tenant from request params; token claims only.

## Done when
All authorization and tenant tests pass; REST Client file demonstrates the flow.
