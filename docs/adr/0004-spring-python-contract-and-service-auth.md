# ADR 0004 - Spring Boot to Python contract and service authentication

- Status: Accepted
- Date: 2026-11-19
- Addresses roadmap gaps G5 and G6

## Context
Users authenticate with the Spring Boot backend, but graph and intelligence logic lives in the Python service (the MCP SDK and the agent are Python, see G5). The Python API must never be reachable by an unauthenticated caller, and the tenant must never be taken from anything the user or a model controls.

## Decision
1. **Spring Boot is the only public entry point.** The Python service listens on `127.0.0.1` (or the private Docker network) and is never published.
2. **Internal REST, versioned under `/internal/v1`:**
   | Method and path | Role needed | Purpose |
   |---|---|---|
   | `GET /vulnerabilities/{cve_id}` | any | CVE details, KEV flags, evidence |
   | `GET /vulnerabilities/{cve_id}/affected-assets?environment=` | any | tenant-scoped matches with freshness |
   | `GET /sources/status` | any | `source_sync` rows |
   | `POST /sources/{source_id}/sync` | `ADMIN` | start an NVD or KEV sync; answers `202` and runs in the background |
   | `POST /vulnerabilities/import` | `ADMIN` | import one CVE (demo path) |
3. **Service JWT** on every call, header `Authorization: Bearer <jwt>`:
   - HS256, shared secret of at least 32 bytes from `INTERNAL_JWT_SECRET` (both sides refuse to start with a shorter one);
   - lifetime 60 seconds, new token per call;
   - claims: `iss=threatlens-backend`, `aud=threatlens-intelligence`, `sub` (user id), `tenant_id`, `roles`, `jti`, `iat`, `exp`;
   - Python accepts HS256 only (never `none` or another algorithm), requires all claims, and validates `iss`, `aud` and `exp`.
4. **Tenant comes from the JWT claim only.** The Python API has no tenant parameter. Python re-checks roles from the JWT (defense in depth); the model or UI can never choose a tenant.
5. **Correlation ID**: Spring generates or validates `X-Correlation-Id` (`[A-Za-z0-9-]{8,64}`), forwards it, and Python logs it and echoes it in the response.
6. **Errors**: Python returns normal HTTP status codes. Spring maps them to RFC 9457 problem details and never forwards Python response bodies to the browser.

## Consequences
- A leaked service JWT is useful for at most 60 seconds, and only for the user and tenant it was minted for.
- A shared HS256 secret means either service could mint tokens. Accepted for one trust boundary on a private network. If the services are ever separated by a network or team boundary, switch to an asymmetric key (EdDSA) or mutual TLS without changing the endpoint contract.
- The Module 04 static `INTERNAL_API_TOKEN` is removed; one authentication scheme remains.
