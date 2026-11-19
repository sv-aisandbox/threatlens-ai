# ADR 0005 - Authentication provider: Keycloak (local OIDC)

- Status: Accepted
- Date: 2026-11-19
- Addresses roadmap gap G8

## Context
The platform needs real OIDC tokens with roles and a tenant, without paying for or registering a hosted identity service during development.

## Decision
- **Keycloak 26.8.2** runs in Docker Compose (`--profile auth`, port `127.0.0.1:8081`), realm `threatlens`, imported from `auth/keycloak/threatlens-realm.json`. No account is needed.
- **Roles** (realm roles): `ADMIN`, `SECURITY_ANALYST`, `VIEWER`.
- **Tenant**: a user attribute `tenant_id` mapped to an access-token claim `tenant_id`. Tenant is therefore decided by whoever administers identities, not by the caller.
- **Audience**: access tokens carry `aud=threatlens-api`; the backend rejects tokens without it.
- **Clients**: `threatlens-web` (authorization code with PKCE, for the UI) and `threatlens-dev` (password grant, for the REST Client file and local scripts only; never enable in a shared environment).
- **Demo identities are dummy**: six users across `TENANT-DEMO` and `TENANT-OTHER`, one with no role and one with no tenant to exercise denials. The realm file contains only dummy passwords and no real secrets.
- The Spring Boot backend is an OAuth2 resource server: it validates signature (JWKS), issuer, expiry and audience, and maps `realm_access.roles` to authorities.

## Consequences
- Tokens are portable: replacing Keycloak with another OIDC provider only needs claim mapping changes.
- `start-dev` stores data in the container, so users reset on a fresh container, which suits a demo. No Keycloak admin user is bootstrapped; create one with `kc.sh bootstrap-admin` if the console is needed.
- Issuer must match exactly, so clients must use `http://127.0.0.1:8081` (not `localhost`).
