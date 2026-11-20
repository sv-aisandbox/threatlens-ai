# ADR 0012 - Web UI: Next.js with a server-side proxy (BFF)

- Status: Accepted
- Addresses roadmap Module 09 (basic web UI)

## Context
The roadmap says the browser talks only to Spring Boot and that login uses Keycloak through Auth.js or similar. Keycloak access tokens last 5 minutes, and a token that lives in browser JavaScript can be stolen by any script injection.

## Decision
- **Next.js 16 (App Router), React 19, TypeScript 5.9 (strict), Tailwind 4**, pnpm. TypeScript 7 and `next-auth` v5 beta were not used because they are not yet stable for this stack.
- **next-auth 4.24** with the Keycloak provider, authorization-code flow with PKCE, against the public client `threatlens-web` (no secret exists).
- **The browser never holds a token.** The access and refresh tokens stay in next-auth's encrypted, HTTP-only cookie. Server components and one route handler (`/api/backend/[...path]`) read it and call Spring Boot with `Authorization: Bearer <user token>`. Spring Boot is still the only service that validates tokens and decides access (roles, tenant). This is a deliberate reading of "the browser talks only to Spring Boot": the UI server is a thin pass-through in front of it.
- The proxy only forwards an **allowlist** of method and path pairs, rejects `..`, `//` and `%` in paths, and drops any `tenant_id` query parameter. The tenant always comes from the token (ADR 0002).
- Roles and tenant are read from the access token **for display only** (hide the admin buttons). The server's 403 is the real control, and the end-to-end tests call the API directly to prove it.
- The session polls every 2 minutes so next-auth refreshes the token before it expires. An expired token is treated as signed out, never reused.
- **No `NEXT_PUBLIC_*` variables.** Every setting is server-side.
- Feed and model text is rendered as plain text (React escapes it). Source links are shown only if they are `http(s)`.
- **Freshness is never hidden:** the overview and every CVE page show NVD, CISA KEV and inventory timestamps side by side, with a banner when data is older than 48 hours or was never loaded. Confirmed, possible and unknown matches differ by icon, text and line style, not colour alone.

## Consequences
- One extra hop (browser to Next to Spring). Acceptable for an internal tool.
- The proxy buffers uploads (at most 5 MB, enforced again by Spring).
- Cytoscape renders on canvas, so the CVE page also shows the same information as a table for keyboard and screen-reader users.
- The end-to-end tests need the full stack and a Chrome install (`scripts/start-all.ps1`).
