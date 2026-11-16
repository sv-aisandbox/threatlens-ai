# Module 02 — Local infrastructure (Roadmap Phase 1)

**Duration:** ~½ week · **Checkpoint 1:** Local foundation · **Depends on:** Module 01
**Goal:** Memgraph and PostgreSQL run locally and healthy.

## Required MCPs
| MCP | Why | Required? |
|---|---|---|
| Memgraph MCP (official Memgraph MCP server) | Run test Cypher against the local graph | Recommended |
| PostgreSQL MCP | Inspect tables, run `SELECT 1`/schema checks | Recommended |
| GitHub MCP | PRs for compose changes | Optional |

(Verify current names/install steps for each server before relying on them; the plain `docker`, `psql`/`mgconsole` CLIs are a fallback.)

## Accounts / manual actions
- **A2 (you):** Install Docker Desktop (WSL 2 backend). Docker Hub login optional.

## Tasks
- [ ] 1.1 **(you)** Install Docker Desktop.
- [ ] 1.2 **(Claude)** `docker-compose.yml`: `memgraph/memgraph-mage`, `memgraph/lab`, `postgres`, private network, named volumes, ports bound to `127.0.0.1` only.
- [ ] 1.3 **(Claude)** Health checks for both databases; pinned image tags (no `latest`).
- [ ] 1.4 **(Claude)** `scripts/verify-infra`: `RETURN 1` on Memgraph, `SELECT 1` on Postgres.
- [ ] 1.5 **(Claude)** README Quick start: start, verify, stop, reset volumes.

## Best practices for this module
- Databases never exposed beyond localhost; credentials from `.env`.
- Pin image versions; record them in ADR 0001.
- Use Compose profiles so optional services (Lab, later Keycloak) start only when needed.

## Done when
`docker compose up -d` plus the verify script pass on a fresh clone.
