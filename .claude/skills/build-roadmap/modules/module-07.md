# Module 07 — MCP tools (Roadmap Phase 6)

**Duration:** ~1 week · **Checkpoint 6:** MCP · **Depends on:** Module 06 (service functions from Modules 03–05)
**Goal:** `get_affected_assets` (plus companions) is callable by any MCP client.

## Required MCPs
| MCP | Why | Required? |
|---|---|---|
| **threatlens-vulnerability** (this project's own MCP server, built here) | Manual end-to-end check from Claude Code | Produced by this module |
| **threatlens-asset** (this project's own MCP server) | Same | Produced by this module |
| Context7 (docs MCP) | Official Python MCP SDK docs | Recommended |
| Memgraph MCP | Cross-check tool output against raw graph | Optional |

## Spec issues addressed here
- **G7** Tenant context: local/demo from server config (env), never a tool argument; remote (post-MVP) from the authenticated MCP session.
- One tested service function backs REST, MCP and agent — never rewrite the query.

## Tasks
- [ ] 6.1 **(Claude)** ADR 0006 — MCP deployment shape (one Python package, two server entrypoints, stdio first).
- [ ] 6.2 **(Claude)** Official MCP Python SDK, two servers:
  - Vulnerability Intelligence: `get_affected_assets`, `get_vulnerability_details`, `search_vulnerabilities`, `get_vulnerability_evidence`.
  - Asset Intelligence: `search_assets`, `get_asset_details`, `get_asset_software`, `get_critical_assets`.
- [ ] 6.3 **(Claude)** Tools call the same service functions as REST; JSON Schemas match spec §6; tenant from trusted context.
- [ ] 6.4 **(Claude)** Stable result structure: evidence, source, collection time, match status.
- [ ] 6.5 **(Claude)** Tool-call audit records (tool, args hash, tenant, latency, outcome).
- [ ] 6.6 **(Claude)** MCP integration tests with the SDK client: listing, schemas, valid call, malformed args rejected, cross-tenant blocked, error shape.
- [ ] 6.7 **(you)** Connect the MCP server to Claude Code locally and ask the demo question.
- [ ] 6.8 **(Claude)** `docs/mcp/` tool catalogue and connection instructions.

## Best practices for this module
- Read-only tools only. Validate arguments server-side. Bounded results.
- Tools re-check permissions; the LLM is never the authorization authority.

## Done when
MCP tests pass and Claude Code can call `get_affected_assets` against seeded data.
