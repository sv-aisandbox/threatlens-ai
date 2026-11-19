# ADR 0006 - MCP deployment shape and tenant context

- Status: Accepted
- Date: 2026-11-19
- Addresses roadmap gap G7

## Context
MCP clients (Claude Code today, the in-app agent in Module 08) call tools that read the security graph. The tenant must never be chosen by the model, and a stdio server has no signed-in user.

## Decision
1. **One Python package, two server entrypoints, stdio first.** The package `mcp_tools` lives in `intelligence-service/` so it shares the uv environment and the tested query functions. Entry points:
   - `python -m mcp_tools.vulnerability_server` (server name `threatlens-vulnerability`): `get_affected_assets`, `get_vulnerability_details`, `search_vulnerabilities`, `get_vulnerability_evidence`.
   - `python -m mcp_tools.asset_server` (server name `threatlens-asset`): `search_assets`, `get_asset_details`, `get_asset_software`, `get_critical_assets`.
   The `mcp-servers/` folders hold launch instructions only. A repository-level `.mcp.json` lets Claude Code start both.
2. **Tenant and roles are trusted server configuration, never tool input.** For local and demo use they come from the environment at startup (`THREATLENS_TENANT_ID`, `THREATLENS_ROLES`, default role `VIEWER`) and are validated; the server refuses to start with a missing or malformed tenant. No tool schema has a tenant property. Unknown arguments, such as an injected `tenant_id`, are **rejected** with an error instead of being silently ignored.
   Remote use (post-MVP, streamable HTTP) will derive tenant and roles from the authenticated MCP session token; the tool code does not change because it only reads the server context.
3. **Read-only tools only**, all annotated `readOnlyHint`. Every tool re-checks the role in the trusted context; the model is never the authorization authority.
4. **One tested service function backs every interface.** Tools call the same `graph_queries` functions as the REST API (`get_affected_assets_with_freshness`, `get_vulnerability`) and new ones added there (asset and search queries). No query is written inside a tool.
5. **Bounded and validated.** Arguments carry JSON Schema patterns, enums and numeric limits; list results are capped and flag `truncated`.
6. **Stable result and error shapes.** Results are an envelope (`tool`, `scope`, `tenant_id`, `generated_at`, results, `freshness`/`warnings` where relevant, `truncated`, `untrusted_fields`). Errors are `{"error": {"code", "message", "correlation_id"}}` with codes `invalid_argument`, `not_found`, `forbidden`, `unavailable`, `internal_error`. Messages never repeat the caller's input, upstream text or stack traces. Asking for another tenant's asset returns the same `not_found` as a nonexistent one.
7. **Audit.** Each call writes a `tool_call_audit` row: server, tool, SHA-256 of the canonical arguments, tenant, actor, latency, outcome, error code and correlation ID. Raw arguments and results are never stored. A failed audit write is logged and does not fail the tool call.
8. **External text is untrusted.** Descriptions and KEV text come from public feeds. Each result lists them in `untrusted_fields`, and the server instructions tell the client to treat them as data, never as instructions (prompt-injection defense).
9. **stdio hygiene.** Nothing is written to stdout except protocol messages; logs go to stderr.

## Consequences
- Claude Code and any other MCP client can use the same tools with the same guarantees as the REST API.
- Changing the tenant means restarting the server with a different environment, which is intended for a local single-tenant demo.
- `mcp` 2.x moved some APIs from 1.x (`MCPServer` replaces `FastMCP`); the version is pinned to `>=2.3,<3`.
