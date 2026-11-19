# Connecting an MCP client

The servers speak MCP over **stdio**: the client starts them as child processes. The tenant is set by environment variables on the server process, never by the model. Catalogue: [tools.md](tools.md).

## 1. Prepare the data (once)

```bash
docker compose up -d --wait                      # Memgraph + PostgreSQL
docker compose --profile migrate run --rm flyway  # database/migrations, including V4 tool_call_audit
cd intelligence-service
uv sync
uv run python -m ingestion.seed_loader            # synthetic demo organization
uv run python -m ingestion.cli import-cve CVE-2021-44228
uv run python -m ingestion.cli sync kev
uv run python -m ingestion.cli match              # computes confirmed / possible / unknown / not_affected
```

## 2. Claude Code (project configuration is already committed)

The repository root contains [`.mcp.json`](../../.mcp.json) defining both servers. Open the project in Claude Code and approve the two project servers when prompted, then check:

```text
/mcp
```

You should see `threatlens-vulnerability` and `threatlens-asset` connected. To use another tenant or role, set the variables before starting Claude Code (defaults are `TENANT-DEMO` and `VIEWER`):

```bash
export THREATLENS_TENANT_ID=TENANT-OTHER      # restart the servers after changing it
export THREATLENS_ROLES=VIEWER                # comma-separated: VIEWER, SECURITY_ANALYST, ADMIN
```

Without `.mcp.json`, the same thing by hand (run from the repository root):

```bash
claude mcp add threatlens-vulnerability --env THREATLENS_TENANT_ID=TENANT-DEMO -- \
  uv --directory intelligence-service run python -m mcp_tools.vulnerability_server
claude mcp add threatlens-asset --env THREATLENS_TENANT_ID=TENANT-DEMO -- \
  uv --directory intelligence-service run python -m mcp_tools.asset_server
```

## 3. Ask the demo question

> Which of my production assets are affected by CVE-2021-44228, and how sure are we?

Expected with the seeded data: `ASSET-013` **confirmed** (Log4j 2.14.1, inside 2.13.0 to 2.15.0), `ASSET-016` **possible** (identified by name only), `ASSET-015` **unknown** (no installed version recorded). `ASSET-014` (2.17.1) is not listed because it is `not_affected`. Only `confirmed` counts as exposure, and the answer should mention any freshness warnings.

More prompts to try:

- "List my critical assets, most exposed first." (`get_critical_assets`)
- "What software runs on ASSET-013 and what is wrong with it?" (`get_asset_software`)
- "Show the evidence behind CVE-2021-44228." (`get_vulnerability_evidence`)
- "Find KEV-listed vulnerabilities with CVSS 9.5 or higher." (`search_vulnerabilities`)

## 4. Other clients and manual checks

Any MCP client works. To test without an assistant, use the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector uv --directory intelligence-service run python -m mcp_tools.vulnerability_server
```

Start a server by hand (it waits for a client on stdin, so press Ctrl+C to stop):

```bash
cd intelligence-service
THREATLENS_TENANT_ID=TENANT-DEMO uv run python -m mcp_tools.asset_server
```

## 5. See what was called

```sql
SELECT occurred_at, server, tool, tenant_id, actor, latency_ms, outcome, error_code, correlation_id
FROM tool_call_audit ORDER BY id DESC LIMIT 20;
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Server fails to start and mentions `THREATLENS_TENANT_ID` | Set it to a valid id such as `TENANT-DEMO` |
| `uv: command not found` in the client log | Give the client the full path to `uv`, or add it to the PATH the client inherits |
| Tool returns `unavailable` | Start the containers (`docker compose up -d --wait`); the servers connect to `127.0.0.1` |
| Every call is `invalid_argument` mentioning `tenant_id` | The client or model is sending a tenant. Remove it: the tenant is fixed by server configuration |
| Empty results | Check `cve_known` and `warnings`. Run the data preparation steps above; an empty result is not proof of safety |
| Protocol errors in a custom client | Servers use stdout only for protocol messages; read logs from stderr |
