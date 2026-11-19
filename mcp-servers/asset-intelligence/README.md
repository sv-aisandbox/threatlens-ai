# Asset Intelligence MCP server

Server name `threatlens-asset`. Tools: `search_assets`, `get_asset_details`, `get_asset_software`, `get_critical_assets`.

The code is in [`intelligence-service/mcp_tools/`](../../intelligence-service/mcp_tools/) (one package, two entrypoints; see [ADR 0006](../../docs/adr/0006-mcp-deployment-and-tenant-context.md)). This folder only documents how to run it.

```bash
cd intelligence-service
THREATLENS_TENANT_ID=TENANT-DEMO uv run python -m mcp_tools.asset_server
```

Every query starts from the configured tenant's assets. Tool reference: [docs/mcp/tools.md](../../docs/mcp/tools.md). Connection steps: [docs/mcp/connecting.md](../../docs/mcp/connecting.md).
