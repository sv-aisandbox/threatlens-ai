"""Asset Intelligence MCP server (`threatlens-asset`).

Run over stdio:  uv run python -m mcp_tools.asset_server
Every query starts from the configured tenant's assets; the tenant is never a tool argument (ADR 0006).
"""

from typing import Annotated, Any, Literal

import psycopg
from pydantic import Field

from app.config import get_driver, pg_conninfo
from graph_queries.assets import FINDING_STATUSES, get_asset, get_asset_software, get_critical_assets, search_assets
from mcp_tools.audit import PostgresToolAudit
from mcp_tools.context import TrustedContext
from mcp_tools.errors import ToolFailure
from mcp_tools.runtime import READ_ONLY, ThreatLensServer, ToolDeps, envelope, run_stdio

SERVER_NAME = "threatlens-asset"
TOOL_NAMES = ["search_assets", "get_asset_details", "get_asset_software", "get_critical_assets"]

AssetId = Annotated[
    str, Field(pattern=r"^ASSET-[A-Z0-9-]{1,40}$", max_length=50, description="Asset identifier, for example ASSET-013")
]
Environment = Literal["production", "staging", "development", "all"]
Criticality = Literal["critical", "high", "medium", "low"]

UNTRUSTED_ASSET = ["name", "vendor", "product", "version"]
UNTRUSTED_FINDING = ["name", "vendor", "product", "version", "findings.match_reason"]
# The same answer for a missing asset and for another tenant's asset: existence is never disclosed.
NOT_FOUND = "No asset with that identifier is in this organization's inventory."


def _env(value: str) -> str | None:
    return None if value == "all" else value


def build_server(deps: ToolDeps) -> ThreatLensServer:
    server = ThreatLensServer(SERVER_NAME, deps)

    @server.tool(
        name="search_assets",
        annotations=READ_ONLY,
        description=(
            "Searches the organization's assets by name or id, environment, criticality and internet exposure. "
            "The organization is fixed by server configuration."
        ),
    )
    def search(
        query: Annotated[str | None, Field(min_length=1, max_length=100, description="Part of an asset name, or an asset id")] = None,
        environment: Annotated[Environment, Field(description="Environment, or 'all'")] = "all",
        criticality: Annotated[Criticality | None, Field(description="Business criticality")] = None,
        internet_exposed: Annotated[bool | None, Field(description="Only internet-exposed (true) or internal (false) assets")] = None,
        limit: Annotated[int, Field(ge=1, le=100, description="Maximum assets to return")] = 25,
    ) -> dict[str, Any]:
        deps.ctx.require_read()
        out = search_assets(deps.driver, deps.ctx.tenant_id, query, _env(environment), criticality, internet_exposed, limit)
        return envelope("search_assets", deps, "tenant", UNTRUSTED_ASSET, results=out["results"], truncated=out["truncated"])

    @server.tool(
        name="get_asset_details",
        annotations=READ_ONLY,
        description="Returns one asset: type, environment, criticality, exposure, inventory import time, software count and confirmed vulnerability count.",
    )
    def details(asset_id: AssetId) -> dict[str, Any]:
        deps.ctx.require_read()
        asset = get_asset(deps.driver, deps.ctx.tenant_id, asset_id)
        if asset is None:
            raise ToolFailure("not_found", NOT_FOUND)
        return envelope("get_asset_details", deps, "tenant", UNTRUSTED_ASSET, asset=asset)

    @server.tool(
        name="get_asset_software",
        annotations=READ_ONLY,
        description=(
            "Lists software installed on an asset with the vulnerabilities matched to each item (status, reason, "
            "severity, KEV). 'not_affected' matches are hidden unless requested."
        ),
    )
    def software(
        asset_id: AssetId,
        include_not_affected: Annotated[bool, Field(description="Also list vulnerabilities ruled out for this software")] = False,
    ) -> dict[str, Any]:
        deps.ctx.require_read()
        statuses = FINDING_STATUSES + ("not_affected",) if include_not_affected else FINDING_STATUSES
        out = get_asset_software(deps.driver, deps.ctx.tenant_id, asset_id, statuses)
        if out is None:
            raise ToolFailure("not_found", NOT_FOUND)
        return envelope(
            "get_asset_software", deps, "tenant", UNTRUSTED_FINDING,
            asset_id=asset_id, software=out["software"], truncated=out["truncated"],
        )

    @server.tool(
        name="get_critical_assets",
        annotations=READ_ONLY,
        description=(
            "Lists the organization's critical assets, most exposed first (confirmed vulnerabilities, then internet "
            "exposure)."
        ),
    )
    def critical(
        environment: Annotated[Environment, Field(description="Environment, or 'all'")] = "all",
        limit: Annotated[int, Field(ge=1, le=100, description="Maximum assets to return")] = 25,
    ) -> dict[str, Any]:
        deps.ctx.require_read()
        out = get_critical_assets(deps.driver, deps.ctx.tenant_id, _env(environment), limit)
        return envelope(
            "get_critical_assets", deps, "tenant", UNTRUSTED_ASSET,
            environment=environment, results=out["results"], truncated=out["truncated"],
        )

    return server


def main() -> None:
    ctx = TrustedContext.from_env(default_actor=f"mcp-stdio:{SERVER_NAME}")
    deps = ToolDeps(
        ctx=ctx,
        driver=get_driver(),
        connect=lambda: psycopg.connect(pg_conninfo()),
        audit=PostgresToolAudit(lambda: psycopg.connect(pg_conninfo())),
    )
    run_stdio(build_server(deps))


if __name__ == "__main__":
    main()
