"""In-process MCP bridge: the agent calls the real MCP tool servers (Module 07) with a trusted context.

The tenant and roles come from the authenticated principal, never from the model, and every call goes through the
same strict-argument, role, tenant-scoping, error-shape and audit code as an external MCP client.
"""

import json
import re
import time
from collections.abc import Callable
from contextlib import AsyncExitStack
from typing import Any

import psycopg
from mcp import Client
from neo4j import Driver

from agent.models import ToolOutcome
from mcp_tools import asset_server, vulnerability_server
from mcp_tools.audit import ToolAudit
from mcp_tools.context import TrustedContext
from mcp_tools.runtime import ToolDeps

_ACTOR_UNSAFE = re.compile(r"[^A-Za-z0-9._:@-]")


def actor_for(subject: str) -> str:
    """A token subject made safe for the audit actor column."""
    return ("agent:" + _ACTOR_UNSAFE.sub("_", subject))[:100]


class McpBridge:
    def __init__(self, tenant_id: str, roles: frozenset[str], subject: str, driver: Driver,
                 connect: Callable[[], psycopg.Connection], audit: ToolAudit) -> None:
        self.ctx = TrustedContext(tenant_id=tenant_id, roles=roles, actor=actor_for(subject))
        deps = ToolDeps(ctx=self.ctx, driver=driver, connect=connect, audit=audit)
        self._servers = {
            vulnerability_server.SERVER_NAME: vulnerability_server.build_server(deps),
            asset_server.SERVER_NAME: asset_server.build_server(deps),
        }
        self._clients: dict[str, Client] = {}
        self._route: dict[str, str] = {}
        self._stack = AsyncExitStack()
        self.listing: list[dict[str, Any]] = []

    async def __aenter__(self) -> "McpBridge":
        for name, server in self._servers.items():
            client = await self._stack.enter_async_context(Client(server))
            self._clients[name] = client
            for tool in (await client.list_tools()).tools:
                self._route[tool.name] = name
                self.listing.append({
                    "name": tool.name,
                    "description": tool.description or "",
                    "input_schema": getattr(tool, "input_schema", None) or tool.inputSchema,
                })
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._stack.aclose()

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        started = time.perf_counter()
        client = self._clients[self._route[name]]
        result = await client.call_tool(name, arguments)
        body = getattr(result, "structured_content", None)
        if body is None:
            body = json.loads(result.content[0].text)
        error_code = body.get("error", {}).get("code") if result.is_error else None
        return ToolOutcome(
            body=body, is_error=bool(result.is_error), latency_ms=int((time.perf_counter() - started) * 1000),
            error_code=error_code,
        )
