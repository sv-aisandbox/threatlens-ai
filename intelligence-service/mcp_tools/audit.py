"""Tool-call audit (roadmap task 6.5). Arguments are stored only as a SHA-256 hash; results never."""

import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import psycopg

logger = logging.getLogger("threatlens.mcp.audit")


@dataclass(frozen=True)
class ToolCallEvent:
    server: str
    tool: str
    args_hash: str
    tenant_id: str
    actor: str
    latency_ms: int
    outcome: str  # success | invalid | denied | not_found | error
    error_code: str | None
    correlation_id: str


class ToolAudit(Protocol):
    def record(self, event: ToolCallEvent) -> None: ...


def hash_arguments(arguments: dict[str, Any] | None) -> str:
    """SHA-256 over canonical JSON (sorted keys, no whitespace). Covers unexpected keys too."""
    canonical = json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PostgresToolAudit:
    """Writes to `tool_call_audit`. A failed write is logged and never fails the tool call."""

    def __init__(self, connect: Callable[[], psycopg.Connection]) -> None:
        self._connect = connect

    def record(self, event: ToolCallEvent) -> None:
        try:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tool_call_audit (server, tool, args_hash, tenant_id, actor, latency_ms, outcome,
                                                 error_code, correlation_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (event.server, event.tool, event.args_hash, event.tenant_id, event.actor, event.latency_ms,
                     event.outcome, event.error_code, event.correlation_id),
                )
        except Exception:  # noqa: BLE001 - audit must not turn a read into an error
            logger.exception("tool audit write failed (call still served)")
