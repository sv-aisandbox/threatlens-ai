"""Per-request usage and cost log (roadmap task 7.9). Stores hashes and counters, never question text or answers."""

import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import psycopg

logger = logging.getLogger("threatlens.agent.usage")


@dataclass(frozen=True)
class UsageRecord:
    correlation_id: str
    tenant_id: str
    actor: str
    provider: str
    model: str
    question_hash: str
    question_chars: int
    steps: int
    tool_calls: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: float
    latency_ms: int
    outcome: str  # answered | refused | limit_reached | error
    stop_reason: str | None
    error_code: str | None


class UsageLog(Protocol):
    def record(self, row: UsageRecord) -> None: ...


def hash_question(question: str) -> str:
    return hashlib.sha256(question.encode("utf-8")).hexdigest()


class PostgresUsageLog:
    """A failed write is logged and never fails the request."""

    def __init__(self, connect: Callable[[], psycopg.Connection]) -> None:
        self._connect = connect

    def record(self, row: UsageRecord) -> None:
        try:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO analyst_request_log (correlation_id, tenant_id, actor, provider, model, question_hash,
                        question_chars, steps, tool_calls, input_tokens, output_tokens, cache_read_tokens,
                        cache_write_tokens, cost_usd, latency_ms, outcome, stop_reason, error_code)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (row.correlation_id, row.tenant_id, row.actor, row.provider, row.model, row.question_hash,
                     row.question_chars, row.steps, row.tool_calls, row.input_tokens, row.output_tokens,
                     row.cache_read_tokens, row.cache_write_tokens, row.cost_usd, row.latency_ms, row.outcome,
                     row.stop_reason, row.error_code),
                )
        except Exception:  # noqa: BLE001 - usage logging must not fail an answer
            logger.exception("usage log write failed (request still served)")
