"""Builds the model adapter and agent from the service environment (ADR 0007)."""

import os
from collections.abc import Callable, Mapping

import psycopg
from neo4j import Driver

from agent.agent import AgentConfig, AnalystAgent
from agent.anthropic_adapter import DEFAULT_MODEL, AnthropicAdapter
from agent.mock_adapter import MockAdapter
from agent.models import ModelAdapter, ModelError
from agent.usage_log import PostgresUsageLog
from mcp_tools.audit import PostgresToolAudit

PLACEHOLDER_KEYS = {"", "your-model-provider-key", "change-me"}


def build_adapter(env: Mapping[str, str] | None = None) -> ModelAdapter:
    env = os.environ if env is None else env
    provider = (env.get("MODEL_PROVIDER") or "mock").strip().lower()
    if provider == "mock":
        return MockAdapter()
    if provider == "anthropic":
        key = (env.get("MODEL_API_KEY") or "").strip()
        if key in PLACEHOLDER_KEYS:
            raise ModelError("model_not_configured", "MODEL_API_KEY is not set")
        return AnthropicAdapter(
            api_key=key,
            model=(env.get("MODEL_NAME") or DEFAULT_MODEL).strip(),
            effort=(env.get("MODEL_EFFORT") or "medium").strip(),
            fallbacks=(env.get("MODEL_FALLBACKS") or "on").strip().lower() != "off",
        )
    raise ModelError("model_not_configured", "MODEL_PROVIDER must be 'mock' or 'anthropic'")


def build_agent(driver: Driver, connect: Callable[[], psycopg.Connection], env: Mapping[str, str] | None = None) -> AnalystAgent:
    return AnalystAgent(
        adapter=build_adapter(env), driver=driver, connect=connect,
        audit=PostgresToolAudit(connect), usage_log=PostgresUsageLog(connect), config=AgentConfig(),
    )
