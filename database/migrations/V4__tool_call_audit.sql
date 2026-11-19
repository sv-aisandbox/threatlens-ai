-- Audit of MCP tool calls. Arguments are stored only as a SHA-256 hash; results are never stored.
CREATE TABLE tool_call_audit (
    id             BIGSERIAL PRIMARY KEY,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    server         TEXT NOT NULL,
    tool           TEXT NOT NULL,
    args_hash      CHAR(64) NOT NULL,
    tenant_id      TEXT NOT NULL,
    actor          TEXT NOT NULL,
    latency_ms     INTEGER NOT NULL CHECK (latency_ms >= 0),
    outcome        TEXT NOT NULL CHECK (outcome IN ('success', 'invalid', 'denied', 'not_found', 'error')),
    error_code     TEXT,
    correlation_id TEXT NOT NULL
);

CREATE INDEX tool_call_audit_tenant_time ON tool_call_audit (tenant_id, occurred_at DESC);
CREATE INDEX tool_call_audit_correlation ON tool_call_audit (correlation_id);

COMMENT ON TABLE tool_call_audit IS 'Append-only. Never store raw arguments, tokens or tool results here.';
