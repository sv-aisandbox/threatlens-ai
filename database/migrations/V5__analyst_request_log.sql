-- One row per analyst question: usage and cost. The question text itself is never stored, only its hash.
CREATE TABLE analyst_request_log (
    id                 BIGSERIAL PRIMARY KEY,
    occurred_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    correlation_id     TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    actor              TEXT NOT NULL,
    provider           TEXT NOT NULL,
    model              TEXT NOT NULL,
    question_hash      CHAR(64) NOT NULL,
    question_chars     INTEGER NOT NULL CHECK (question_chars >= 0),
    steps              INTEGER NOT NULL CHECK (steps >= 0),
    tool_calls         INTEGER NOT NULL CHECK (tool_calls >= 0),
    input_tokens       INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens      INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    cache_read_tokens  INTEGER NOT NULL DEFAULT 0 CHECK (cache_read_tokens >= 0),
    cache_write_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cache_write_tokens >= 0),
    cost_usd           NUMERIC(12, 6) NOT NULL DEFAULT 0 CHECK (cost_usd >= 0),
    latency_ms         INTEGER NOT NULL CHECK (latency_ms >= 0),
    outcome            TEXT NOT NULL CHECK (outcome IN ('answered', 'refused', 'limit_reached', 'error')),
    stop_reason        TEXT,
    error_code         TEXT
);

CREATE INDEX analyst_request_log_tenant_time ON analyst_request_log (tenant_id, occurred_at DESC);
CREATE INDEX analyst_request_log_correlation ON analyst_request_log (correlation_id);

COMMENT ON TABLE analyst_request_log IS 'Append-only usage and cost log. Never store question text, answers, tool results or keys.';
