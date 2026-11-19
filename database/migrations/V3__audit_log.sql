-- API audit trail written by the Spring Boot backend: who did what, for which tenant, with what outcome.
CREATE TABLE audit_log (
    id             BIGSERIAL PRIMARY KEY,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor          TEXT NOT NULL,
    tenant_id      TEXT,
    action         TEXT NOT NULL,
    resource       TEXT,
    outcome        TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    http_status    INTEGER NOT NULL,
    correlation_id TEXT NOT NULL
);

CREATE INDEX audit_log_tenant_time ON audit_log (tenant_id, occurred_at DESC);
CREATE INDEX audit_log_correlation ON audit_log (correlation_id);

COMMENT ON TABLE audit_log IS 'Append-only. Never store tokens, request bodies or response bodies here.';
COMMENT ON COLUMN audit_log.actor IS 'Token subject, or "anonymous" when authentication failed.';
