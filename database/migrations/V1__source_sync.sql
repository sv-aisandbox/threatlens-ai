-- Data freshness per connector (spec section 20.3).
-- Counters describe the most recent attempt, not cumulative totals.
CREATE TABLE source_sync (
    source_id          TEXT PRIMARY KEY,
    last_attempt_at    TIMESTAMPTZ,
    last_success_at    TIMESTAMPTZ,
    last_status        TEXT CHECK (last_status IN ('success', 'partial', 'failed')),
    records_received   INTEGER NOT NULL DEFAULT 0 CHECK (records_received >= 0),
    records_created    INTEGER NOT NULL DEFAULT 0 CHECK (records_created >= 0),
    records_updated    INTEGER NOT NULL DEFAULT 0 CHECK (records_updated >= 0),
    records_rejected   INTEGER NOT NULL DEFAULT 0 CHECK (records_rejected >= 0),
    error_summary      TEXT,
    source_modified_at TIMESTAMPTZ,
    sync_cursor_at     TIMESTAMPTZ
);

COMMENT ON COLUMN source_sync.error_summary IS 'Sanitized: no secrets, no response bodies, truncated.';
COMMENT ON COLUMN source_sync.source_modified_at IS 'Provider-supplied modification time (NVD: newest lastModified seen; KEV: dateReleased).';
COMMENT ON COLUMN source_sync.sync_cursor_at IS 'High-water mark for incremental sync (NVD lastModEndDate of last fully completed run).';
