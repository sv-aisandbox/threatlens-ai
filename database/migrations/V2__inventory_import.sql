-- One row per inventory import attempt, including the row-level reject report (spec section 20.3:
-- inventory freshness is tracked separately from intelligence freshness).
CREATE TABLE inventory_import (
    import_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         TEXT NOT NULL,
    source_name       TEXT NOT NULL,
    source_format     TEXT NOT NULL CHECK (source_format IN ('json', 'csv')),
    imported_at       TIMESTAMPTZ NOT NULL,
    rows_received     INTEGER NOT NULL CHECK (rows_received >= 0),
    rows_accepted     INTEGER NOT NULL CHECK (rows_accepted >= 0),
    rows_rejected     INTEGER NOT NULL CHECK (rows_rejected >= 0),
    assets_imported   INTEGER NOT NULL CHECK (assets_imported >= 0),
    software_imported INTEGER NOT NULL CHECK (software_imported >= 0),
    reject_report     JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX inventory_import_tenant_time ON inventory_import (tenant_id, imported_at DESC);

COMMENT ON COLUMN inventory_import.reject_report IS 'Field names and error types only; never raw cell values.';
