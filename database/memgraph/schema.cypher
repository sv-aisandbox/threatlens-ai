// ThreatLens AI - Memgraph schema (verified against memgraph-mage 3.14.0).
// Safe to re-run: existing constraints and indexes are left unchanged.

CREATE CONSTRAINT ON (n:Tenant) ASSERT n.tenant_id IS UNIQUE;
CREATE CONSTRAINT ON (n:Asset) ASSERT n.asset_id IS UNIQUE;
CREATE CONSTRAINT ON (n:Software) ASSERT n.software_id IS UNIQUE;
CREATE CONSTRAINT ON (n:Vulnerability) ASSERT n.cve_id IS UNIQUE;
CREATE CONSTRAINT ON (n:Evidence) ASSERT n.evidence_id IS UNIQUE;

// Tenant-filtered queries start from Asset.tenant_id.
CREATE INDEX ON :Asset(tenant_id);
