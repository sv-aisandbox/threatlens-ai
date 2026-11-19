// Shapes returned by the Spring Boot API (docs/api/openapi.json). Optional fields are nullable on the wire.

export type MatchStatus = "confirmed" | "possible" | "unknown" | "not_affected";
export type Role = "ADMIN" | "SECURITY_ANALYST" | "VIEWER";

export interface SourceFreshness {
  source_id: string;
  label: string;
  last_status: string | null;
  last_attempt_at: string | null;
  last_success_at: string | null;
  age_hours: number | null;
  stale: boolean;
  records_received: number;
  records_rejected: number;
}

export interface Overview {
  tenant_id: string;
  generated_at: string;
  vulnerabilities: { total: number; kev: number; critical_cvss: number };
  assets: { total: number; critical: number; affected_critical: number };
  exposure: { confirmed: number; possible: number; unknown: number; confirmed_cves: number };
  top_exposures: {
    cve_id: string;
    cvss_score: number | null;
    severity: string | null;
    kev_listed: boolean;
    synthetic: boolean;
    confirmed_assets: number;
  }[];
  sources: SourceFreshness[];
  inventory: { last_imported_at: string | null; age_hours: number | null; stale: boolean };
  stale_after_hours: number;
  warnings: string[];
}

export interface SourceStatus {
  source_id: string;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_status: string | null;
  records_received: number | null;
  records_created: number | null;
  records_updated: number | null;
  records_rejected: number | null;
  error_summary: string | null;
  source_modified_at: string | null;
  sync_cursor_at: string | null;
}

export interface VulnerabilitySummary {
  cve_id: string;
  description: string | null;
  cvss_score: number | null;
  severity: string | null;
  published_at: string | null;
  kev_listed: boolean;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_name: string | null;
  synthetic: boolean;
}

export interface VulnerabilitySearch {
  results: VulnerabilitySummary[];
  truncated: boolean;
}

export interface Evidence {
  evidence_id: string;
  source_name: string;
  source_url: string | null;
  collected_at: string | null;
}

export interface VulnerabilityDetails extends VulnerabilitySummary {
  cvss_version: string | null;
  cvss_vector: string | null;
  last_modified_at: string | null;
  vuln_status: string | null;
  kev_ransomware_use: string | null;
  kev_required_action: string | null;
  evidence: Evidence[];
}

export interface Software {
  software_id: string | null;
  vendor: string | null;
  product: string | null;
  version: string | null;
  cpe: string | null;
}

export interface AffectedAsset {
  asset_id: string;
  asset_name: string | null;
  tenant_id: string;
  environment: string | null;
  criticality: string | null;
  internet_exposed: boolean | null;
  inventory_imported_at: string | null;
  software: Software | null;
  cve_id: string;
  cvss_score: number | null;
  severity: string | null;
  match_status: MatchStatus;
  match_reason: string | null;
  matched_by: string | null;
  matched_at: string | null;
  source_ref: string | null;
  evidence: Evidence[];
}

export interface Freshness {
  intelligence: { nvd_last_success_at: string | null; kev_last_success_at: string | null };
  inventory_last_imported_at: string | null;
}

export interface AffectedAssets {
  cve_id: string;
  tenant_id: string;
  results: AffectedAsset[];
  freshness: Freshness | null;
  warnings: string[];
}

export interface GraphNode {
  id: string;
  type: "vulnerability" | "software" | "asset";
  label: string;
  severity?: string | null;
  kev_listed?: boolean | null;
  environment?: string | null;
  criticality?: string | null;
  internet_exposed?: boolean | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: "RUNS" | "AFFECTED_BY";
  match_status?: MatchStatus | null;
  reason?: string | null;
}

export interface VulnerabilityGraph {
  cve_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
}

export interface InventoryReject {
  ref: string;
  asset_id: string | null;
  errors: { field: string; type: string }[];
}

export interface InventoryImportSummary {
  import_id: string;
  source_name: string;
  source_format: string;
  imported_at: string;
  rows_received: number;
  rows_accepted: number;
  rows_rejected: number;
  assets_imported: number;
  software_imported: number;
}

export interface InventoryImportDetail extends InventoryImportSummary {
  rejects: InventoryReject[];
}

export interface InventoryImportResult {
  import_id: string;
  tenant_id: string;
  format: string;
  rows_received: number;
  rows_accepted: number;
  rows_rejected: number;
  assets_imported: number;
  software_imported: number;
  rejects: InventoryReject[];
  matching: null | {
    software_considered: number;
    created: number;
    updated: number;
    unchanged: number;
    removed: number;
  };
}

export interface AnalystFinding {
  asset_id: string;
  asset_name: string | null;
  environment: string | null;
  criticality: string | null;
  internet_exposed: boolean | null;
  cve_id: string;
  software: { vendor: string | null; product: string | null; version: string | null } | null;
  match_status: MatchStatus;
  reason: string | null;
  matched_at: string | null;
  evidence_ids: string[];
}

export interface AnalystTraceStep {
  step: number;
  tool: string;
  args: Record<string, unknown>;
  outcome: string;
  latency_ms: number | null;
  injection_suspected: boolean | null;
  tool_correlation_id: string | null;
  result_summary: string | null;
}

export interface AnalystAnswer {
  answer: string;
  outcome: string;
  summary: { confirmed_exposures: number; possible: number; unknown: number };
  findings: { confirmed: AnalystFinding[]; possible: AnalystFinding[]; unknown: AnalystFinding[] };
  evidence: {
    evidence_id: string;
    source_name: string;
    source_url: string | null;
    collected_at: string | null;
    content_hash: string | null;
  }[];
  freshness: Freshness | null;
  warnings: string[];
  grounding: { ok: boolean; ungrounded: string[] };
  trace: AnalystTraceStep[];
  usage: { provider: string; model: string; steps: number; tool_calls: number; latency_ms: number } | null;
  correlation_id: string | null;
}

/** RFC 7807 problem body returned by the backend for every error. */
export interface Problem {
  status?: number;
  title?: string;
  detail?: string;
  code?: string;
  correlationId?: string;
}
