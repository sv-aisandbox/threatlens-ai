package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** One tenant asset matched to the CVE, with status, reason and evidence. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AffectedAsset(
        @JsonProperty("asset_id") String assetId,
        @JsonProperty("asset_name") String assetName,
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("environment") String environment,
        @JsonProperty("criticality") String criticality,
        @JsonProperty("internet_exposed") Boolean internetExposed,
        @JsonProperty("inventory_imported_at") String inventoryImportedAt,
        @JsonProperty("software") Software software,
        @JsonProperty("cve_id") String cveId,
        @JsonProperty("cvss_score") Double cvssScore,
        @JsonProperty("severity") String severity,
        @JsonProperty("match_status") String matchStatus,
        @JsonProperty("match_reason") String matchReason,
        @JsonProperty("matched_by") String matchedBy,
        @JsonProperty("matched_at") String matchedAt,
        @JsonProperty("source_ref") String sourceRef,
        @JsonProperty("evidence") List<Evidence> evidence) {}
