package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** One asset-vulnerability match found by the analyst's tools, never written by the model. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AnalystFinding(
        @JsonProperty("asset_id") String assetId,
        @JsonProperty("asset_name") String assetName,
        @JsonProperty("environment") String environment,
        @JsonProperty("criticality") String criticality,
        @JsonProperty("internet_exposed") Boolean internetExposed,
        @JsonProperty("cve_id") String cveId,
        @JsonProperty("software") FindingSoftware software,
        @JsonProperty("match_status") String matchStatus,
        @JsonProperty("reason") String reason,
        @JsonProperty("matched_at") String matchedAt,
        @JsonProperty("evidence_ids") List<String> evidenceIds) {}
