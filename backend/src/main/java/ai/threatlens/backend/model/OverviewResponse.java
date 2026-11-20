package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Security overview for the caller's organization, with data freshness reported separately for intelligence and inventory. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OverviewResponse(
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("generated_at") String generatedAt,
        @JsonProperty("vulnerabilities") VulnerabilityCounts vulnerabilities,
        @JsonProperty("assets") AssetCounts assets,
        @JsonProperty("exposure") ExposureCounts exposure,
        @JsonProperty("top_exposures") List<TopExposure> topExposures,
        @JsonProperty("sources") List<SourceFreshness> sources,
        @JsonProperty("inventory") InventoryFreshness inventory,
        @JsonProperty("stale_after_hours") int staleAfterHours,
        @JsonProperty("warnings") List<String> warnings) {}
