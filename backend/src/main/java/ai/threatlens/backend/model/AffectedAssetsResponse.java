package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Tenant-scoped affected assets for one CVE, plus freshness and warnings. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AffectedAssetsResponse(
        @JsonProperty("cve_id") String cveId,
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("results") List<AffectedAsset> results,
        @JsonProperty("freshness") Freshness freshness,
        @JsonProperty("warnings") List<String> warnings) {}
