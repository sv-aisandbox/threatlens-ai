package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** A CVE with confirmed exposure in this organization. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TopExposure(
        @JsonProperty("cve_id") String cveId,
        @JsonProperty("cvss_score") Double cvssScore,
        @JsonProperty("severity") String severity,
        @JsonProperty("kev_listed") boolean kevListed,
        @JsonProperty("synthetic") boolean synthetic,
        @JsonProperty("confirmed_assets") long confirmedAssets) {}
