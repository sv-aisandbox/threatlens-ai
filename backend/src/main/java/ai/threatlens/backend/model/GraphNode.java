package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** A node of the asset, software and CVE graph. Fields depend on the type. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GraphNode(
        @JsonProperty("id") String id,
        @JsonProperty("type") String type,
        @JsonProperty("label") String label,
        @JsonProperty("severity") String severity,
        @JsonProperty("cvss_score") Double cvssScore,
        @JsonProperty("kev_listed") Boolean kevListed,
        @JsonProperty("environment") String environment,
        @JsonProperty("criticality") String criticality,
        @JsonProperty("internet_exposed") Boolean internetExposed,
        @JsonProperty("vendor") String vendor,
        @JsonProperty("product") String product,
        @JsonProperty("version") String version) {}
