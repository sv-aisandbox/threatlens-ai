package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** The organization's assets. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AssetCounts(
        @JsonProperty("total") long total,
        @JsonProperty("critical") long critical,
        @JsonProperty("affected_critical") long affectedCritical) {}
