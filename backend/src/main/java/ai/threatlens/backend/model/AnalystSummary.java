package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Counts per group. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AnalystSummary(
        @JsonProperty("confirmed_exposures") int confirmedExposures,
        @JsonProperty("possible") int possible,
        @JsonProperty("unknown") int unknown) {}
