package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Software behind a finding. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FindingSoftware(
        @JsonProperty("vendor") String vendor,
        @JsonProperty("product") String product,
        @JsonProperty("version") String version) {}
