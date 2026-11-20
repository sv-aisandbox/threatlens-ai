package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Asset-vulnerability matches by status; only confirmed counts as exposure. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ExposureCounts(
        @JsonProperty("confirmed") long confirmed,
        @JsonProperty("possible") long possible,
        @JsonProperty("unknown") long unknown,
        @JsonProperty("confirmed_cves") long confirmedCves) {}
