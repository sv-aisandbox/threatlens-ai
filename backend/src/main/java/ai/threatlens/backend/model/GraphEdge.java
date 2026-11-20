package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** An edge. AFFECTED_BY edges carry the match status and reason. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GraphEdge(
        @JsonProperty("source") String source,
        @JsonProperty("target") String target,
        @JsonProperty("type") String type,
        @JsonProperty("match_status") String matchStatus,
        @JsonProperty("reason") String reason) {}
