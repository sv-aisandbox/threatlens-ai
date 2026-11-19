package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Findings kept in separate groups: only confirmed counts as exposure. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AnalystFindings(
        @JsonProperty("confirmed") List<AnalystFinding> confirmed,
        @JsonProperty("possible") List<AnalystFinding> possible,
        @JsonProperty("unknown") List<AnalystFinding> unknown) {}
