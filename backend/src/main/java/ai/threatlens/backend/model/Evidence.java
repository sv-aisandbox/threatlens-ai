package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Source evidence supporting a vulnerability. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Evidence(
        @JsonProperty("evidence_id") String evidenceId,
        @JsonProperty("source_name") String sourceName,
        @JsonProperty("source_url") String sourceUrl,
        @JsonProperty("collected_at") String collectedAt) {}
