package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Cited evidence with provenance. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AnalystEvidence(
        @JsonProperty("evidence_id") String evidenceId,
        @JsonProperty("source_name") String sourceName,
        @JsonProperty("source_url") String sourceUrl,
        @JsonProperty("collected_at") String collectedAt,
        @JsonProperty("content_hash") String contentHash) {}
