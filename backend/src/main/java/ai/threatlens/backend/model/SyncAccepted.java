package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** A sync was accepted and runs in the background. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SyncAccepted(
        @JsonProperty("accepted") boolean accepted,
        @JsonProperty("source_id") String sourceId) {}
