package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** When a source last succeeded, and whether that is too old to call current. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SourceFreshness(
        @JsonProperty("source_id") String sourceId,
        @JsonProperty("label") String label,
        @JsonProperty("last_status") String lastStatus,
        @JsonProperty("last_attempt_at") String lastAttemptAt,
        @JsonProperty("last_success_at") String lastSuccessAt,
        @JsonProperty("age_hours") Double ageHours,
        @JsonProperty("stale") boolean stale,
        @JsonProperty("records_received") long recordsReceived,
        @JsonProperty("records_rejected") long recordsRejected) {}
