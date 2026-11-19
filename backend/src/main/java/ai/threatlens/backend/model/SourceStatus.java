package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Sync status of one intelligence source. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SourceStatus(
        @JsonProperty("source_id") String sourceId,
        @JsonProperty("last_attempt_at") String lastAttemptAt,
        @JsonProperty("last_success_at") String lastSuccessAt,
        @JsonProperty("last_status") String lastStatus,
        @JsonProperty("records_received") Integer recordsReceived,
        @JsonProperty("records_created") Integer recordsCreated,
        @JsonProperty("records_updated") Integer recordsUpdated,
        @JsonProperty("records_rejected") Integer recordsRejected,
        @JsonProperty("error_summary") String errorSummary,
        @JsonProperty("source_modified_at") String sourceModifiedAt,
        @JsonProperty("sync_cursor_at") String syncCursorAt) {}
