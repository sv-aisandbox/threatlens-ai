package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Last successful intelligence syncs. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record IntelligenceFreshness(
        @JsonProperty("nvd_last_success_at") String nvdLastSuccessAt,
        @JsonProperty("kev_last_success_at") String kevLastSuccessAt) {}
