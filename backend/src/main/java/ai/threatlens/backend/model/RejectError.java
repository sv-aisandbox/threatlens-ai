package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** A field and error type; never the rejected value. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RejectError(
        @JsonProperty("field") String field,
        @JsonProperty("type") String type) {}
