package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Whether the narrative stayed inside what the tools returned. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AnalystGrounding(
        @JsonProperty("ok") boolean ok,
        @JsonProperty("ungrounded") List<String> ungrounded) {}
