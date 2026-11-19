package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/** One tool call the analyst made, or was refused. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AnalystTraceStep(
        @JsonProperty("step") int step,
        @JsonProperty("tool") String tool,
        @JsonProperty("args") Map<String, Object> args,
        @JsonProperty("outcome") String outcome,
        @JsonProperty("latency_ms") Integer latencyMs,
        @JsonProperty("injection_suspected") Boolean injectionSuspected,
        @JsonProperty("tool_correlation_id") String toolCorrelationId,
        @JsonProperty("result_summary") String resultSummary) {}
