package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** The analyst's answer: narrative plus code-built findings, evidence, freshness, warnings and a full tool trace. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AnalystAnswer(
        @JsonProperty("answer") String answer,
        @JsonProperty("outcome") String outcome,
        @JsonProperty("summary") AnalystSummary summary,
        @JsonProperty("findings") AnalystFindings findings,
        @JsonProperty("evidence") List<AnalystEvidence> evidence,
        @JsonProperty("freshness") Freshness freshness,
        @JsonProperty("warnings") List<String> warnings,
        @JsonProperty("grounding") AnalystGrounding grounding,
        @JsonProperty("trace") List<AnalystTraceStep> trace,
        @JsonProperty("usage") AnalystUsage usage,
        @JsonProperty("correlation_id") String correlationId) {}
