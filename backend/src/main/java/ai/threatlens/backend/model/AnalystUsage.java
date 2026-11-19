package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Model usage and estimated cost for this question. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AnalystUsage(
        @JsonProperty("provider") String provider,
        @JsonProperty("model") String model,
        @JsonProperty("steps") int steps,
        @JsonProperty("tool_calls") int toolCalls,
        @JsonProperty("input_tokens") int inputTokens,
        @JsonProperty("output_tokens") int outputTokens,
        @JsonProperty("cache_read_tokens") int cacheReadTokens,
        @JsonProperty("cache_write_tokens") int cacheWriteTokens,
        @JsonProperty("cost_usd") double costUsd,
        @JsonProperty("latency_ms") int latencyMs) {}
