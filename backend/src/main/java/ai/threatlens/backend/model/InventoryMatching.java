package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Matching run after an import. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record InventoryMatching(
        @JsonProperty("software_considered") int softwareConsidered,
        @JsonProperty("created") int created,
        @JsonProperty("updated") int updated,
        @JsonProperty("unchanged") int unchanged,
        @JsonProperty("removed") int removed) {}
