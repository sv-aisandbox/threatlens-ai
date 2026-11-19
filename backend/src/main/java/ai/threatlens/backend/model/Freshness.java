package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Data freshness: intelligence and inventory are reported separately (spec 20.3). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Freshness(
        @JsonProperty("intelligence") IntelligenceFreshness intelligence,
        @JsonProperty("inventory_last_imported_at") String inventoryLastImportedAt) {}
