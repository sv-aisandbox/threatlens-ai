package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** When the organization's inventory was last imported. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record InventoryFreshness(
        @JsonProperty("last_imported_at") String lastImportedAt,
        @JsonProperty("age_hours") Double ageHours,
        @JsonProperty("stale") boolean stale) {}
