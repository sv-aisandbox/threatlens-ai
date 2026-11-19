package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** One past import (counters only). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record InventoryImportSummary(
        @JsonProperty("import_id") String importId,
        @JsonProperty("source_name") String sourceName,
        @JsonProperty("source_format") String sourceFormat,
        @JsonProperty("imported_at") String importedAt,
        @JsonProperty("rows_received") int rowsReceived,
        @JsonProperty("rows_accepted") int rowsAccepted,
        @JsonProperty("rows_rejected") int rowsRejected,
        @JsonProperty("assets_imported") int assetsImported,
        @JsonProperty("software_imported") int softwareImported) {}
