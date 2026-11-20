package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** One past import including its reject report. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record InventoryImportDetail(
        @JsonProperty("import_id") String importId,
        @JsonProperty("source_name") String sourceName,
        @JsonProperty("source_format") String sourceFormat,
        @JsonProperty("imported_at") String importedAt,
        @JsonProperty("rows_received") int rowsReceived,
        @JsonProperty("rows_accepted") int rowsAccepted,
        @JsonProperty("rows_rejected") int rowsRejected,
        @JsonProperty("assets_imported") int assetsImported,
        @JsonProperty("software_imported") int softwareImported,
        @JsonProperty("rejects") List<InventoryReject> rejects) {}
