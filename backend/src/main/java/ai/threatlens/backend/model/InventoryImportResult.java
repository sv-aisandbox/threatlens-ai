package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Result of an upload: counters and the row-level reject report. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record InventoryImportResult(
        @JsonProperty("import_id") String importId,
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("format") String format,
        @JsonProperty("rows_received") int rowsReceived,
        @JsonProperty("rows_accepted") int rowsAccepted,
        @JsonProperty("rows_rejected") int rowsRejected,
        @JsonProperty("assets_imported") int assetsImported,
        @JsonProperty("software_imported") int softwareImported,
        @JsonProperty("rejects") List<InventoryReject> rejects,
        @JsonProperty("matching") InventoryMatching matching) {}
