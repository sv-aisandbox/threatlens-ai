package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** A rejected row, identified by its position in the file. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record InventoryReject(
        @JsonProperty("ref") String ref,
        @JsonProperty("asset_id") String assetId,
        @JsonProperty("errors") List<RejectError> errors) {}
