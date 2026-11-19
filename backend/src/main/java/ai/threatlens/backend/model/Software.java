package ai.threatlens.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Installed software as recorded in the inventory. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Software(
        @JsonProperty("software_id") String softwareId,
        @JsonProperty("vendor") String vendor,
        @JsonProperty("product") String product,
        @JsonProperty("version") String version,
        @JsonProperty("cpe") String cpe) {}
