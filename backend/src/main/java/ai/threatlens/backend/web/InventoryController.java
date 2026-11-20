package ai.threatlens.backend.web;

import ai.threatlens.backend.model.InventoryImportDetail;
import ai.threatlens.backend.model.InventoryImportResult;
import ai.threatlens.backend.model.InventoryImportSummary;
import ai.threatlens.backend.service.InventoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Pattern;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/inventory")
@Tag(name = "Inventory")
public class InventoryController {

    private final InventoryService service;

    public InventoryController(InventoryService service) {
        this.service = service;
    }

    @PostMapping(value = "/import", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Upload an asset inventory, CSV or JSON, up to 5 MB (ADMIN only)",
            description = "Validated row by row: accepted rows are imported and matched, rejected rows are reported by position "
                    + "with field names and error types, never cell values. The tenant is the caller's own.")
    public InventoryImportResult upload(@RequestPart("file") MultipartFile file) {
        return service.upload(file);
    }

    @GetMapping("/imports")
    @Operation(summary = "Recent inventory imports of the caller's organization (SECURITY_ANALYST or ADMIN)")
    public List<InventoryImportSummary> imports() {
        return service.imports();
    }

    @GetMapping("/imports/{importId}")
    @Operation(summary = "One import with its reject report (SECURITY_ANALYST or ADMIN)")
    public InventoryImportDetail importDetail(@PathVariable @Pattern(regexp = "^[0-9a-fA-F-]{36}$") String importId) {
        return service.importDetail(importId);
    }
}
