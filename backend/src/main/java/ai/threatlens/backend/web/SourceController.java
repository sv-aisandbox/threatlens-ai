package ai.threatlens.backend.web;

import ai.threatlens.backend.model.SourceStatus;
import ai.threatlens.backend.model.SyncAccepted;
import ai.threatlens.backend.service.SourceService;
import ai.threatlens.backend.service.Validation;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Pattern;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sources")
@Tag(name = "Sources")
public class SourceController {

    private final SourceService service;

    public SourceController(SourceService service) {
        this.service = service;
    }

    @GetMapping("/status")
    @Operation(summary = "Last sync status per intelligence source", description = "Shows last attempt, last success and counters.")
    public List<SourceStatus> status() {
        return service.status();
    }

    @PostMapping("/{sourceId}/sync")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Operation(summary = "Start a sync (ADMIN only)", description = "Runs in the background; poll /api/sources/status.")
    public SyncAccepted sync(@PathVariable @Pattern(regexp = Validation.SOURCE_REGEX) String sourceId) {
        return service.startSync(sourceId);
    }
}
