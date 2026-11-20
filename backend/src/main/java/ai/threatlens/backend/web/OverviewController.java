package ai.threatlens.backend.web;

import ai.threatlens.backend.model.OverviewResponse;
import ai.threatlens.backend.service.OverviewService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/overview")
@Tag(name = "Overview")
public class OverviewController {

    private final OverviewService service;

    public OverviewController(OverviewService service) {
        this.service = service;
    }

    @GetMapping
    @Operation(
            summary = "Security overview of the caller's organization",
            description = "Counts, top confirmed exposures and, for every source and the inventory, when it last succeeded and "
                    + "whether that is too old to call current. The organization comes from the token only.")
    public OverviewResponse overview() {
        return service.overview();
    }
}
