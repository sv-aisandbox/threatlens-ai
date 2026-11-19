package ai.threatlens.backend.web;

import ai.threatlens.backend.model.AnalystAnswer;
import ai.threatlens.backend.service.AnalystService;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.HashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/analyst")
@Tag(name = "Analyst")
public class AnalystController {

    /**
     * Only the question. Any other field (a tenant, a role, a tool list) is rejected rather than ignored: Jackson's
     * default is to drop unknown properties silently, so they are collected and validated to be empty.
     */
    public static class AskRequest {

        @NotBlank
        @Size(min = 3, max = 2000)
        @Schema(example = "Which of my production assets are affected by CVE-2021-44228, and how sure are we?")
        private String question;

        private final Map<String, Object> unexpected = new HashMap<>();

        public String getQuestion() {
            return question;
        }

        public void setQuestion(String question) {
            this.question = question;
        }

        @JsonAnySetter
        void collectUnexpected(String name, Object value) {
            unexpected.put(name, value);
        }

        @JsonIgnore
        @Schema(hidden = true)
        @AssertTrue(message = "unexpected fields")
        public boolean isOnlyKnownFields() {
            return unexpected.isEmpty();
        }
    }

    private final AnalystService service;

    public AnalystController(AnalystService service) {
        this.service = service;
    }

    @PostMapping("/ask")
    @Operation(
            summary = "Ask the AI security analyst (SECURITY_ANALYST or ADMIN)",
            description = "Answers from the caller's own tenant only. Findings are built from tool results and kept in "
                    + "confirmed / possible / unknown groups; evidence, freshness warnings and the full tool trace are included.")
    public AnalystAnswer ask(@Valid @RequestBody AskRequest request) {
        return service.ask(request.getQuestion());
    }
}
