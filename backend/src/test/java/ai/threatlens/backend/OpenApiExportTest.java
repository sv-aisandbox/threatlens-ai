package ai.threatlens.backend;

import static org.assertj.core.api.Assertions.assertThat;

import ai.threatlens.backend.support.AbstractApiTest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.json.JsonMapper;

/**
 * Keeps docs/api/openapi.json in sync with the code. Run {@code ./mvnw test -Dopenapi.update=true}
 * to regenerate it; otherwise the test fails when the committed file has drifted.
 */
class OpenApiExportTest extends AbstractApiTest {

    static final Path FILE = Path.of("..", "docs", "api", "openapi.json");

    @Autowired
    JsonMapper mapper;

    @Test
    void committedOpenApiMatchesTheCode() throws IOException {
        String raw = asUser(admin("TENANT-DEMO")).get("/v3/api-docs").then().statusCode(200).extract().asString();
        String generated = canonical(raw);

        if (Boolean.getBoolean("openapi.update")) {
            Files.createDirectories(FILE.getParent());
            Files.writeString(FILE, generated, StandardCharsets.UTF_8);
        }
        assertThat(FILE).as("run ./mvnw test -Dopenapi.update=true to create it").exists();
        assertThat(Files.readString(FILE, StandardCharsets.UTF_8).replace("\r\n", "\n")).isEqualTo(generated);
    }

    @Test
    void documentedContractIsTheExpectedOne() {
        String raw = asUser(admin("TENANT-DEMO")).get("/v3/api-docs").then().statusCode(200).extract().asString();
        for (String expected : List.of("/api/vulnerabilities/{cveId}", "/api/vulnerabilities/{cveId}/affected-assets",
                "/api/sources/status", "/api/sources/{sourceId}/sync", "bearerAuth")) {
            assertThat(raw).contains(expected);
        }
        assertThat(raw).as("tenant is never a parameter").doesNotContain("tenant_id\",\"in\"").doesNotContain("\"name\":\"tenant");
    }

    /** Stable, pretty-printed JSON with sorted keys so the file diffs cleanly. */
    @SuppressWarnings("unchecked")
    private String canonical(String json) {
        Map<String, Object> doc = mapper.readValue(json, Map.class);
        // springdoc embeds the random test port; publish the stable local development URL instead.
        doc.put("servers", List.of(Map.of("url", "http://127.0.0.1:8080", "description", "Local development")));
        Object tree = sort(doc);
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(tree).replace("\r\n", "\n") + "\n";
    }

    @SuppressWarnings("unchecked")
    private static Object sort(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> sorted = new TreeMap<>();
            ((Map<String, Object>) map).forEach((k, v) -> sorted.put(k, sort(v)));
            return sorted;
        }
        if (value instanceof List<?> list) {
            return list.stream().map(OpenApiExportTest::sort).toList();
        }
        return value;
    }
}
