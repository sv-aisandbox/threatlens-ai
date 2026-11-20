package ai.threatlens.backend;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;

import ai.threatlens.backend.support.AbstractApiTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

/** Metrics are for administrators only; logs are JSON, carry the correlation id and never contain credentials. */
@ExtendWith(OutputCaptureExtension.class)
class ObservabilityTest extends AbstractApiTest {

    @Test
    void metricsAreAdminOnly() {
        io.restassured.RestAssured.given().get("/actuator/metrics").then().statusCode(401);
        asUser(viewer("TENANT-A")).get("/actuator/metrics").then().statusCode(403);
        asUser(analyst("TENANT-A")).get("/actuator/metrics").then().statusCode(403);
        asUser(admin("TENANT-A")).get("/actuator/metrics").then().statusCode(200).body("names", hasItem("http.server.requests"));
    }

    @Test
    void otherActuatorEndpointsStayClosed() {
        for (String path : new String[] {"/actuator/env", "/actuator/beans", "/actuator/heapdump", "/actuator/loggers"}) {
            asUser(admin("TENANT-A")).get(path).then().statusCode(org.hamcrest.Matchers.anyOf(
                    org.hamcrest.Matchers.is(403), org.hamcrest.Matchers.is(404)));
        }
    }

    @Test
    void requestLogsAreJsonWithTheCorrelationIdAndNoCredentials(CapturedOutput output) {
        String cid = "obs-" + java.util.UUID.randomUUID();
        String token = viewer("TENANT-A");
        asUser(token).header("X-Correlation-Id", cid).get("/api/overview").then().statusCode(200);
        String tampered = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.TAMPERED-SIGNATURE-VALUE";
        io.restassured.RestAssured.given().header("Authorization", "Bearer " + tampered).get("/api/overview").then().statusCode(401);

        String logs = output.getAll();
        assertThat(logs).contains("\"cid\":\"" + cid + "\"").contains("\"@timestamp\"").contains("GET /api/overview -> 200");
        assertThat(logs).doesNotContain(token).doesNotContain(tampered).doesNotContain("TAMPERED-SIGNATURE-VALUE");
        assertThat(logs).doesNotContain("hunter2");
    }
}
