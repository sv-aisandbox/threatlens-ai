package ai.threatlens.backend;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;

import ai.threatlens.backend.support.AbstractApiTest;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

@TestPropertySource(properties = {
    "threatlens.rate-limit.requests-per-minute=3",
    "threatlens.rate-limit.sync-per-minute=1",
    "threatlens.rate-limit.analyst-per-minute=2"
})
class RateLimitTest extends AbstractApiTest {

    @Test
    void callersAreLimitedIndividuallyAndLimitedCallsNeverReachPython() {
        String alice = analyst("TENANT-DEMO");
        String bob = analyst("TENANT-DEMO");
        for (int i = 0; i < 3; i++) {
            asUser(alice).get("/api/sources/status").then().statusCode(200);
        }
        asUser(alice).get("/api/sources/status").then().statusCode(429)
                .contentType("application/problem+json")
                .header("Retry-After", matchesPattern("\\d+"))
                .body("status", equalTo(429));
        assertThat(STUB.requests()).as("the limited call was not forwarded").hasSize(3);

        asUser(bob).get("/api/sources/status").then().statusCode(200); // a different user keeps their own budget
    }

    @Test
    void syncHasASmallerBudgetThanReads() {
        String admin = admin("TENANT-DEMO");
        asUser(admin).post("/api/sources/kev/sync").then().statusCode(202);
        asUser(admin).post("/api/sources/kev/sync").then().statusCode(429);
        asUser(admin).get("/api/sources/status").then().statusCode(200); // reads are counted separately
    }

    @Test
    void analystQuestionsHaveTheirOwnSmallBudget() {
        String analyst = analyst("TENANT-DEMO");
        for (int i = 0; i < 2; i++) {
            asUser(analyst).contentType("application/json").body("{\"question\":\"Which assets are critical?\"}").post("/api/analyst/ask").then().statusCode(200);
        }
        asUser(analyst).contentType("application/json").body("{\"question\":\"Which assets are critical?\"}").post("/api/analyst/ask").then()
                .statusCode(429).contentType("application/problem+json").header("Retry-After", matchesPattern("\\d+"));
        asUser(analyst).get("/api/sources/status").then().statusCode(200); // reads keep their own budget
    }

    @Test
    void limitedRequestsAreAudited() {
        String token = analyst("TENANT-DEMO");
        String cid = "rl-" + java.util.UUID.randomUUID();
        for (int i = 0; i < 3; i++) {
            asUser(token).get("/api/sources/status").then().statusCode(200);
        }
        asUser(token).header("X-Correlation-Id", cid).get("/api/sources/status").then().statusCode(429);
        org.awaitility.Awaitility.await().atMost(java.time.Duration.ofSeconds(5)).untilAsserted(() ->
                assertThat(jdbc.sql("SELECT outcome FROM audit_log WHERE correlation_id = :c").param("c", cid)
                        .query(String.class).single()).isEqualTo("denied"));
    }
}
