package ai.threatlens.backend;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.notNullValue;

import ai.threatlens.backend.support.AbstractApiTest;
import ai.threatlens.backend.support.StubIntelligence.Received;
import io.restassured.response.Response;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Validation, RFC 9457 problem details, upstream failure handling, correlation ids and the audit trail. */
class ApiBehaviourTest extends AbstractApiTest {

    static final String CVE = "CVE-2021-44228";
    static final String AFFECTED = "/api/vulnerabilities/" + CVE + "/affected-assets";

    // ---- happy path ----------------------------------------------------------------------------------

    @Test
    void vulnerabilityDetailsAreReturnedAsTypedJson() {
        asUser(viewer("TENANT-DEMO")).get("/api/vulnerabilities/" + CVE).then().statusCode(200)
                .body("cve_id", equalTo(CVE)).body("cvss_score", equalTo(10.0f)).body("kev_listed", equalTo(true))
                .body("evidence[0].source_name", equalTo("NVD"));
    }

    @Test
    void affectedAssetsIncludeStatusReasonEvidenceAndFreshness() {
        asUser(analyst("TENANT-DEMO")).get(AFFECTED).then().statusCode(200)
                .body("results[0].match_status", equalTo("confirmed"))
                .body("results[0].match_reason", notNullValue())
                .body("results[0].software.cpe", notNullValue())
                .body("freshness.intelligence.nvd_last_success_at", notNullValue())
                .body("freshness.inventory_last_imported_at", notNullValue())
                .body("warnings.size()", equalTo(0))
                .body("results[0]", org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasKey("unexpected_field")));
    }

    @Test
    void environmentFilterIsForwarded() {
        asUser(analyst("TENANT-DEMO")).queryParam("environment", "production").get(AFFECTED).then().statusCode(200);
        assertThat(STUB.requests().getFirst().query()).isEqualTo("environment=production");
    }

    // ---- validation -------------------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"CVE-1", "cve-2021-44228", "CVE-2021-44228x", "CVE-2021-44228%27%20OR%201%3D1", "CVE-2021-44228%0D%0AX-Evil%3A1",
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "CVE-2021-4422800000000000000000000000000000000000000"})
    void invalidCveIdsAreRejectedWithoutCallingUpstream(String bad) {
        for (String path : List.of("/api/vulnerabilities/" + bad, "/api/vulnerabilities/" + bad + "/affected-assets")) {
            Response r = asUser(analyst("TENANT-DEMO")).get(path);
            r.then().statusCode(400).contentType("application/problem+json")
                    .body("status", equalTo(400)).body("title", equalTo("Bad Request")).body("correlationId", notNullValue());
            assertThat(r.asString()).as("the offending value is never echoed").doesNotContain("script").doesNotContain("OR 1").doesNotContain("X-Evil");
        }
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void encodedPathTraversalIsRejectedByTheFirewall() {
        asUser(analyst("TENANT-DEMO")).get("/api/vulnerabilities/..%2F..%2Fetc%2Fpasswd").then().statusCode(400);
        assertThat(STUB.requests()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"moon", "PRODUCTION", "production%27", "", "prod", "production,staging"})
    void invalidEnvironmentIs400(String env) {
        asUser(analyst("TENANT-DEMO")).queryParam("environment", env).get(AFFECTED).then().statusCode(400)
                .contentType("application/problem+json");
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void unknownSourceIs400() {
        asUser(admin("TENANT-DEMO")).post("/api/sources/other/sync").then().statusCode(400);
        asUser(admin("TENANT-DEMO")).post("/api/sources/..%2Fnvd/sync").then().statusCode(400);
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void unknownPathsAndMethodsAreProblemDetails() {
        asUser(analyst("TENANT-DEMO")).get("/api/nothing-here").then().statusCode(404).contentType("application/problem+json");
        asUser(analyst("TENANT-DEMO")).delete("/api/sources/status").then().statusCode(405).contentType("application/problem+json");
        asUser(analyst("TENANT-DEMO")).post("/api/vulnerabilities/" + CVE).then().statusCode(405);
    }

    // ---- upstream failures: generic problems, nothing leaked --------------------------------------------

    @Test
    void upstreamNotFoundIs404() {
        asUser(analyst("TENANT-DEMO")).get("/api/vulnerabilities/CVE-2099-0001").then().statusCode(404)
                .contentType("application/problem+json").body("title", equalTo("Not Found"));
    }

    @Test
    void upstreamConflictIs409() {
        STUB.failWith(409, "{\"detail\":\"a sync for this source is already running\"}");
        asUser(admin("TENANT-DEMO")).post("/api/sources/nvd/sync").then().statusCode(409)
                .contentType("application/problem+json").body("title", equalTo("Conflict"));
    }

    @ParameterizedTest
    @ValueSource(ints = {500, 503, 401, 403, 422})
    void upstreamErrorsBecomeABlandBadGateway(int status) {
        STUB.failWith(status, "SECRET-INTERNAL-TRACE jdbc:postgresql://db password=hunter2");
        Response r = asUser(analyst("TENANT-DEMO")).get(AFFECTED);
        r.then().statusCode(502).contentType("application/problem+json").body("title", equalTo("Bad Gateway"));
        assertThat(r.asString()).doesNotContain("SECRET-INTERNAL-TRACE").doesNotContain("hunter2").doesNotContain("jdbc");
    }

    @Test
    void unparseableUpstreamBodyIsABadGateway() {
        STUB.failWith(200, "<html>not json</html>");
        asUser(analyst("TENANT-DEMO")).get(AFFECTED).then().statusCode(502).contentType("application/problem+json");
    }

    @Test
    void slowUpstreamTimesOutAs504() {
        STUB.delay(4_000); // the test profile sets a 2 second read timeout
        asUser(analyst("TENANT-DEMO")).get(AFFECTED).then().statusCode(504).contentType("application/problem+json")
                .body("title", equalTo("Gateway Timeout"));
    }

    // ---- correlation ids -----------------------------------------------------------------------------------

    @Test
    void validCorrelationIdIsEchoedAndForwardedToPython() {
        String cid = "test-" + UUID.randomUUID();
        asUser(analyst("TENANT-DEMO")).header("X-Correlation-Id", cid).get(AFFECTED).then().statusCode(200)
                .header("X-Correlation-Id", equalTo(cid));
        assertThat(STUB.requests().getFirst().headers()).containsEntry("x-correlation-id", cid);
    }

    @Test
    void malformedCorrelationIdIsReplaced() {
        String response = asUser(analyst("TENANT-DEMO")).header("X-Correlation-Id", "bad id; DROP TABLE").get(AFFECTED)
                .then().statusCode(200).header("X-Correlation-Id", matchesPattern("[0-9a-f-]{36}"))
                .extract().header("X-Correlation-Id");
        assertThat(STUB.requests().getFirst().headers()).containsEntry("x-correlation-id", response);
    }

    @Test
    void errorBodiesCarryTheSameCorrelationIdAsTheHeader() {
        String cid = "err-" + UUID.randomUUID();
        asUser(analyst("TENANT-DEMO")).header("X-Correlation-Id", cid).get("/api/vulnerabilities/not-a-cve").then()
                .statusCode(400).header("X-Correlation-Id", equalTo(cid)).body("correlationId", equalTo(cid));
    }

    // ---- audit trail ------------------------------------------------------------------------------------------

    private Map<String, Object> auditRow(String cid) {
        await().atMost(Duration.ofSeconds(5)).until(
                () -> jdbc.sql("SELECT count(*) FROM audit_log WHERE correlation_id = :c").param("c", cid).query(Long.class).single() > 0);
        return jdbc.sql("SELECT actor, tenant_id, action, resource, outcome, http_status FROM audit_log WHERE correlation_id = :c")
                .param("c", cid).query().singleRow();
    }

    @Test
    void successfulReadIsAudited() {
        String cid = "aud-" + UUID.randomUUID();
        String token = ai.threatlens.backend.support.TestTokens.user("TENANT-DEMO", "SECURITY_ANALYST").subject("bob-sub").build();
        asUser(token).header("X-Correlation-Id", cid).get(AFFECTED).then().statusCode(200);
        assertThat(auditRow(cid)).containsEntry("actor", "bob-sub").containsEntry("tenant_id", "TENANT-DEMO")
                .containsEntry("action", "GET /api/vulnerabilities/{cveId}/affected-assets")
                .containsEntry("resource", CVE).containsEntry("outcome", "success").containsEntry("http_status", 200);
    }

    @Test
    void forbiddenActionIsAuditedAsDenied() {
        String cid = "aud-" + UUID.randomUUID();
        asUser(viewer("TENANT-DEMO")).header("X-Correlation-Id", cid).post("/api/sources/nvd/sync").then().statusCode(403);
        assertThat(auditRow(cid)).containsEntry("tenant_id", "TENANT-DEMO").containsEntry("outcome", "denied")
                .containsEntry("http_status", 403).containsEntry("action", "POST /api/sources/{sourceId}/sync")
                .containsEntry("resource", "nvd");
    }

    @Test
    void unauthenticatedRequestIsAuditedAsAnonymous() {
        String cid = "aud-" + UUID.randomUUID();
        io.restassured.RestAssured.given().header("X-Correlation-Id", cid).get(AFFECTED).then().statusCode(401);
        assertThat(auditRow(cid)).containsEntry("actor", "anonymous").containsEntry("outcome", "denied").containsEntry("http_status", 401);
        assertThat(auditRow(cid).get("tenant_id")).isNull();
    }

    @Test
    void invalidInputIsAuditedWithoutTheOffendingValue() {
        String cid = "aud-" + UUID.randomUUID();
        asUser(analyst("TENANT-DEMO")).header("X-Correlation-Id", cid).get("/api/vulnerabilities/CVE-2021-44228x").then().statusCode(400);
        Map<String, Object> row = auditRow(cid);
        assertThat(row).containsEntry("outcome", "error");
        assertThat(row.get("resource")).isNull(); // only well-formed identifiers are stored
    }

    @Test
    void auditRowsNeverContainTokens() {
        String cid = "aud-" + UUID.randomUUID();
        asUser(analyst("TENANT-DEMO")).header("X-Correlation-Id", cid).get(AFFECTED).then().statusCode(200);
        auditRow(cid);
        Long suspicious = jdbc.sql("""
                SELECT count(*) FROM audit_log
                WHERE concat_ws('|', actor, tenant_id, action, resource, outcome, correlation_id) ~ 'eyJ|Bearer'
                """).query(Long.class).single();
        assertThat(suspicious).isZero();
    }

    @Test
    void healthChecksAreNotAudited() {
        long before = jdbc.sql("SELECT count(*) FROM audit_log").query(Long.class).single();
        io.restassured.RestAssured.given().get("/actuator/health").then().statusCode(200);
        assertThat(jdbc.sql("SELECT count(*) FROM audit_log").query(Long.class).single()).isEqualTo(before);
    }
}
