package ai.threatlens.backend;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;

import ai.threatlens.backend.support.AbstractApiTest;
import ai.threatlens.backend.support.StubIntelligence.Received;
import ai.threatlens.backend.support.TestTokens;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** POST /api/analyst/ask: authentication, roles, tenant from the token only, validation, errors, audit. */
class AnalystApiTest extends AbstractApiTest {

    static final String ASK = "/api/analyst/ask";
    static final String QUESTION = "Which of my production assets are affected by CVE-2021-44228, and how sure are we?";

    private static io.restassured.specification.RequestSpecification ask(String token) {
        return asUser(token).contentType(ContentType.JSON);
    }

    private static Map<String, String> body(String question) {
        return Map.of("question", question);
    }

    // ---- authentication and roles ----------------------------------------------------------------------------

    @Test
    void noTokenIs401() {
        io.restassured.RestAssured.given().contentType(ContentType.JSON).body(body(QUESTION)).post(ASK).then()
                .statusCode(401).contentType("application/problem+json");
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void viewersAndRoleLessUsersAreForbidden() {
        ask(viewer("TENANT-DEMO")).body(body(QUESTION)).post(ASK).then().statusCode(403).contentType("application/problem+json");
        ask(TestTokens.user("TENANT-DEMO").withoutRealmAccess().build()).body(body(QUESTION)).post(ASK).then().statusCode(403);
        ask(TestTokens.user(null, "SECURITY_ANALYST").build()).body(body(QUESTION)).post(ASK).then().statusCode(403);
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void analystsAndAdminsReceiveTheTypedAnswer() {
        for (String token : List.of(analyst("TENANT-A"), admin("TENANT-A"))) {
            ask(token).body(body(QUESTION)).post(ASK).then().statusCode(200)
                    .body("outcome", equalTo("answered"))
                    .body("summary.confirmed_exposures", equalTo(1))
                    .body("findings.confirmed", hasSize(1))
                    .body("findings.confirmed[0].asset_id", equalTo("ASSET-OF-TENANT-A"))
                    .body("findings.confirmed[0].software.product", equalTo("Log4j"))
                    .body("findings.possible", hasSize(0))
                    .body("evidence[0].source_name", equalTo("NVD"))
                    .body("evidence[0].collected_at", notNullValue())
                    .body("freshness.intelligence.nvd_last_success_at", notNullValue())
                    .body("grounding.ok", equalTo(true))
                    .body("trace[0].tool", equalTo("get_affected_assets"))
                    .body("trace[0].args.cve_id", equalTo("CVE-2021-44228"))
                    .body("usage.provider", equalTo("mock"))
                    .body("$", org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasKey("unexpected")))
                    .body("trace[0]", org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasKey("unexpected")));
        }
    }

    // ---- tenant from the token only ---------------------------------------------------------------------------

    @Test
    void thePythonServiceReceivesOnlyTheQuestionAndASignedTenant() throws Exception {
        ask(analyst("TENANT-A")).header("X-Tenant-Id", "TENANT-B").queryParam("tenant_id", "TENANT-B")
                .body(body(QUESTION)).post(ASK).then().statusCode(200).body("findings.confirmed[0].asset_id", equalTo("ASSET-OF-TENANT-A"));
        Received sent = STUB.requests().getFirst();
        assertThat(sent.path()).isEqualTo("/internal/v1/analyst/ask");
        assertThat(sent.query()).isNull();
        assertThat(sent.headers()).doesNotContainKeys("x-tenant-id");
        assertThat(JsonPath.from(sent.body()).getMap("$")).containsOnlyKeys("question").containsEntry("question", QUESTION);
        var claims = SignedJWT.parse(sent.bearer()).getJWTClaimsSet();
        assertThat(claims.getStringClaim("tenant_id")).isEqualTo("TENANT-A");
        assertThat(claims.getStringListClaim("roles")).containsExactly("SECURITY_ANALYST");
    }

    @Test
    void twoTenantsAreAnsweredSeparately() {
        String a = ask(analyst("TENANT-A")).body(body(QUESTION)).post(ASK).then().statusCode(200).extract().asString();
        String b = ask(analyst("TENANT-B")).body(body(QUESTION)).post(ASK).then().statusCode(200).extract().asString();
        assertThat(a).contains("ASSET-OF-TENANT-A").doesNotContain("TENANT-B");
        assertThat(b).contains("ASSET-OF-TENANT-B").doesNotContain("TENANT-A");
    }

    @ParameterizedTest
    @ValueSource(strings = {"tenant_id", "tenantId", "tenant", "roles", "tools", "role"})
    void extraBodyFieldsAreRejectedNotIgnored(String field) {
        ask(analyst("TENANT-A")).body(Map.of("question", QUESTION, field, "TENANT-B")).post(ASK).then().statusCode(400)
                .contentType("application/problem+json");
        assertThat(STUB.requests()).isEmpty();
    }

    // ---- validation ----------------------------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"", "  ", "ab"})
    void tooShortOrBlankQuestionsAre400(String question) {
        ask(analyst("TENANT-A")).body(body(question)).post(ASK).then().statusCode(400).contentType("application/problem+json")
                .body("status", equalTo(400)).body("correlationId", notNullValue());
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void anOversizedQuestionIs400AndTheLimitIsExact() {
        ask(analyst("TENANT-A")).body(body("x".repeat(2001))).post(ASK).then().statusCode(400);
        ask(analyst("TENANT-A")).body(body("x".repeat(2000))).post(ASK).then().statusCode(200);
    }

    @Test
    void malformedBodiesAre400WithoutEchoingInput() {
        for (String raw : List.of("", "not json at all SECRET-ECHO", "[1,2,3]", "{\"question\": 42}", "{\"question\": null}", "{}")) {
            Response r = asUser(analyst("TENANT-A")).contentType(ContentType.JSON).body(raw).post(ASK);
            r.then().statusCode(400).contentType("application/problem+json");
            assertThat(r.asString()).doesNotContain("SECRET-ECHO");
        }
        asUser(analyst("TENANT-A")).contentType(ContentType.TEXT).body("question=hi").post(ASK).then().statusCode(415);
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void onlyPostIsAllowed() {
        asUser(analyst("TENANT-A")).get(ASK).then().statusCode(405).contentType("application/problem+json");
        asUser(analyst("TENANT-A")).delete(ASK).then().statusCode(405);
    }

    // ---- upstream behaviour ----------------------------------------------------------------------------------------

    @Test
    void anUnavailableOrBusyAnalystIs503() {
        for (int status : List.of(503, 429)) {
            STUB.failWith(status, "{\"detail\":\"SECRET-INTERNAL\"}");
            Response r = ask(analyst("TENANT-A")).body(body(QUESTION)).post(ASK);
            r.then().statusCode(503).contentType("application/problem+json").body("title", equalTo("Service Unavailable"));
            assertThat(r.asString()).doesNotContain("SECRET-INTERNAL");
        }
    }

    @Test
    void aRejectedQuestionFromPythonIs400AndOtherFailuresAreBlandBadGateways() {
        STUB.failWith(422, "{\"detail\":\"invalid question\"}");
        ask(analyst("TENANT-A")).body(body(QUESTION)).post(ASK).then().statusCode(400);
        for (int status : List.of(500, 401, 403)) {
            STUB.failWith(status, "SECRET-INTERNAL-TRACE password=hunter2");
            Response r = ask(analyst("TENANT-A")).body(body(QUESTION)).post(ASK);
            r.then().statusCode(502).contentType("application/problem+json");
            assertThat(r.asString()).doesNotContain("SECRET-INTERNAL").doesNotContain("hunter2");
        }
    }

    @Test
    void theAnalystGetsALongerTimeoutThanOrdinaryLookups() {
        STUB.delay(3_000); // ordinary calls time out after 2 s in the test profile; the analyst may take up to 6 s
        asUser(viewer("TENANT-A")).get("/api/sources/status").then().statusCode(504);
        ask(analyst("TENANT-A")).body(body(QUESTION)).post(ASK).then().statusCode(200);
    }

    @Test
    void theAnalystTimeoutIsStillBounded() {
        STUB.delay(8_000);
        ask(analyst("TENANT-A")).body(body(QUESTION)).post(ASK).then().statusCode(504).contentType("application/problem+json");
    }

    // ---- correlation and audit -------------------------------------------------------------------------------------

    @Test
    void theCorrelationIdIsForwardedEchoedAndAudited() {
        String cid = "analyst-" + UUID.randomUUID();
        ask(analyst("TENANT-A")).header("X-Correlation-Id", cid).body(body(QUESTION)).post(ASK).then().statusCode(200)
                .header("X-Correlation-Id", equalTo(cid)).body("correlation_id", equalTo(cid));
        assertThat(STUB.requests().getFirst().headers()).containsEntry("x-correlation-id", cid);
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
                assertThat(jdbc.sql("SELECT action || '|' || tenant_id || '|' || outcome || '|' || http_status FROM audit_log WHERE correlation_id = :c")
                        .param("c", cid).query(String.class).single())
                        .isEqualTo("POST /api/analyst/ask|TENANT-A|success|200"));
    }

    @Test
    void deniedAndInvalidCallsAreAuditedWithoutTheQuestionText() {
        String denied = "analyst-" + UUID.randomUUID();
        String invalid = "analyst-" + UUID.randomUUID();
        ask(viewer("TENANT-A")).header("X-Correlation-Id", denied).body(body("secret-marker-question-1")).post(ASK).then().statusCode(403);
        ask(analyst("TENANT-A")).header("X-Correlation-Id", invalid).body(body("")).post(ASK).then().statusCode(400);
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            assertThat(jdbc.sql("SELECT outcome FROM audit_log WHERE correlation_id = :c").param("c", denied).query(String.class).single()).isEqualTo("denied");
            assertThat(jdbc.sql("SELECT outcome FROM audit_log WHERE correlation_id = :c").param("c", invalid).query(String.class).single()).isEqualTo("error");
        });
        Long leaked = jdbc.sql("SELECT count(*) FROM audit_log WHERE concat_ws('|', actor, action, resource, correlation_id) LIKE '%secret-marker%'")
                .query(Long.class).single();
        assertThat(leaked).isZero();
    }
}
