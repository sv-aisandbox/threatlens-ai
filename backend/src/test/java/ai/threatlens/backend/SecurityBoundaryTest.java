package ai.threatlens.backend;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.notNullValue;

import ai.threatlens.backend.support.AbstractApiTest;
import ai.threatlens.backend.support.StubIntelligence.Received;
import ai.threatlens.backend.support.TestTokens;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/** 401 without a valid token, 403 for the wrong role, and tenant A can never read tenant B. */
class SecurityBoundaryTest extends AbstractApiTest {

    static final String CVE = "CVE-2021-44228";
    static final String AFFECTED = "/api/vulnerabilities/" + CVE + "/affected-assets";
    static final String TEST_SECRET = "test-only-secret-0123456789abcdef0123456789abcdef";

    // ---- 401 -----------------------------------------------------------------------------------

    @Test
    void noTokenIs401WithProblemDetails() {
        io.restassured.RestAssured.given().get(AFFECTED).then()
                .statusCode(401)
                .contentType("application/problem+json")
                .header("WWW-Authenticate", equalTo("Bearer"))
                .header("X-Correlation-Id", notNullValue())
                .body("status", equalTo(401))
                .body("title", equalTo("Unauthorized"))
                .body("correlationId", notNullValue());
        assertThat(STUB.requests()).as("nothing reaches the intelligence service").isEmpty();
    }

    static Stream<Arguments> badTokens() throws Exception {
        String unsigned = new PlainJWT(new JWTClaimsSet.Builder().issuer(TestTokens.ISSUER).subject("x")
                .audience(TestTokens.AUDIENCE).expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("tenant_id", "TENANT-DEMO").claim("realm_access", java.util.Map.of("roles", List.of("ADMIN"))).build())
                .serialize();
        return Stream.of(
                Arguments.of("garbage", "not.a.jwt"),
                Arguments.of("alg none", unsigned),
                Arguments.of("expired", TestTokens.user("TENANT-DEMO", "ADMIN").expiresAt(Instant.now().minusSeconds(3600)).build()),
                Arguments.of("wrong issuer", TestTokens.user("TENANT-DEMO", "ADMIN").issuer("https://evil.invalid/realms/x").build()),
                Arguments.of("wrong audience", TestTokens.user("TENANT-DEMO", "ADMIN").audience("account").build()),
                Arguments.of("no audience", TestTokens.user("TENANT-DEMO", "ADMIN").audience(null).build()),
                Arguments.of("signed by another key", TestTokens.user("TENANT-DEMO", "ADMIN").signedWith(TestTokens.OTHER_KEY).build()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("badTokens")
    void invalidTokensAre401(String label, String token) {
        asUser(token).get(AFFECTED).then().statusCode(401).contentType("application/problem+json");
        asUser(token).post("/api/sources/nvd/sync").then().statusCode(401);
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void nonBearerSchemeIs401() {
        io.restassured.RestAssured.given().header("Authorization", "Basic YWxpY2U6c2VjcmV0").get(AFFECTED).then().statusCode(401);
    }

    // ---- 403: authenticated but not permitted -------------------------------------------------------

    @Test
    void viewerAndAnalystCanReadButCannotSync() {
        for (String token : List.of(viewer("TENANT-DEMO"), analyst("TENANT-DEMO"))) {
            asUser(token).get(AFFECTED).then().statusCode(200);
            asUser(token).get("/api/vulnerabilities/" + CVE).then().statusCode(200);
            asUser(token).get("/api/sources/status").then().statusCode(200);
            asUser(token).post("/api/sources/nvd/sync").then()
                    .statusCode(403).contentType("application/problem+json").body("status", equalTo(403));
        }
        assertThat(STUB.requests()).noneMatch(r -> r.method().equals("POST"));
    }

    @Test
    void adminCanStartSync() {
        asUser(admin("TENANT-DEMO")).post("/api/sources/kev/sync").then()
                .statusCode(202).body("accepted", equalTo(true)).body("source_id", equalTo("kev"));
        assertThat(STUB.requests()).extracting(Received::path).containsExactly("/internal/v1/sources/kev/sync");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("deniedUsers")
    void usersWithoutRoleOrTenantAreForbiddenEverywhere(String label, String token) {
        asUser(token).get(AFFECTED).then().statusCode(403).contentType("application/problem+json");
        asUser(token).get("/api/vulnerabilities/" + CVE).then().statusCode(403);
        asUser(token).get("/api/sources/status").then().statusCode(403);
        asUser(token).post("/api/sources/nvd/sync").then().statusCode(403);
        assertThat(STUB.requests()).isEmpty();
    }

    static Stream<Arguments> deniedUsers() {
        return Stream.of(
                Arguments.of("no realm_access claim", TestTokens.user("TENANT-DEMO").withoutRealmAccess().build()),
                Arguments.of("unknown role only", TestTokens.user("TENANT-DEMO", "ROOT", "default-roles-threatlens").build()),
                Arguments.of("no tenant claim", TestTokens.user(null, "ADMIN").build()),
                Arguments.of("malformed tenant", TestTokens.user("tenant-demo", "ADMIN").build()),
                Arguments.of("injection-looking tenant", TestTokens.user("TENANT-DEMO' OR 1=1 //", "ADMIN").build()));
    }

    // ---- tenant isolation --------------------------------------------------------------------------

    @Test
    void tenantComesFromTheTokenNotFromTheRequest() throws Exception {
        String tokenA = analyst("TENANT-A");
        asUser(tokenA)
                .header("X-Tenant-Id", "TENANT-B")
                .header("X-Tenant", "TENANT-B")
                .queryParam("tenant_id", "TENANT-B")
                .queryParam("tenantId", "TENANT-B")
                .get(AFFECTED)
                .then().statusCode(200)
                .body("tenant_id", equalTo("TENANT-A"))
                .body("results[0].asset_id", equalTo("ASSET-OF-TENANT-A"))
                .body("results[0].tenant_id", equalTo("TENANT-A"));

        Received sent = STUB.requests().getFirst();
        assertThat(sent.query()).as("no tenant hint is forwarded").isNull();
        assertThat(sent.headers()).doesNotContainKeys("x-tenant-id", "x-tenant");
        assertThat(claims(sent.bearer()).getStringClaim("tenant_id")).isEqualTo("TENANT-A");
    }

    @Test
    void twoTenantsGetOnlyTheirOwnData() {
        String a = asUser(analyst("TENANT-A")).get(AFFECTED).then().statusCode(200).extract().asString();
        String b = asUser(analyst("TENANT-B")).get(AFFECTED).then().statusCode(200).extract().asString();
        assertThat(a).contains("ASSET-OF-TENANT-A").doesNotContain("TENANT-B");
        assertThat(b).contains("ASSET-OF-TENANT-B").doesNotContain("TENANT-A");
    }

    @Test
    void viewerCannotUseAnAdminsTenantByTamperingWithBodyOrPath() throws Exception {
        asUser(viewer("TENANT-A")).queryParam("tenant", "TENANT-B").get("/api/sources/status").then().statusCode(200);
        assertThat(claims(STUB.requests().getFirst().bearer()).getStringClaim("tenant_id")).isEqualTo("TENANT-A");
    }

    // ---- the service JWT sent to the Python service ----------------------------------------------------

    @Test
    void serviceJwtIsShortLivedSignedAndCarriesOnlyTrustedClaims() throws Exception {
        String userToken = TestTokens.user("TENANT-DEMO", "SECURITY_ANALYST").subject("alice-subject").build();
        asUser(userToken).get(AFFECTED).then().statusCode(200);

        String forwarded = STUB.requests().getFirst().bearer();
        assertThat(forwarded).isNotEqualTo(userToken); // the user's own token is never passed on
        SignedJWT jwt = SignedJWT.parse(forwarded);
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("HS256");
        assertThat(jwt.verify(new MACVerifier(TEST_SECRET.getBytes(StandardCharsets.UTF_8)))).isTrue();
        JWTClaimsSet c = jwt.getJWTClaimsSet();
        assertThat(c.getIssuer()).isEqualTo("threatlens-backend");
        assertThat(c.getAudience()).containsExactly("threatlens-intelligence");
        assertThat(c.getSubject()).isEqualTo("alice-subject");
        assertThat(c.getStringClaim("tenant_id")).isEqualTo("TENANT-DEMO");
        assertThat(c.getStringListClaim("roles")).containsExactly("SECURITY_ANALYST");
        assertThat(c.getJWTID()).isNotBlank();
        assertThat(c.getExpirationTime().getTime() - c.getIssueTime().getTime()).isEqualTo(60_000L);
    }

    @Test
    void eachCallGetsAFreshServiceToken() throws Exception {
        String token = analyst("TENANT-DEMO");
        asUser(token).get("/api/sources/status").then().statusCode(200);
        asUser(token).get("/api/sources/status").then().statusCode(200);
        List<Received> sent = STUB.requests();
        assertThat(claims(sent.get(0).bearer()).getJWTID()).isNotEqualTo(claims(sent.get(1).bearer()).getJWTID());
    }

    // ---- actuator and headers --------------------------------------------------------------------------

    @Test
    void onlyHealthIsPublicAndItRevealsNoDetails() {
        io.restassured.RestAssured.given().get("/actuator/health").then().statusCode(200)
                .body("status", equalTo("UP")).body("components", org.hamcrest.Matchers.nullValue());
        for (String path : List.of("/actuator/env", "/actuator/beans", "/actuator/heapdump", "/actuator", "/v3/api-docs")) {
            io.restassured.RestAssured.given().get(path).then().statusCode(401);
            asUser(viewer("TENANT-DEMO")).get(path).then().statusCode(403);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/", "/error", "/api", "/swagger-ui.html", "/h2-console"})
    void everythingElseIsDenied(String path) {
        io.restassured.RestAssured.given().get(path).then().statusCode(401);
        asUser(admin("TENANT-DEMO")).get(path).then().statusCode(org.hamcrest.Matchers.anyOf(equalTo(403), equalTo(404)));
    }

    @Test
    void responsesAreNotCacheableAndNotSniffable() {
        asUser(analyst("TENANT-DEMO")).get(AFFECTED).then().statusCode(200)
                .header("Cache-Control", containsString("no-store"))
                .header("X-Content-Type-Options", equalTo("nosniff"))
                .header("X-Frame-Options", not(org.hamcrest.Matchers.emptyOrNullString()));
    }

    private static JWTClaimsSet claims(String jwt) {
        try {
            return SignedJWT.parse(jwt).getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new IllegalStateException(e);
        }
    }
}
