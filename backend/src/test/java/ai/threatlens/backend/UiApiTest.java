package ai.threatlens.backend;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import ai.threatlens.backend.support.AbstractApiTest;
import ai.threatlens.backend.support.StubIntelligence.Received;
import ai.threatlens.backend.support.TestTokens;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.response.Response;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Overview, vulnerability search and the CVE graph: the data behind the web UI. */
class UiApiTest extends AbstractApiTest {

    static final String CVE = "CVE-2021-44228";

    // ---- overview -------------------------------------------------------------------------------------------

    @Test
    void overviewRequiresAuthentication() {
        io.restassured.RestAssured.given().get("/api/overview").then().statusCode(401).contentType("application/problem+json");
        asUser(TestTokens.user("TENANT-A").withoutRealmAccess().build()).get("/api/overview").then().statusCode(403);
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void everyRoleSeesTheOverviewWithFreshnessReportedSeparately() {
        for (String token : List.of(viewer("TENANT-A"), analyst("TENANT-A"), admin("TENANT-A"))) {
            asUser(token).get("/api/overview").then().statusCode(200)
                    .body("tenant_id", equalTo("TENANT-A"))
                    .body("vulnerabilities.kev", equalTo(4))
                    .body("assets.affected_critical", equalTo(3))
                    .body("exposure.confirmed", equalTo(7))
                    .body("top_exposures[0].cve_id", equalTo(CVE))
                    .body("sources", hasSize(2))
                    .body("sources[0].stale", equalTo(false))
                    .body("sources[1].last_success_at", nullValue())  // never synced is visible, not hidden
                    .body("sources[1].stale", equalTo(true))
                    .body("inventory.stale", equalTo(true))
                    .body("stale_after_hours", equalTo(48))
                    .body("warnings[0]", notNullValue())
                    .body("top_exposures[0]", not(hasKey("unexpected")));
        }
    }

    @Test
    void theOverviewTenantComesFromTheTokenOnly() throws Exception {
        asUser(viewer("TENANT-A")).header("X-Tenant-Id", "TENANT-B").queryParam("tenant_id", "TENANT-B").get("/api/overview").then()
                .statusCode(200).body("tenant_id", equalTo("TENANT-A"));
        Received sent = STUB.requests().getFirst();
        assertThat(sent.query()).isNull();
        assertThat(SignedJWT.parse(sent.bearer()).getJWTClaimsSet().getStringClaim("tenant_id")).isEqualTo("TENANT-A");
        asUser(viewer("TENANT-B")).get("/api/overview").then().body("tenant_id", equalTo("TENANT-B"));
    }

    // ---- search ----------------------------------------------------------------------------------------------

    @Test
    void searchForwardsOnlyValidatedParameters() {
        asUser(viewer("TENANT-A")).queryParam("query", "log4j").queryParam("kevOnly", true).queryParam("minCvss", 9.5).queryParam("limit", 5)
                .get("/api/vulnerabilities").then().statusCode(200)
                .body("results[0].cve_id", equalTo(CVE)).body("results[0].kev_listed", equalTo(true))
                .body("truncated", equalTo(false)).body("results[0]", not(hasKey("unexpected")));
        String query = STUB.requests().getFirst().query();
        assertThat(query).contains("query=log4j", "kev_only=true", "min_cvss=9.5", "limit=5");
    }

    @Test
    void searchWithoutParametersUsesSafeDefaults() {
        asUser(viewer("TENANT-A")).get("/api/vulnerabilities").then().statusCode(200);
        assertThat(STUB.requests().getFirst().query()).contains("kev_only=false", "limit=20").doesNotContain("query=");
    }

    @ParameterizedTest
    @ValueSource(strings = {"query=a", "query=x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x%20x",
            "minCvss=11", "minCvss=-1", "limit=0", "limit=51", "kevOnly=maybe", "limit=ten"})
    void invalidSearchParametersAre400WithoutCallingUpstream(String qs) {
        Response r = asUser(viewer("TENANT-A")).get("/api/vulnerabilities?" + qs);
        r.then().statusCode(400).contentType("application/problem+json");
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void searchRequiresAuthentication() {
        io.restassured.RestAssured.given().get("/api/vulnerabilities").then().statusCode(401);
    }

    // ---- graph -----------------------------------------------------------------------------------------------

    @Test
    void theGraphIsTypedAndOnlyContainsTheCallersAssets() {
        asUser(analyst("TENANT-A")).get("/api/vulnerabilities/" + CVE + "/graph").then().statusCode(200)
                .body("cve_id", equalTo(CVE)).body("nodes", hasSize(3)).body("edges", hasSize(2))
                .body("nodes.type", hasItem("asset")).body("nodes.id", hasItem("ASSET-OF-TENANT-A"))
                .body("edges.find { it.type == 'AFFECTED_BY' }.match_status", equalTo("confirmed"))
                .body("edges.find { it.type == 'AFFECTED_BY' }.reason", notNullValue());
        asUser(analyst("TENANT-B")).get("/api/vulnerabilities/" + CVE + "/graph").then().body("nodes.id", hasItem("ASSET-OF-TENANT-B"));
    }

    @Test
    void theGraphForwardsTheNotAffectedSwitchAndNothingElse() {
        asUser(viewer("TENANT-A")).queryParam("includeNotAffected", true).queryParam("tenant_id", "TENANT-B")
                .get("/api/vulnerabilities/" + CVE + "/graph").then().statusCode(200);
        assertThat(STUB.requests().getFirst().query()).isEqualTo("include_not_affected=true");
    }

    @ParameterizedTest
    @ValueSource(strings = {"CVE-1", "cve-2021-44228", "CVE-2021-44228x", "CVE-2021-44228%27%20OR%201%3D1"})
    void aMalformedCveIdIsRejectedBeforeAnyUpstreamCall(String bad) {
        asUser(viewer("TENANT-A")).get("/api/vulnerabilities/" + bad + "/graph").then().statusCode(400).contentType("application/problem+json");
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void anUnknownCveIs404AndTheGraphNeedsAToken() {
        asUser(viewer("TENANT-A")).get("/api/vulnerabilities/CVE-2099-0001/graph").then().statusCode(404).contentType("application/problem+json");
        io.restassured.RestAssured.given().get("/api/vulnerabilities/" + CVE + "/graph").then().statusCode(401);
    }

    @Test
    void upstreamFailuresStayBland() {
        STUB.failWith(500, "SECRET-TRACE password=hunter2");
        for (String path : List.of("/api/overview", "/api/vulnerabilities", "/api/vulnerabilities/" + CVE + "/graph")) {
            Response r = asUser(viewer("TENANT-A")).get(path);
            r.then().statusCode(502).contentType("application/problem+json");
            assertThat(r.asString()).doesNotContain("SECRET-TRACE").doesNotContain("hunter2");
        }
    }
}
