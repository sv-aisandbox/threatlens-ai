package ai.threatlens.backend;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;

import ai.threatlens.backend.support.AbstractApiTest;
import ai.threatlens.backend.support.StubIntelligence.Received;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Inventory upload (ADMIN) and import history: validation, tenant from the token, fixed error wording. */
class InventoryApiTest extends AbstractApiTest {

    static final String UPLOAD = "/api/inventory/import";
    static final String CSV = "asset_id,name,asset_type,environment,criticality,internet_exposed\nASSET-1,a,server,production,low,false\nASSET-2,b,nope,production,low,false\n";
    static final String IMPORT_ID = "11111111-2222-3333-4444-555555555555";

    private static io.restassured.specification.RequestSpecification upload(String token, String filename, String content) {
        return asUser(token).multiPart("file", filename, content.getBytes(StandardCharsets.UTF_8), "text/csv");
    }

    // ---- who may upload --------------------------------------------------------------------------------------

    @Test
    void onlyAdministratorsMayUpload() {
        io.restassured.RestAssured.given().multiPart("file", "x.csv", CSV.getBytes(StandardCharsets.UTF_8)).post(UPLOAD).then().statusCode(401);
        upload(viewer("TENANT-A"), "x.csv", CSV).post(UPLOAD).then().statusCode(403);
        upload(analyst("TENANT-A"), "x.csv", CSV).post(UPLOAD).then().statusCode(403);
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void anUploadReturnsTheCountersTheRejectReportAndTheMatchingSummary() {
        upload(admin("TENANT-A"), "inventory.csv", CSV).post(UPLOAD).then().statusCode(200)
                .body("import_id", equalTo(IMPORT_ID)).body("tenant_id", equalTo("TENANT-A")).body("format", equalTo("csv"))
                .body("rows_rejected", equalTo(1)).body("rejects", hasSize(1)).body("rejects[0].ref", equalTo("row 3"))
                .body("rejects[0].errors[0].field", equalTo("asset_type")).body("matching.created", equalTo(1));
    }

    @Test
    void thePythonServiceReceivesTheExactBytesAndASignedTenantAndNothingElse() throws Exception {
        upload(admin("TENANT-A"), "inventory.csv", CSV).header("X-Tenant-Id", "TENANT-B").queryParam("tenant_id", "TENANT-B")
                .post(UPLOAD).then().statusCode(200);
        Received sent = STUB.requests().getFirst();
        assertThat(sent.path()).isEqualTo("/internal/v1/inventory/import");
        assertThat(sent.query()).isNull();
        JsonPath body = JsonPath.from(sent.body());
        assertThat(body.getMap("$")).containsOnlyKeys("filename", "format", "content_base64");
        assertThat(new String(Base64.getDecoder().decode(body.getString("content_base64")), StandardCharsets.UTF_8)).isEqualTo(CSV);
        assertThat(body.getString("format")).isEqualTo("csv");
        assertThat(SignedJWT.parse(sent.bearer()).getJWTClaimsSet().getStringClaim("tenant_id")).isEqualTo("TENANT-A");
    }

    @Test
    void theFormatIsDerivedFromTheExtensionAndTheFilenameIsMadeSafe() {
        upload(admin("TENANT-A"), "../../etc/pass wd<script>.JSON", "{}\n{}\n{}\n").post(UPLOAD).then().statusCode(200).body("format", equalTo("json"));
        JsonPath body = JsonPath.from(STUB.requests().getFirst().body());
        assertThat(body.getString("filename")).isEqualTo("pass wd_script_.JSON").doesNotContain("/", "..", "<");
        upload(admin("TENANT-A"), "C:\\Users\\x\\inventory.csv", CSV).post(UPLOAD).then().statusCode(200);
        assertThat(JsonPath.from(STUB.requests().getLast().body()).getString("filename")).isEqualTo("inventory.csv");
    }

    // ---- validation ------------------------------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"inventory.exe", "inventory", "inventory.csv.exe", "inventory.xlsx", ".csv.png"})
    void onlyCsvAndJsonAreAccepted(String filename) {
        upload(admin("TENANT-A"), filename, CSV).post(UPLOAD).then().statusCode(400).contentType("application/problem+json");
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void anEmptyFileOrAMissingPartIs400() {
        upload(admin("TENANT-A"), "empty.csv", "").post(UPLOAD).then().statusCode(400);
        asUser(admin("TENANT-A")).multiPart("other", "x.csv", CSV.getBytes(StandardCharsets.UTF_8)).post(UPLOAD).then().statusCode(400);
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void anOversizedFileIsRejectedBeforeItReachesPython() {
        byte[] big = new byte[5 * 1024 * 1024 + 1024];
        java.util.Arrays.fill(big, (byte) 'a');
        Response r = asUser(admin("TENANT-A")).multiPart("file", "big.csv", big, "text/csv").post(UPLOAD);
        assertThat(r.statusCode()).isIn(400, 413);
        assertThat(r.contentType()).contains("problem+json");
        assertThat(STUB.requests()).isEmpty();
    }

    @Test
    void aNonMultipartBodyIs415() {
        asUser(admin("TENANT-A")).contentType("application/json").body("{\"file\":\"x\"}").post(UPLOAD).then().statusCode(415);
    }

    // ---- file-level rejection uses OUR wording ----------------------------------------------------------------------

    @Test
    void aRejectedFileGets422WithFixedWordingAndOnlyAllowlistedColumnNames() {
        Response r = upload(admin("TENANT-A"), "bad.csv", CSV).post(UPLOAD);
        r.then().statusCode(422).contentType("application/problem+json").body("code", equalTo("missing_columns")).body("correlationId", notNullValue());
        assertThat(r.jsonPath().getString("detail")).isEqualTo("The CSV is missing required columns: asset_id.");
        assertThat(r.asString()).doesNotContain("SECRET-COLUMN");
    }

    @Test
    void anUnknownOrHostileUpstreamCodeIsNeverEchoed() {
        Response r = upload(admin("TENANT-A"), "evil.csv", CSV).post(UPLOAD);
        r.then().statusCode(422).body("code", equalTo("unknown"));
        assertThat(r.jsonPath().getString("detail")).isEqualTo("The file could not be imported.");
        assertThat(r.asString()).doesNotContain("<script>").doesNotContain("<img");
    }

    @Test
    void anUnexpectedUpstreamValidationShapeIsABadGateway() {
        upload(admin("TENANT-A"), "weird.csv", CSV).post(UPLOAD).then().statusCode(502).contentType("application/problem+json");
    }

    @Test
    void otherUpstreamFailuresAreBland() {
        STUB.failWith(500, "SECRET-TRACE");
        Response r = upload(admin("TENANT-A"), "x.csv", CSV).post(UPLOAD);
        r.then().statusCode(502);
        assertThat(r.asString()).doesNotContain("SECRET-TRACE");
    }

    // ---- history ----------------------------------------------------------------------------------------------------

    @Test
    void analystsAndAdminsSeeTheImportHistoryViewersDoNot() {
        for (String token : List.of(analyst("TENANT-A"), admin("TENANT-A"))) {
            asUser(token).get("/api/inventory/imports").then().statusCode(200).body("[0].source_name", equalTo("inventory.csv")).body("[0].rows_rejected", equalTo(1));
            asUser(token).get("/api/inventory/imports/" + IMPORT_ID).then().statusCode(200).body("rejects", hasSize(1));
        }
        asUser(viewer("TENANT-A")).get("/api/inventory/imports").then().statusCode(403);
        asUser(viewer("TENANT-A")).get("/api/inventory/imports/" + IMPORT_ID).then().statusCode(403);
        io.restassured.RestAssured.given().get("/api/inventory/imports").then().statusCode(401);
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-uuid", "11111111-2222-3333-4444-55555555555", "11111111-2222-3333-4444-555555555555x", "%27%3B%20DROP%20TABLE"})
    void aMalformedImportIdIs400(String id) {
        asUser(admin("TENANT-A")).get("/api/inventory/imports/" + id).then().statusCode(400);
    }

    @Test
    void anUnknownImportIs404() {
        asUser(admin("TENANT-A")).get("/api/inventory/imports/00000000-0000-0000-0000-000000000000").then().statusCode(404).contentType("application/problem+json");
    }

    // ---- audit -------------------------------------------------------------------------------------------------------

    @Test
    void uploadsAreAuditedWithoutTheFilenameOrContent() {
        String cid = "inv-" + UUID.randomUUID();
        upload(admin("TENANT-A"), "secret-marker-name.csv", CSV).header("X-Correlation-Id", cid).post(UPLOAD).then().statusCode(200);
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
                assertThat(jdbc.sql("SELECT action || '|' || tenant_id || '|' || outcome || '|' || http_status FROM audit_log WHERE correlation_id = :c")
                        .param("c", cid).query(String.class).single()).isEqualTo("POST /api/inventory/import|TENANT-A|success|200"));
        assertThat(jdbc.sql("SELECT count(*) FROM audit_log WHERE concat_ws('|', actor, action, resource) LIKE '%secret-marker%'").query(Long.class).single()).isZero();
    }
}
