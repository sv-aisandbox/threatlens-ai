package ai.threatlens.backend.support;

import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

/**
 * Stands in for the Python intelligence service. It records every request exactly as received so tests can
 * assert what the backend sent (service JWT, correlation id, parameters), and its affected-assets answer
 * is derived from the tenant inside the service JWT, which makes tenant leaks observable.
 */
public class StubIntelligence {

    public record Received(String method, String path, String query, Map<String, String> headers, String body) {
        public String bearer() {
            String auth = headers.get("authorization");
            return auth != null && auth.startsWith("Bearer ") ? auth.substring(7) : null;
        }
    }

    private static final String ANALYST_ANSWER = """
            {"answer":"ASSET-OF-%1$s is exposed.","outcome":"answered",
            "summary":{"confirmed_exposures":1,"possible":0,"unknown":0},
            "findings":{"confirmed":[{"asset_id":"ASSET-OF-%1$s","asset_name":"asset","environment":"production","criticality":"high",
            "internet_exposed":true,"cve_id":"CVE-2021-44228","software":{"vendor":"Apache","product":"Log4j","version":"2.14.1"},
            "match_status":"confirmed","reason":"within range","matched_at":"2026-11-19T12:00:00.000Z","evidence_ids":["EVID-NVD-CVE-2021-44228"]}],
            "possible":[],"unknown":[]},
            "evidence":[{"evidence_id":"EVID-NVD-CVE-2021-44228","source_name":"NVD","source_url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "collected_at":"2026-11-19T12:00:00.000Z","content_hash":"abc"}],
            "freshness":{"intelligence":{"nvd_last_success_at":"2026-11-19T10:00:00+00:00","kev_last_success_at":null},
            "inventory_last_imported_at":"2026-11-19T12:00:00+00:00"},
            "warnings":[],"grounding":{"ok":true,"ungrounded":[]},
            "trace":[{"step":1,"tool":"get_affected_assets","args":{"cve_id":"CVE-2021-44228"},"outcome":"ok","latency_ms":12,
            "injection_suspected":false,"tool_correlation_id":"abc","unexpected":1}],
            "usage":{"provider":"mock","model":"mock-analyst-1","steps":2,"tool_calls":1,"input_tokens":100,"output_tokens":20,
            "cache_read_tokens":0,"cache_write_tokens":0,"cost_usd":0.0,"latency_ms":50},
            "correlation_id":"%2$s"}
            """;

    private final HttpServer server;
    private final List<Received> requests = new CopyOnWriteArrayList<>();
    private volatile int forcedStatus = 0;
    private volatile String forcedBody = "";
    private volatile long delayMillis = 0;

    public StubIntelligence() {
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        server.createContext("/", this::handle);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public List<Received> requests() {
        return requests;
    }

    public void reset() {
        requests.clear();
        forcedStatus = 0;
        forcedBody = "";
        delayMillis = 0;
    }

    public void failWith(int status, String body) {
        this.forcedStatus = status;
        this.forcedBody = body;
    }

    public void delay(long millis) {
        this.delayMillis = millis;
    }

    private void handle(HttpExchange ex) throws IOException {
        Map<String, String> headers = new TreeMap<>();
        ex.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(), String.join(",", v)));
        String path = ex.getRequestURI().getPath();
        String requestBody = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        requests.add(new Received(ex.getRequestMethod(), path, ex.getRequestURI().getRawQuery(), headers, requestBody));
        try {
            if (delayMillis > 0) {
                Thread.sleep(delayMillis);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (forcedStatus != 0) {
            respond(ex, forcedStatus, forcedBody);
            return;
        }
        String tenant = tenantOf(headers.get("authorization"));
        String method = ex.getRequestMethod();
        if (method.equals("GET") && path.matches("/internal/v1/vulnerabilities/CVE-\\d{4}-\\d{4,}/affected-assets")) {
            String cve = path.split("/")[4];
            respond(ex, 200, """
                    {"cve_id":"%s","tenant_id":"%s","results":[{"asset_id":"ASSET-OF-%s","asset_name":"asset of %s",
                    "tenant_id":"%s","environment":"production","criticality":"high","internet_exposed":true,
                    "inventory_imported_at":"2026-11-19T12:00:00.000Z","software":{"software_id":"S1","vendor":"Apache",
                    "product":"Log4j","version":"2.14.1","cpe":"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
                    "cve_id":"%s","cvss_score":10.0,"severity":"critical","match_status":"confirmed",
                    "match_reason":"installed 2.14.1 is within >=2.13.0, <2.15.0 of apache:log4j","matched_by":"cpe-matcher/1",
                    "matched_at":"2026-11-19T12:00:00.000Z","source_ref":"EVID-NVD-%s","evidence":[],"unexpected_field":1}],
                    "freshness":{"intelligence":{"nvd_last_success_at":"2026-11-19T10:00:00+00:00","kev_last_success_at":null},
                    "inventory_last_imported_at":"2026-11-19T12:00:00+00:00"},"warnings":[]}
                    """.formatted(cve, tenant, tenant, tenant, tenant, cve, cve));
        } else if (method.equals("GET") && path.equals("/internal/v1/vulnerabilities/CVE-2021-44228")) {
            respond(ex, 200, """
                    {"cve_id":"CVE-2021-44228","description":"Apache Log4j2 JNDI features","cvss_score":10.0,"severity":"critical",
                    "cvss_version":"3.1","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "published_at":"2021-12-10T10:15:09.143Z","last_modified_at":"2026-08-11T19:33:44.513Z","vuln_status":"Analyzed",
                    "kev_listed":true,"kev_date_added":"2021-12-10","kev_due_date":"2021-12-24","kev_ransomware_use":"known",
                    "kev_name":"Apache Log4j2 RCE","synthetic":false,
                    "evidence":[{"evidence_id":"EVID-NVD-CVE-2021-44228","source_name":"NVD","source_url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228","collected_at":"2026-11-19T12:00:00.000Z"}]}
                    """);
        } else if (method.equals("GET") && path.startsWith("/internal/v1/vulnerabilities/CVE-")) {
            respond(ex, 404, "{\"detail\":\"not found\"}");
        } else if (method.equals("GET") && path.equals("/internal/v1/sources/status")) {
            respond(ex, 200, """
                    [{"source_id":"nvd","last_attempt_at":"2026-11-19T10:00:00+00:00","last_success_at":"2026-11-19T10:00:00+00:00",
                    "last_status":"success","records_received":910,"records_created":910,"records_updated":0,"records_rejected":0,
                    "error_summary":null,"source_modified_at":null,"sync_cursor_at":null}]
                    """);
        } else if (method.equals("POST") && path.equals("/internal/v1/analyst/ask")) {
            respond(ex, 200, ANALYST_ANSWER.formatted(tenant, headers.getOrDefault("x-correlation-id", "none")));
        } else if (method.equals("POST") && path.matches("/internal/v1/sources/(nvd|kev)/sync")) {
            respond(ex, 202, "{\"accepted\":true,\"source_id\":\"" + path.split("/")[4] + "\"}");
        } else {
            respond(ex, 404, "{\"detail\":\"not found\"}");
        }
    }

    private static String tenantOf(String authorization) {
        try {
            SignedJWT jwt = SignedJWT.parse(authorization.substring(7));
            return String.valueOf(jwt.getJWTClaimsSet().getClaim("tenant_id"));
        } catch (ParseException | RuntimeException e) {
            return "NO-TENANT";
        }
    }

    private static void respond(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            ex.getResponseBody().write(bytes);
        }
        ex.close();
    }
}
