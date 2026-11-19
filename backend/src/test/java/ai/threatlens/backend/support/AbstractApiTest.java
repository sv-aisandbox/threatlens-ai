package ai.threatlens.backend.support;

import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static io.restassured.RestAssured.given;

/**
 * Real PostgreSQL (Testcontainers, same migrations as production), the real security chain over HTTP, and a stub
 * for the Python service. One Spring context is shared by the subclasses that do not change configuration.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import(TestSecurityConfig.class)
public abstract class AbstractApiTest {

    /**
     * One container for the whole JVM. Spring caches application contexts across test classes, so a
     * per-class container would leave cached contexts pointing at a stopped database. Testcontainers'
     * Ryuk sidecar removes it when the JVM exits.
     */
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.12");

    static {
        POSTGRES.start();
    }

    protected static final StubIntelligence STUB = new StubIntelligence();

    @DynamicPropertySource
    static void intelligence(DynamicPropertyRegistry registry) {
        registry.add("threatlens.intelligence.base-url", STUB::baseUrl);
    }

    @LocalServerPort
    protected int port;

    @Autowired
    protected JdbcClient jdbc;

    @BeforeEach
    void resetStub() {
        STUB.reset();
        RestAssured.port = port;
        RestAssured.baseURI = "http://127.0.0.1";
    }

    protected static RequestSpecification asUser(String token) {
        return given().header("Authorization", "Bearer " + token);
    }

    protected static String analyst(String tenant) {
        return TestTokens.user(tenant, "SECURITY_ANALYST").build();
    }

    protected static String viewer(String tenant) {
        return TestTokens.user(tenant, "VIEWER").build();
    }

    protected static String admin(String tenant) {
        return TestTokens.user(tenant, "ADMIN").build();
    }
}
