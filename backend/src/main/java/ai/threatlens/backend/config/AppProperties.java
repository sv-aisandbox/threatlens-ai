package ai.threatlens.backend.config;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Typed configuration. The service JWT secret has no default: the application refuses to start without it. */
@ConfigurationProperties(prefix = "threatlens")
public record AppProperties(Security security, Intelligence intelligence, RateLimit rateLimit) {

    public static final int MIN_SECRET_BYTES = 32;

    public AppProperties {
        if (security == null || isBlank(security.issuer()) || isBlank(security.jwkSetUri()) || isBlank(security.audience())) {
            throw new IllegalStateException("threatlens.security.issuer, jwk-set-uri and audience must be set");
        }
        if (intelligence == null || isBlank(intelligence.baseUrl())) {
            throw new IllegalStateException("threatlens.intelligence.base-url must be set");
        }
        if (intelligence.jwtSecret() == null
                || intelligence.jwtSecret().getBytes(StandardCharsets.UTF_8).length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(
                    "INTERNAL_JWT_SECRET must be set and at least " + MIN_SECRET_BYTES + " bytes long");
        }
        if (rateLimit == null) {
            rateLimit = new RateLimit(120, 5, 10);
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    public record Security(String issuer, String jwkSetUri, String audience) {}

    public record Intelligence(
            String baseUrl, String jwtSecret, Duration connectTimeout, Duration readTimeout, Duration analystReadTimeout) {
        public Intelligence {
            connectTimeout = connectTimeout == null ? Duration.ofSeconds(2) : connectTimeout;
            readTimeout = readTimeout == null ? Duration.ofSeconds(15) : readTimeout;
            // An analyst answer involves a model call and several tool calls, so it gets a longer (still bounded) timeout.
            analystReadTimeout = analystReadTimeout == null ? Duration.ofSeconds(120) : analystReadTimeout;
        }

        /** Keep the secret out of logs and accidental toString() output. */
        @Override
        public String toString() {
            return "Intelligence[baseUrl=" + baseUrl + ", jwtSecret=***]";
        }
    }

    public record RateLimit(int requestsPerMinute, int syncPerMinute, int analystPerMinute) {}
}
