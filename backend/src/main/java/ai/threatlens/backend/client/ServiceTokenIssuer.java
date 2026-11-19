package ai.threatlens.backend.client;

import ai.threatlens.backend.config.AppProperties;
import ai.threatlens.backend.security.CurrentUser;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Component;

/** Mints the 60-second service JWT that authenticates this backend to the Python service (ADR 0004). */
@Component
public class ServiceTokenIssuer {

    public static final String ISSUER = "threatlens-backend";
    public static final String AUDIENCE = "threatlens-intelligence";
    public static final Duration LIFETIME = Duration.ofSeconds(60);

    private final JwtEncoder encoder;
    private final Clock clock;

    public ServiceTokenIssuer(AppProperties properties, Clock clock) {
        byte[] secret = properties.intelligence().jwtSecret().getBytes(StandardCharsets.UTF_8);
        this.encoder = new NimbusJwtEncoder(new ImmutableSecret<>(new SecretKeySpec(secret, "HmacSHA256")));
        this.clock = clock;
    }

    public String issue(CurrentUser user) {
        Instant now = clock.instant();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(ISSUER)
                .audience(List.of(AUDIENCE))
                .subject(user.subject())
                .issuedAt(now)
                .expiresAt(now.plus(LIFETIME))
                .id(UUID.randomUUID().toString())
                .claim("tenant_id", user.tenantId())
                .claim("roles", user.roles().stream().sorted().toList())
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
