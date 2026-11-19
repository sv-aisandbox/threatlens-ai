package ai.threatlens.backend.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Builds access tokens shaped like the ones Keycloak issues, signed with a throwaway RSA key. */
public final class TestTokens {

    public static final String ISSUER = "https://issuer.test.invalid/realms/threatlens";
    public static final String AUDIENCE = "threatlens-api";

    public static final RSAKey KEY = generate("test-key");
    public static final RSAKey OTHER_KEY = generate("other-key");

    private TestTokens() {}

    private static RSAKey generate(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Builder user(String tenant, String... roles) {
        return new Builder().tenant(tenant).roles(roles);
    }

    public static final class Builder {
        private String issuer = ISSUER;
        private String audience = AUDIENCE;
        private String subject = "user-" + UUID.randomUUID();
        private String tenant;
        private List<String> roles = List.of();
        private boolean realmAccess = true;
        private Instant expiresAt = Instant.now().plusSeconds(300);
        private RSAKey signer = KEY;
        private JWSAlgorithm algorithm = JWSAlgorithm.RS256;

        public Builder tenant(String v) { this.tenant = v; return this; }
        public Builder roles(String... v) { this.roles = List.of(v); return this; }
        public Builder subject(String v) { this.subject = v; return this; }
        public Builder issuer(String v) { this.issuer = v; return this; }
        public Builder audience(String v) { this.audience = v; return this; }
        public Builder expiresAt(Instant v) { this.expiresAt = v; return this; }
        public Builder signedWith(RSAKey v) { this.signer = v; return this; }
        public Builder withoutRealmAccess() { this.realmAccess = false; return this; }

        public String build() {
            try {
                JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                        .issuer(issuer)
                        .subject(subject)
                        .jwtID(UUID.randomUUID().toString())
                        .issueTime(Date.from(Instant.now().minusSeconds(5)))
                        .expirationTime(Date.from(expiresAt));
                if (audience != null) {
                    claims.audience(audience);
                }
                if (tenant != null) {
                    claims.claim("tenant_id", tenant);
                }
                if (realmAccess && !roles.isEmpty()) {
                    claims.claim("realm_access", Map.of("roles", roles));
                }
                SignedJWT jwt = new SignedJWT(
                        new JWSHeader.Builder(algorithm).keyID(signer.getKeyID()).build(), claims.build());
                jwt.sign(new RSASSASigner(signer));
                return jwt.serialize();
            } catch (JOSEException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
