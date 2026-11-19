package ai.threatlens.backend.support;

import ai.threatlens.backend.security.JwtSupport;
import com.nimbusds.jose.JOSEException;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/** Validates test tokens against the test public key using the same validators as production. */
@TestConfiguration
@Profile("test")
public class TestSecurityConfig {

    @Bean
    JwtDecoder jwtDecoder() throws JOSEException {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(TestTokens.KEY.toRSAPublicKey()).build();
        decoder.setJwtValidator(JwtSupport.validator(TestTokens.ISSUER, TestTokens.AUDIENCE));
        return decoder;
    }
}
