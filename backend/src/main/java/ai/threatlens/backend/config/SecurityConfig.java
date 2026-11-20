package ai.threatlens.backend.config;

import ai.threatlens.backend.audit.AuditFilter;
import ai.threatlens.backend.audit.AuditRepository;
import ai.threatlens.backend.security.JwtSupport;
import ai.threatlens.backend.security.Problems;
import ai.threatlens.backend.security.RateLimitFilter;
import jakarta.servlet.DispatcherType;
import java.time.Clock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Stateless OAuth2 resource server. Everything under /api requires a valid token; any other path is denied.
 * Roles and tenant come from token claims only. Fine-grained role checks live in the service layer.
 */
@Configuration
@EnableConfigurationProperties(AppProperties.class)
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    /** Signature via the issuer's JWKS, plus expiry, issuer and audience checks. Replaced in tests. */
    @Bean
    @Profile("!test")
    JwtDecoder jwtDecoder(AppProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.security().jwkSetUri()).build();
        decoder.setJwtValidator(JwtSupport.validator(properties.security().issuer(), properties.security().audience()));
        return decoder;
    }

    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http, AppProperties properties, AuditRepository auditRepository, Clock clock)
            throws Exception {
        AuthenticationEntryPoint unauthorized = (request, response, ex) -> {
            response.setHeader("WWW-Authenticate", "Bearer");
            Problems.write(request, response, 401, "Unauthorized", "Authentication is required or the token is invalid.");
        };
        AccessDeniedHandler forbidden = (request, response, ex) ->
                Problems.write(request, response, 403, "Forbidden", "You do not have access to this resource.");

        http.csrf(AbstractHttpConfigurer::disable) // bearer-token API, no cookies or sessions
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // The container's own error dispatch (malformed/hostile paths) keeps its real status.
                        // Direct requests to /error are REQUEST dispatches and are still denied below.
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers("/v3/api-docs", "/v3/api-docs/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/actuator/metrics", "/actuator/metrics/**").hasRole("ADMIN")
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().denyAll())
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(JwtSupport.converter()))
                        .authenticationEntryPoint(unauthorized)
                        .accessDeniedHandler(forbidden))
                .exceptionHandling(e -> e.authenticationEntryPoint(unauthorized).accessDeniedHandler(forbidden))
                // Audit wraps bearer processing so authentication failures are recorded too;
                // rate limiting runs once the caller is known.
                .addFilterBefore(new AuditFilter(auditRepository), BearerTokenAuthenticationFilter.class)
                .addFilterAfter(new RateLimitFilter(properties.rateLimit(), clock), BearerTokenAuthenticationFilter.class);
        return http.build();
    }
}
