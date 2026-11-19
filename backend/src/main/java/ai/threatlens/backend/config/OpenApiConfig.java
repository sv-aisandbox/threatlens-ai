package ai.threatlens.backend.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    OpenAPI threatLensOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("ThreatLens AI API")
                        .version("0.1.0")
                        .description("Authenticated, tenant-aware API. The tenant and role come from the access token "
                                + "(Keycloak) and can never be supplied by the caller. Errors are RFC 9457 problem details."))
                .components(new Components().addSecuritySchemes("bearerAuth",
                        new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }
}
