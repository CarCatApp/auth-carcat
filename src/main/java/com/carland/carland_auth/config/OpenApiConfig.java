package com.carland.carland_auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    private static final String BEARER_SCHEME = "bearerAuth";

    @Value("${carland.swagger.public-server-url:https://digital-innovation.agency/auth/server}")
    private String publicServerUrl;

    @Bean
    public OpenAPI carlandAuthOpenAPI() {
        String description = """
                **auth-service** — dual contract period.

                | Definition | Base | Notes |
                |---|---|---|
                | Legacy | `/api/v1/users`, `/api/v1/otp` | password + registerToken |
                | NewUsers | `/api/v1/newUsers` | authToken + pin_hash (argon2id) |

                NewUsers paths: `/auth`, `/otp/createAndSend`, `/otp/verify`, `/setPinCode`, `/login`.
                """;

        return new OpenAPI()
                .info(new Info()
                        .title("1. Auth — Login / Register / Tokens")
                        .description(description)
                        .version("v1")
                        .contact(new Contact().name("Carland Engineering")))
                .servers(List.of(new Server()
                        .url(publicServerUrl)
                        .description("Production via nginx (/auth/server → auth-service)")))
                .components(new Components()
                        .addSecuritySchemes(BEARER_SCHEME, new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("Access JWT from login.")))
                .addSecurityItem(new SecurityRequirement().addList(BEARER_SCHEME));
    }

    @Bean
    public GroupedOpenApi legacyUsersGroup() {
        return GroupedOpenApi.builder()
                .group("legacy-users")
                .displayName("1A. Auth — Legacy (/users)")
                .pathsToMatch("/api/v1/users/**", "/api/v1/otp/**")
                .addOpenApiCustomizer(openApi -> openApi.getInfo()
                        .title("1A. Auth — Legacy")
                        .description("Legacy Postman/Flutter contract. setPassword = free-form password (BCrypt → password column). PIN rules do NOT apply."))
                .build();
    }

    @Bean
    public GroupedOpenApi newUsersGroup() {
        return GroupedOpenApi.builder()
                .group("new-users")
                .displayName("1B. Auth — NewUsers")
                .pathsToMatch("/api/v1/newUsers/**")
                .addOpenApiCustomizer(openApi -> openApi.getInfo()
                        .title("1B. Auth — NewUsers")
                        .description("""
                                PO parallel flow under `/api/v1/newUsers`:
                                1. POST /auth → authToken + next (SEND_OTP | PIN_CHECK); purpose in JWT
                                2. POST /otp/createAndSend { authToken } → next VERIFY_OTP
                                3. POST /otp/verify { authToken, otp } → pinSetupToken + next SET_PIN
                                4. PUT /setPinCode { pinSetupToken, pinCode } → status PIN_SET
                                5. POST /login { phoneNumber, pinCode, deviceId }
                                """))
                .build();
    }

    @Bean
    public GroupedOpenApi staffGroup() {
        return GroupedOpenApi.builder()
                .group("staff")
                .displayName("1C. Auth — Staff")
                .pathsToMatch("/api/v1/staff/**", "/api/v1/internal/staff/**")
                .addOpenApiCustomizer(openApi -> openApi.getInfo()
                        .title("1C. Auth — Staff")
                        .description("""
                                Booking partner/branch admin:
                                - POST /api/v1/internal/staff/provision (X-Internal-Token)
                                - POST /api/v1/internal/staff/disable (X-Internal-Token)
                                - POST /api/v1/staff/login (phone or email + password)
                                - PUT /api/v1/staff/me/own-password (access JWT; replace invited password)
                                - POST /api/v1/staff/password/forgot { phoneNumber|email, channel: SMS|EMAIL }
                                - POST /api/v1/staff/password/verify-otp → resetToken
                                - POST /api/v1/staff/password/reset { resetToken, newPassword }
                                """))
                .build();
    }

    @Bean
    public OperationCustomizer headerDefaultsCustomizer() {
        return (operation, handlerMethod) -> {
            if (operation.getParameters() == null) {
                return operation;
            }
            operation.getParameters().removeIf(param ->
                    "header".equalsIgnoreCase(param.getIn())
                            && "Authorization".equalsIgnoreCase(param.getName()));

            for (Parameter param : operation.getParameters()) {
                if (!"header".equalsIgnoreCase(param.getIn()) || param.getName() == null) {
                    continue;
                }
                if ("Accept-Language".equalsIgnoreCase(param.getName())) {
                    param.setDescription("Client locale. Fixed to `az` in Swagger UI (read-only).");
                    param.setRequired(true);
                    param.setSchema(new StringSchema()
                            ._default("az")
                            .example("az")
                            .readOnly(true));
                }
            }
            return operation;
        };
    }
}
