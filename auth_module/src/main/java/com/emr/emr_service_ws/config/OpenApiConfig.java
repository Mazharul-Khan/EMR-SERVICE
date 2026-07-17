package com.emr.emr_service_ws.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI emrOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("EMR Auth Service API")
                        .description("Authentication and Authorization Service for the Electronic Medical Records (EMR) system. " +
                                "Provides endpoints for user registration, login, and token validation.")
                        .version("v1.0.0"))
                .servers(List.of(
                        new Server().url("http://localhost:8080").description("Local Development Server")
                ));
    }
}
