package com.emr.emr_service_ws.config.annotations;

import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.media.Content;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Custom annotation to document a 401 Unauthorized API response.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@ApiResponse(
        responseCode = "401",
        description = "Unauthorized (e.g. invalid username, password, or invalid/expired/revoked token)",
        content = @Content(mediaType = "application/json")
)
public @interface ApiUnauthorizedResponse {
}
