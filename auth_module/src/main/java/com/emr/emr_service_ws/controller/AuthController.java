package com.emr.emr_service_ws.controller;

import com.emr.emr_service_ws.dto.ApiResponse.ApiResponse;
import com.emr.emr_service_ws.dto.authDto.LoginRequest;
import com.emr.emr_service_ws.dto.authDto.SaveAuthTokenResponse;
import com.emr.emr_service_ws.dto.authDto.SignUpRequest;
import com.emr.emr_service_ws.dto.authDto.SignUpResponse;
import com.emr.emr_service_ws.dto.authDto.ValidateTokenResponse;
import com.emr.emr_service_ws.service.AuthService;
import com.emr.emr_service_ws.config.annotations.ApiBadRequestResponse;
import com.emr.emr_service_ws.config.annotations.ApiUnauthorizedResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "Endpoints for user registration, login, and token validation")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @Operation(summary = "Register a new user",
            description = "Creates a new user account with a BCrypt-hashed password and assigns the specified role.")
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "201", description = "User created successfully")
    @ApiBadRequestResponse
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<SignUpResponse>> signUp(
            @RequestBody SignUpRequest signUpRequest) {
        ApiResponse<SignUpResponse> response = authService.signUp(signUpRequest);
        if (response.isSuccess()) {
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @Operation(summary = "Login a user",
            description = "Authenticates credentials using BCrypt, revokes previous active tokens, generates and saves a new JWT token valid for 30 days.")
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Login successful")
    @ApiUnauthorizedResponse
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<SaveAuthTokenResponse>> login(
            @RequestBody LoginRequest loginRequest) {
        ApiResponse<SaveAuthTokenResponse> response = authService.login(loginRequest);
        if (response.isSuccess()) {
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @Operation(summary = "Validate an auth token",
            description = "Checks whether the provided token is valid, active, non-expired, and non-revoked. Returns the associated user details on success.")
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Token is valid")
    @ApiUnauthorizedResponse
    @PostMapping("/validate")
    public ResponseEntity<ApiResponse<ValidateTokenResponse>> validateToken(
            @RequestParam("token") String token) {
        ApiResponse<ValidateTokenResponse> response = authService.validateToken(token);
        if (response.isSuccess()) {
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @Operation(summary = "Logout",
            description = "Make the active token inactive and logout")
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Logout successful")
    @ApiUnauthorizedResponse
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(
            @RequestParam("token") String token) {
        ApiResponse<String> response = authService.logout(token);
        if (response.isSuccess()) {
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

}
