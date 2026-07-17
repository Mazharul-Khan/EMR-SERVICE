package com.emr.emr_service_ws.service;

import com.emr.emr_service_ws.dto.ApiResponse.ApiResponse;
import com.emr.emr_service_ws.dto.authDto.*;

public interface AuthService {

    ApiResponse<SignUpResponse> signUp(SignUpRequest signUpRequest);

    ApiResponse<SaveAuthTokenResponse> login(LoginRequest loginRequest);

    ApiResponse<ValidateTokenResponse> validateToken(String token);
    ApiResponse<String> logout(String token);
}
