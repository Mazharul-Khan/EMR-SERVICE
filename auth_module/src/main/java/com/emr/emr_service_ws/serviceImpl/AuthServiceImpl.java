package com.emr.emr_service_ws.serviceImpl;

import com.emr.emr_service_ws.dto.ApiResponse.ApiResponse;
import com.emr.emr_service_ws.dto.authDto.*;
import com.emr.emr_service_ws.entity.AuthToken;
import com.emr.emr_service_ws.entity.Role;
import com.emr.emr_service_ws.entity.User;
import com.emr.emr_service_ws.repository.AuthTokenRepository;
import com.emr.emr_service_ws.repository.RoleRepository;
import com.emr.emr_service_ws.repository.UserRepository;
import com.emr.emr_service_ws.service.AuthService;
import com.emr.emr_service_ws.utils.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthTokenRepository authTokenRepository;
    private final JwtUtils jwtUtils;

    public AuthServiceImpl(UserRepository userRepository,
                           RoleRepository roleRepository,
                           AuthTokenRepository authTokenRepository,
                           JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.authTokenRepository = authTokenRepository;
        this.jwtUtils = jwtUtils;
    }

    @Override
    public ApiResponse<SignUpResponse> signUp(SignUpRequest signUpRequest) {
        if (signUpRequest == null) {
            return new ApiResponse<>(false, "Sign up request can not be null", null);
        }

        String username = signUpRequest.getUsername();
        String email = signUpRequest.getEmail();
        String password = signUpRequest.getPassword();
        String roleName = signUpRequest.getRole();

        if (username == null || username.trim().isEmpty()) {
            return new ApiResponse<>(false, "Username is required", null);
        }
        if (email == null || email.trim().isEmpty()) {
            return new ApiResponse<>(false, "Email is required", null);
        }
        if (password == null || password.trim().isEmpty()) {
            return new ApiResponse<>(false, "Password is required", null);
        }
        if (roleName == null || roleName.trim().isEmpty()) {
            return new ApiResponse<>(false, "Role is required", null);
        }

        try {
            Optional<Role> roleOpt = roleRepository.findByRoleName(roleName.trim());
            if (roleOpt.isEmpty()) {
                return new ApiResponse<>(false, "Role \"" + roleName + "\" does not exist.", null);
            }

            if (userRepository.existsByUserName(username.trim())) {
                return new ApiResponse<>(false, "Username already exists", null);
            }

            if (userRepository.existsByEmail(email.trim())) {
                return new ApiResponse<>(false, "Email already exists", null);
            }

            String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(10));

            User user = new User();
            user.setUserName(username.trim());
            user.setEmail(email.trim());
            user.setPasswordHash(passwordHash);
            user.setIsActive(true);
            user.getRoles().add(roleOpt.get());

            User savedUser = userRepository.save(user);

            SignUpResponse response = new SignUpResponse();
            response.setUserId(savedUser.getUserId());
            response.setUserName(savedUser.getUserName());
            response.setEmail(savedUser.getEmail());
            response.setActive(savedUser.getIsActive());
            response.setRoleName(roleOpt.get().getRoleName());

            return new ApiResponse<>(true, "User created successfully", response);

        } catch (Exception e) {
            logger.error("Error during user sign up", e);
            return new ApiResponse<>(false, "User creation failed: " + e.getMessage(), null);
        }
    }

    @Override
    public ApiResponse<SaveAuthTokenResponse> login(LoginRequest loginRequest) {
        if (loginRequest == null) {
            return new ApiResponse<>(false, "Login data can not be null", null);
        }

        String username = loginRequest.getUserName();
        String password = loginRequest.getPassword();

        if (username == null || username.trim().isEmpty()) {
            return new ApiResponse<>(false, "Username is required", null);
        }
        if (password == null || password.trim().isEmpty()) {
            return new ApiResponse<>(false, "Password is required", null);
        }

        try {
            Optional<User> userOpt = userRepository.findByUserName(username.trim());
            if (userOpt.isEmpty()) {
                return new ApiResponse<>(false, "Invalid username", null);
            }

            User user = userOpt.get();
            if (!user.getIsActive()) {
                return new ApiResponse<>(false, "User account is inactive", null);
            }

            if (!BCrypt.checkpw(password, user.getPasswordHash())) {
                return new ApiResponse<>(false, "Invalid password", null);
            }

            // Revoke older active tokens
            authTokenRepository.revokeActiveTokens(user.getUserId(), LocalDateTime.now());

            // Generate JWT Token
            String tokenValue = jwtUtils.generateToken(user.getUserName() + UUID.randomUUID().toString());

            // Save new active AuthToken
            AuthToken authToken = new AuthToken();
            authToken.setUser(user);
            authToken.setToken(tokenValue);
            authToken.setExpiresAt(LocalDateTime.now().plusDays(30));
            authToken.setIsActive(true);

            AuthToken savedToken = authTokenRepository.save(authToken);

            SaveAuthTokenResponse response = new SaveAuthTokenResponse();
            response.setTokenId(savedToken.getTokenId());
            response.setUserId(user.getUserId());
            response.setToken(savedToken.getToken());
            response.setExpiresAt(java.sql.Timestamp.valueOf(savedToken.getExpiresAt()));
            response.setActive(savedToken.getIsActive());

            return new ApiResponse<>(true, "Log in successfull", response);

        } catch (Exception e) {
            logger.error("Error during user login", e);
            return new ApiResponse<>(false, "Login Failed: " + e.getMessage(), null);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<ValidateTokenResponse> validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return new ApiResponse<>(false, "Token is required", null);
        }

        try {
            Optional<AuthToken> tokenOpt = authTokenRepository.findByToken(token.trim());
            if (tokenOpt.isEmpty()) {
                return new ApiResponse<>(false, "Invalid token", null);
            }

            AuthToken authToken = tokenOpt.get();

            if (authToken.getRevokedAt() != null) {
                return new ApiResponse<>(false, "Token has been revoked", null);
            }

            if (!authToken.getIsActive()) {
                return new ApiResponse<>(false, "Token is inactive", null);
            }

            if (authToken.getExpiresAt().isBefore(LocalDateTime.now())) {
                return new ApiResponse<>(false, "Token has expired", null);
            }

            User user = authToken.getUser();
            if (user == null || !user.getIsActive()) {
                return new ApiResponse<>(false, "User account is inactive", null);
            }

            ValidateTokenResponse response = new ValidateTokenResponse();
            response.setUserId(user.getUserId());
            response.setUserName(user.getUserName());
            response.setEmail(user.getEmail());
            response.setActive(user.getIsActive());
            
            // Map first role or empty
            String roleName = user.getRoles().isEmpty() ? "" : user.getRoles().iterator().next().getRoleName();
            response.setRoleName(roleName);
            response.setTokenExpiresAt(authToken.getExpiresAt());

            return new ApiResponse<>(true, "Token validated successfully", response);

        } catch (Exception e) {
            logger.error("Error during token validation", e);
            return new ApiResponse<>(false, "Token validation failed: " + e.getMessage(), null);
        }
    }

    @Override
    public ApiResponse<String> logout(String token){
        if(token==null || token.isEmpty()){
            return new ApiResponse<>(false,"token can not be empty",null);
        }

        try{
            Optional<AuthToken> tokenOpt = authTokenRepository.findByToken(token);
            if (tokenOpt.isEmpty()) {
                return new ApiResponse<>(false, "Invalid token", null);
            }

            AuthToken authToken = tokenOpt.get();
            if(authToken.getIsActive()!= true){
                return new ApiResponse<>(false, "Token already Invalidated", null);
            }
            if(authToken.getRevokedAt()!=null){
                return new ApiResponse<>(false, "Token already Revoked", null);
            }
            if (authToken.getExpiresAt().isBefore(LocalDateTime.now())) {
                return new ApiResponse<>(false, "Token has expired", null);
            }

            UUID userId = authToken.getUser().getUserId();
            authTokenRepository.revokeActiveTokens(userId,LocalDateTime.now());

            return new ApiResponse<>(true,"Logout successful",null);

        } catch (Exception e) {
            return new ApiResponse<>(false,"Logout Failed",e.getMessage());
        }
    }
}
