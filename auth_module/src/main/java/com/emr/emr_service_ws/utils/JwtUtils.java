package com.emr.emr_service_ws.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.stereotype.Component;
import java.util.Date;

@Component
public class JwtUtils {

    // Define a secret key string (must be secure/long in production)
    private final String SECRET_KEY = "your_super_secret_and_very_long_key_here_for_security";

    public String generateToken(String username) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);

        // Minimal token with no expiration stamp in the payload
        return JWT.create()
                .withSubject(username)
                .sign(algorithm);
    }
}