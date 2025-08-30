package com.example.authservice.service;

import com.example.authservice.client.ExternalUserClient;
import com.example.authservice.model.AuthRequest;
import com.example.authservice.model.AuthResponse;
import com.example.authservice.model.UserInfo;
import com.example.authservice.util.JwtUtil;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final ExternalUserClient externalUserClient;
    private final JwtUtil jwtUtil;

    public AuthService(ExternalUserClient externalUserClient, JwtUtil jwtUtil) {
        this.externalUserClient = externalUserClient;
        this.jwtUtil = jwtUtil;
    }

    public AuthResponse login(AuthRequest request) {
        UserInfo userInfo = externalUserClient.validateUser(request);
        if (userInfo != null && userInfo.getUsername() != null) {
            String token = jwtUtil.generateToken(userInfo.getUsername(), userInfo.getRoles());
            return new AuthResponse(token, "Login successful");
        }
        throw new RuntimeException("Invalid credentials");
    }
}
