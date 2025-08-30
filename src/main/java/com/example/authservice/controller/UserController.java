package com.example.authservice.controller;

import com.example.authservice.client.ExternalUserClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final ExternalUserClient externalUserClient;

    public UserController(ExternalUserClient externalUserClient) {
        this.externalUserClient = externalUserClient;
    }

    @GetMapping("/me")
    public String getCurrentUser() {
        return externalUserClient.getCurrentUser();
    }
}
