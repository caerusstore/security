package com.example.authservice.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "externalUserClient", url = "https://external-service.com/api", configuration = com.example.authservice.config.FeignClientConfig.class)
public interface ExternalUserClient {

    @GetMapping("/users/me")
    String getCurrentUser();
}
