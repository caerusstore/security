package com.example.authservice.client;

import com.example.authservice.model.AuthRequest;
import com.example.authservice.model.UserInfo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "mock-user-service", url = "${user-service.url}")
public interface ExternalUserClient {
    @PostMapping("/users/validate")
    UserInfo validateUser(@RequestBody AuthRequest request);
}
