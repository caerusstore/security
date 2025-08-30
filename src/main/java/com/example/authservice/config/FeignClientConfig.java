package com.example.authservice.config;

import feign.RequestInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;

@Configuration
public class FeignClientConfig {

    private final OAuth2AuthorizedClientManager clientManager;

    public FeignClientConfig(OAuth2AuthorizedClientManager clientManager) {
        this.clientManager = clientManager;
    }

    @Bean
    public RequestInterceptor oauth2FeignRequestInterceptor() {
        return requestTemplate -> {
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("external-service")
                    .principal("external-user-auth-service")
                    .build();

            OAuth2AuthorizedClient client = clientManager.authorize(authorizeRequest);

            if (client != null && client.getAccessToken() != null) {
                requestTemplate.header("Authorization", "Bearer " + client.getAccessToken().getTokenValue());
            }
        };
    }
}
