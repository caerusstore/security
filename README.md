# security
security service

Got it—here’s a clean, independent security service pattern using Spring Boot 3 / Spring Security 6 and Spring Cloud (Gateway) that authenticates via an external UserService and issues JWTs your other services can trust. This keeps auth/authz centralized and lets all downstream services remain stateless resource servers.

High-level architecture

security-service (this component)

Accepts username/password (or API credentials) and calls External UserService to verify user + fetch roles/permissions.

Issues signed JWT (RS256) with user id, roles, and fine-grained permissions.

Publishes its JWKS at /oauth2/jwks so others can validate tokens without calling back.

(Optional) Exposes /introspect for opaque-token scenarios.

api-gateway (Spring Cloud Gateway)

Validates incoming JWT (public key/JWK from security-service).

Performs coarse-grained route authorization.

Relays token to downstream services (Token Relay).

business microservices

Configure as Resource Servers (JWT).

Use method/endpoint security (@PreAuthorize, AuthorizationManager) with roles/permissions from JWT.

external-user-service

Your existing system of record for users, passwords, roles, and permissions.

Exposed via REST; security-service calls it.

security-service (Spring Security 6) — core implementation
Maven (key deps)
<dependencies>
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
  </dependency>
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
  </dependency>
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
  </dependency>
  <dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
  </dependency>
</dependencies>

application.yaml (keys + external user service)
server:
  port: 8081

external-user-service:
  base-url: https://external-user-service.internal
  auth-endpoint: /api/auth/check-credentials
  roles-endpoint: /api/users/{userId}/roles
  permissions-endpoint: /api/users/{userId}/permissions
  # Optionally, a service token if the external service requires it:
  service-token: BEARER xyz

jwt:
  issuer: https://security-service.mycorp
  ttl-minutes: 60
  key-id: key-1
  # You will load keys from a keystore or PEMs:
  private-key-pem: |
    -----BEGIN PRIVATE KEY-----
    ...your PKCS8 key...
    -----END PRIVATE KEY-----
  public-key-pem: |
    -----BEGIN PUBLIC KEY-----
    ...matching public key...
    -----END PUBLIC KEY-----

External client (calls UserService)
// package com.example.security.external;
@Component
public class ExternalUserClient {
    private final WebClient webClient;

    public record AuthRequest(String username, String password) {}
    public record AuthResult(boolean valid, String userId) {}
    public record RoleResponse(List<String> roles) {}
    public record PermissionResponse(List<String> permissions) {}

    public ExternalUserClient(@Value("${external-user-service.base-url}") String baseUrl,
                              @Value("${external-user-service.service-token}") String serviceToken) {
        this.webClient = WebClient.builder()
            .baseUrl(baseUrl)
            .defaultHeader(HttpHeaders.AUTHORIZATION, serviceToken)
            .build();
    }

    public Optional<String> validateCredentials(String username, String password) {
        AuthResult res = webClient.post()
            .uri("/api/auth/check-credentials")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(new AuthRequest(username, password))
            .retrieve()
            .bodyToMono(AuthResult.class)
            .block();
        return (res != null && res.valid()) ? Optional.of(res.userId()) : Optional.empty();
    }

    public List<String> fetchRoles(String userId) {
        return webClient.get()
            .uri(uriBuilder -> uriBuilder.path("/api/users/{id}/roles").build(userId))
            .retrieve()
            .bodyToMono(RoleResponse.class)
            .map(RoleResponse::roles)
            .defaultIfEmpty(List.of())
            .block();
    }

    public List<String> fetchPermissions(String userId) {
        return webClient.get()
            .uri(uriBuilder -> uriBuilder.path("/api/users/{id}/permissions").build(userId))
            .retrieve()
            .bodyToMono(PermissionResponse.class)
            .map(PermissionResponse::permissions)
            .defaultIfEmpty(List.of())
            .block();
    }
}

JWT service (sign + expose JWKS)
// package com.example.security.jwt;
@Component
public class JwtService {

    private final RSAKey rsaKey;
    private final JWSHeader jwsHeader;
    private final String issuer;
    private final Duration ttl;

    public JwtService(@Value("${jwt.private-key-pem}") String privatePem,
                      @Value("${jwt.public-key-pem}") String publicPem,
                      @Value("${jwt.key-id}") String kid,
                      @Value("${jwt.issuer}") String issuer,
                      @Value("${jwt.ttl-minutes}") long ttlMinutes) throws Exception {
        this.issuer = issuer;
        this.ttl = Duration.ofMinutes(ttlMinutes);

        RSAKey pub = (RSAKey) RSAKey.parseFromPEMEncodedObjects(publicPem);
        RSAKey priv = (RSAKey) RSAKey.parseFromPEMEncodedObjects(privatePem);
        this.rsaKey = new RSAKey.Builder(pub.toRSAPublicKey()).privateKey(priv.toRSAPrivateKey()).keyID(kid).build();
        this.jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).type(JOSEObjectType.JWT).build();
    }

    public String createToken(String userId, String username, List<String> roles, List<String> permissions) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(ttl)))
                .subject(userId)
                .claim("username", username)
                .claim("roles", roles)
                .claim("perms", permissions)
                .build();

        SignedJWT jwt = new SignedJWT(jwsHeader, claims);
        try {
            JWSSigner signer = new RSASSASigner(rsaKey.toPrivateKey());
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign JWT", e);
        }
    }

    // JWKS endpoint data
    public String jwks() {
        JWK jwkPublic = rsaKey.toPublicJWK();
        JWKSet set = new JWKSet(jwkPublic);
        return set.toJSONObject().toJSONString();
    }
}

Auth controller (login + jwks)
// package com.example.security.api;
@RestController
@RequestMapping("/auth")
public class AuthController {
    private final ExternalUserClient userClient;
    private final JwtService jwtService;

    public record LoginRequest(String username, String password) {}
    public record LoginResponse(String accessToken, String tokenType, long expiresIn) {}

    public AuthController(ExternalUserClient userClient, JwtService jwtService) {
        this.userClient = userClient;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        Optional<String> userIdOpt = userClient.validateCredentials(req.username(), req.password());
        if (userIdOpt.isEmpty()) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

        String userId = userIdOpt.get();
        List<String> roles = userClient.fetchRoles(userId);
        List<String> perms = userClient.fetchPermissions(userId);
        String token = jwtService.createToken(userId, req.username(), roles, perms);
        return ResponseEntity.ok(new LoginResponse(token, "Bearer", 3600));
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public String jwks() { return jwtService.jwks(); }
}

Security configuration (permit login/jwks; secure the rest)
// package com.example.security.config;
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/login", "/auth/.well-known/jwks.json", "/auth/health").permitAll()
                .anyRequest().authenticated()
            )
            // If you also protect admin endpoints of security-service itself using JWT:
            .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
            .build();
    }

    @Bean
    JwtDecoder jwtDecoder(@Value("${jwt.public-key-pem}") String publicPem) throws Exception {
        RSAKey pub = (RSAKey) RSAKey.parseFromPEMEncodedObjects(publicPem);
        RSAPublicKey key = pub.toRSAPublicKey();
        return NimbusJwtDecoder.withPublicKey(key).build();
    }
}

Spring Cloud Gateway (token validation + route auth)
Maven
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-gateway</artifactId>
</dependency>
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>

application.yaml
spring:
  cloud:
    gateway:
      routes:
        - id: orders
          uri: http://orders:8080
          predicates:
            - Path=/orders/**
          filters:
            - RemoveRequestHeader=Cookie
        - id: users
          uri: http://users:8080
          predicates:
            - Path=/users/**
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://security-service:8081/auth/.well-known/jwks.json

# Example coarse-grained auth via Spring Security config (below)

Security config in gateway
@Configuration
@EnableMethodSecurity
public class GatewaySecurityConfig {

    @Bean
    SecurityFilterChain gatewayChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(a -> a
                .requestMatchers(HttpMethod.POST, "/auth/**").permitAll()
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/orders/**").hasAnyAuthority("ROLE_ADMIN","ROLE_ORDER_VIEW")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
            .build();
    }
}

Resource microservice (JWT validation + fine-grained checks)
Maven
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>

application.yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://security-service:8081/auth/.well-known/jwks.json

Security config + method security
@Configuration
@EnableMethodSecurity
public class ResourceSecurityConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(a -> a
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter())))
            .build();
    }

    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthConverter() {
        return jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null) roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));
            List<String> perms = jwt.getClaimAsStringList("perms");
            if (perms != null) perms.forEach(p -> authorities.add(new SimpleGrantedAuthority(p)));
            return new JwtAuthenticationToken(jwt, authorities);
        };
    }
}

Usage in code
@PreAuthorize("hasAuthority('ORDER_READ') or hasRole('ADMIN')")
@GetMapping("/orders/{id}")
public Order get(@PathVariable String id) { ... }

External UserService contract (example)

POST /api/auth/check-credentials → { valid: true/false, userId: "u123" }

GET /api/users/{id}/roles → { roles: ["ADMIN","ANALYST"] }

GET /api/users/{id}/permissions → { permissions: ["ORDER_READ","ORDER_WRITE"] }

You can adapt to your existing endpoints. If the external service returns password hashes, swap to validate locally using PasswordEncoder.matches().

Hardening & production checklists

Rotate signing keys; support multiple keys (kid) in JWKS.

Clock skew handling (JwtDecoder setters).

Add refresh tokens:

Implement /auth/refresh that validates a long-lived refresh token (signed or stored) and issues a new access token.

Brute-force/throttling on /auth/login (Bucket4j or Spring rate limiter).

Audit logging (login success/failure, token issuance).

Map external permissions → API scopes consistently.

Multi-tenancy: add tenantId claim and enforce at gateway/microservices.

CSRF: remain disabled for pure token APIs; keep enabled for browser flows with sessions if you add UI.

CORS: configure allowed origins at gateway (if used by SPAs).

Quick test (happy path)

Login

POST http://security-service:8081/auth/login
{ "username": "alice", "password": "secret" }


→ accessToken (JWT)

Call through Gateway

GET http://gateway:8080/orders/123
Authorization: Bearer <accessToken>
