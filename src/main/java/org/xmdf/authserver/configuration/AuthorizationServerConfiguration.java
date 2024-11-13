package org.xmdf.authserver.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.xmdf.authserver.jose.Jwks;
import org.xmdf.authserver.repository.OAuthAuthorizationConsentRepository;
import org.xmdf.authserver.repository.OAuthAuthorizationRepository;
import org.xmdf.authserver.repository.OAuthClientRepository;
import org.xmdf.authserver.service.OAuthAuthorizationConsentService;
import org.xmdf.authserver.service.OAuthAuthorizationService;
import org.xmdf.authserver.service.OAuthClientService;

import java.time.Instant;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfiguration {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(oidc -> oidc.clientRegistrationEndpoint(Customizer.withDefaults()));
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    public ApplicationRunner initializeClients(
            RegisteredClientRepository registeredClientRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.oauth2.client.registrar-client.id}") String registrarClientId,
            @Value("${app.oauth2.client.registrar-client.secret}") String registrarClientSecret,
            @Value("${app.oauth2.client.oidc-client.id}") String oidcClientId,
            @Value("${app.oauth2.client.oidc-client.secret}") String oidcClientSecret) {

        return (args) -> {
            if (registeredClientRepository.findByClientId(registrarClientId) == null) {
                registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(registrarClientId)
                        .clientSecret(passwordEncoder.encode(registrarClientSecret))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .scope("client.create")
                        .scope("client.read")
                        .clientIdIssuedAt(Instant.now())
                        .build());
            }
            if (registeredClientRepository.findByClientId(oidcClientId) == null) {
                registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(oidcClientId)
                        .clientSecret(passwordEncoder.encode(oidcClientSecret))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .scope("client.create")
                        .scope("client.read")
                        .clientIdIssuedAt(Instant.now())
                        .build());
            }
        };
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(OAuthClientRepository clientRepository) {
        return new OAuthClientService(clientRepository);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            OAuthAuthorizationRepository authorizationRepository,
            RegisteredClientRepository registeredClientRepository) {
        return new OAuthAuthorizationService(authorizationRepository, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            OAuthAuthorizationConsentRepository authorizationConsentRepository,
            RegisteredClientRepository registeredClientRepository) {
        return new OAuthAuthorizationConsentService(authorizationConsentRepository, registeredClientRepository);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
