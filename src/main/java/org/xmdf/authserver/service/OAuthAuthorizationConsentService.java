package org.xmdf.authserver.service;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.xmdf.authserver.domain.OAuthAuthorizationConsent;
import org.xmdf.authserver.repository.OAuthAuthorizationConsentRepository;

import java.util.stream.Collectors;

public class OAuthAuthorizationConsentService implements OAuth2AuthorizationConsentService {
    private final OAuthAuthorizationConsentRepository authorizationConsentRepository;
    private final RegisteredClientRepository oAuthClientService;

    public OAuthAuthorizationConsentService(OAuthAuthorizationConsentRepository authorizationConsentRepository, RegisteredClientRepository oAuthClientService) {
        Assert.notNull(authorizationConsentRepository, "authorizationConsentRepository cannot be null");
        Assert.notNull(oAuthClientService, "registeredClientRepository cannot be null");
        this.authorizationConsentRepository = authorizationConsentRepository;
        this.oAuthClientService = oAuthClientService;
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authorizationConsentRepository.save(toEntity(authorizationConsent));
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
                authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        return this.authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(
                registeredClientId, principalName).map(this::toObject).orElse(null);
    }

    private OAuth2AuthorizationConsent toObject(OAuthAuthorizationConsent authorizationConsent) {
        var registeredClientId = authorizationConsent.getRegisteredClientId();
        var registeredClient = this.oAuthClientService.findById(registeredClientId);

        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '%s' was not found in the RegisteredClientRepository."
                            .formatted(registeredClientId));
        }

        var builder = OAuth2AuthorizationConsent.withId(
                registeredClientId, authorizationConsent.getPrincipalName());

        if (authorizationConsent.getAuthorities() != null) {
            for (var authority : StringUtils.commaDelimitedListToSet(authorizationConsent.getAuthorities())) {
                builder.authority(new SimpleGrantedAuthority(authority));
            }
        }

        return builder.build();
    }

    private OAuthAuthorizationConsent toEntity(OAuth2AuthorizationConsent authorizationConsent) {
        var authorities = authorizationConsent.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        return OAuthAuthorizationConsent.builder()
                .registeredClientId(authorizationConsent.getRegisteredClientId())
                .principalName(authorizationConsent.getPrincipalName())
                .authorities(StringUtils.collectionToCommaDelimitedString(authorities))
                .build();
    }
}
