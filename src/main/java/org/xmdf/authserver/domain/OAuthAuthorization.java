package org.xmdf.authserver.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.time.Instant;

import static lombok.EqualsAndHashCode.Include;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Entity
@Table(name = "oauth2_authorization")
public class OAuthAuthorization {

    @Id
    @Column
    @Include
    private String id;
    private String registeredClientId;
    @Column(length = 200)
    private String principalName;
    @Column(length = 100)
    private String authorizationGrantType;
    @Column(length = 1000)
    private String authorizedScopes;
    @Column
    private String attributes;
    @Column(length = 500)
    private String state;
    private String authorizationCodeValue;
    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;
    private String authorizationCodeMetadata;
    private String accessTokenValue;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;
    private String accessTokenMetadata;
    @Column(length = 100)
    private String accessTokenType;
    @Column(length = 1000)
    private String accessTokenScopes;
    private String oidcIdTokenValue;
    private Instant oidcIdTokenIssuedAt;
    private Instant oidcIdTokenExpiresAt;
    private String oidcIdTokenMetadata;
    private String oidcIdTokenClaims;
    private String refreshTokenValue;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;
    private String refreshTokenMetadata;
    private String userCodeValue;
    private Instant userCodeIssuedAt;
    private Instant userCodeExpiresAt;
    private String userCodeMetadata;
    private String deviceCodeValue;
    private Instant deviceCodeIssuedAt;
    private Instant deviceCodeExpiresAt;
    private String deviceCodeMetadata;
}
