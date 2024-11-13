package org.xmdf.authserver.domain;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;

import static lombok.EqualsAndHashCode.Include;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Entity
@Table(name = "oauth2_authorization_consent")
@IdClass(OAuthAuthorizationConsent.AuthorizationConsentId.class)
public class OAuthAuthorizationConsent {

    @Id
    @Include
    private String registeredClientId;

    @Id
    @Include
    @Column(length = 200)
    private String principalName;

    @Column(length = 1000)
    private String authorities;

    @EqualsAndHashCode
    public static class AuthorizationConsentId implements Serializable {

        private String registeredClientId;
        private String principalName;
    }
}
