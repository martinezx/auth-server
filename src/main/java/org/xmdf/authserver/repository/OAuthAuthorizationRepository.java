package org.xmdf.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.xmdf.authserver.domain.OAuthAuthorization;

import java.util.Optional;

public interface OAuthAuthorizationRepository extends JpaRepository<OAuthAuthorization, String> {

    Optional<OAuthAuthorization> findByState(String state);

    Optional<OAuthAuthorization> findByAuthorizationCodeValue(String authorizationCode);

    Optional<OAuthAuthorization> findByAccessTokenValue(String accessToken);

    Optional<OAuthAuthorization> findByRefreshTokenValue(String refreshToken);

    Optional<OAuthAuthorization> findByOidcIdTokenValue(String idToken);

    Optional<OAuthAuthorization> findByUserCodeValue(String userCode);

    Optional<OAuthAuthorization> findByDeviceCodeValue(String deviceCode);

    @Query("select a from OAuthAuthorization a where a.state = :token" +
            " or a.authorizationCodeValue = :token" +
            " or a.accessTokenValue = :token" +
            " or a.refreshTokenValue = :token" +
            " or a.oidcIdTokenValue = :token" +
            " or a.userCodeValue = :token" +
            " or a.deviceCodeValue = :token"
    )
    Optional<OAuthAuthorization> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(@Param("token") String token);
}
