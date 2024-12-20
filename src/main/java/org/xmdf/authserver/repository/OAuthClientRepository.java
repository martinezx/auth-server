package org.xmdf.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.xmdf.authserver.domain.OAuthClient;

import java.util.Optional;

@Repository
public interface OAuthClientRepository extends JpaRepository<OAuthClient, String> {

    Optional<OAuthClient> findByClientId(String clientId);
}