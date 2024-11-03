INSERT INTO public.oauth2_registered_client (
    id, client_id, client_id_issued_at, client_secret, client_secret_expires_at, client_name,
    client_authentication_methods, authorization_grant_types, redirect_uris, post_logout_redirect_uris, scopes,
    client_settings, token_settings
)
VALUES (
    '1bb27ddb-5d3a-4492-bf2e-d37a71fa0f9e', 'oidc-client', CURRENT_TIMESTAMP, '$2a$10$0HP.FlC2DUveTIWB3qTPo.hw.dbiRL694BxTruwCYSQG0x6rrNN5S', null,
    '1bb27ddb-5d3a-4492-bf2e-d37a71fa0f9e', 'client_secret_basic', 'refresh_token,authorization_code',
    'https://oauthdebugger.com/debug', 'http://127.0.0.1:9000/', 'openid,profile',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.x509-certificate-bound-access-tokens":false,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]}'
);