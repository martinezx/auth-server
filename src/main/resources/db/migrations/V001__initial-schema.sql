CREATE TABLE _user (
   id       uuid            PRIMARY KEY,
   username varchar(100)    NOT NULL UNIQUE,
   password varchar(100)    NOT NULL,
   enabled  boolean
);

CREATE TABLE _role (
   id   uuid            PRIMARY KEY,
   name varchar(100)    NOT NULL UNIQUE
);

CREATE TABLE _user_role (
    user_id    uuid,
    role_id    uuid,
    CONSTRAINT  fk_user_role_user FOREIGN KEY (user_id) REFERENCES _user (id),
    CONSTRAINT  fk_user_role_role FOREIGN KEY (role_id) REFERENCES _role (id),
    PRIMARY KEY(role_id, user_id)
);

CREATE TABLE oauth2_client (
    id                            varchar(255)                              PRIMARY KEY,
    client_id                     varchar(100)                              NOT NULL,
    client_id_issued_at           timestamp     DEFAULT CURRENT_TIMESTAMP   NOT NULL,
    client_secret                 varchar(200)  DEFAULT NULL,
    client_secret_expires_at      timestamp     DEFAULT NULL,
    client_name                   varchar(200)                              NOT NULL,
    client_authentication_methods varchar(1000)                             NOT NULL,
    authorization_grant_types     varchar(1000)                             NOT NULL,
    redirect_uris                 varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris     varchar(1000) DEFAULT NULL,
    scopes                        varchar(1000)                             NOT NULL,
    client_settings               varchar(2000)                             NOT NULL,
    token_settings                varchar(2000)                             NOT NULL
);

CREATE TABLE oauth2_authorization (
    id                              varchar(255)                PRIMARY KEY,
    registered_client_id            varchar(255)                NOT NULL,
    principal_name                  varchar(200)                NOT NULL,
    authorization_grant_type        varchar(100)                NOT NULL,
    authorized_scopes               varchar(1000) DEFAULT NULL,
    attributes                      text          DEFAULT NULL,
    state                           varchar(500)  DEFAULT NULL,
    authorization_code_value        text          DEFAULT NULL,
    authorization_code_issued_at    timestamp     DEFAULT NULL,
    authorization_code_expires_at   timestamp     DEFAULT NULL,
    authorization_code_metadata     text          DEFAULT NULL,
    access_token_value              text          DEFAULT NULL,
    access_token_issued_at          timestamp     DEFAULT NULL,
    access_token_expires_at         timestamp     DEFAULT NULL,
    access_token_metadata           text          DEFAULT NULL,
    access_token_type               varchar(100)  DEFAULT NULL,
    access_token_scopes             varchar(1000) DEFAULT NULL,
    oidc_id_token_value             text          DEFAULT NULL,
    oidc_id_token_issued_at         timestamp     DEFAULT NULL,
    oidc_id_token_expires_at        timestamp     DEFAULT NULL,
    oidc_id_token_metadata          text          DEFAULT NULL,
    oidc_id_token_claims            text          DEFAULT NULL,
    refresh_token_value             text          DEFAULT NULL,
    refresh_token_issued_at         timestamp     DEFAULT NULL,
    refresh_token_expires_at        timestamp     DEFAULT NULL,
    refresh_token_metadata          text          DEFAULT NULL,
    user_code_value                 text          DEFAULT NULL,
    user_code_issued_at             timestamp     DEFAULT NULL,
    user_code_expires_at            timestamp     DEFAULT NULL,
    user_code_metadata              text          DEFAULT NULL,
    device_code_value               text          DEFAULT NULL,
    device_code_issued_at           timestamp     DEFAULT NULL,
    device_code_expires_at          timestamp     DEFAULT NULL,
    device_code_metadata            text          DEFAULT NULL,
    CONSTRAINT fk_oauth2_authorization_oauth2_client FOREIGN KEY (registered_client_id) REFERENCES oauth2_client (id)
);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id    varchar(255)    NOT NULL,
    principal_name          varchar(200)    NOT NULL,
    authorities             varchar(1000)   NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name),
    CONSTRAINT  fk_oauth2_authorization_consent_oauth2_client FOREIGN KEY (registered_client_id) REFERENCES oauth2_client (id)
);