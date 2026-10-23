-- +goose Up

-- Service clients for the OAuth 2.0 client credentials grant: microservices
-- exchange client_id + client_secret for short-lived access tokens. Secrets
-- are 256-bit random values, so a SHA-256 hash is enough to store them. During
-- a rotation the previous secret stays valid until prev_secret_expires_at.
CREATE TABLE oauth_clients (
    id                      uuid PRIMARY KEY,
    name                    text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    client_id               text        NOT NULL,
    secret_hash             bytea       NOT NULL,
    secret_hint             text        NOT NULL DEFAULT '',
    prev_secret_hash        bytea,
    prev_secret_expires_at  timestamptz,
    allowed_scopes          text[]      NOT NULL DEFAULT '{}',
    allowed_audiences       text[]      NOT NULL DEFAULT '{}',
    token_ttl_seconds       integer     NOT NULL DEFAULT 900 CHECK (token_ttl_seconds BETWEEN 60 AND 3600),
    created_at              timestamptz NOT NULL DEFAULT now(),
    secret_rotated_at       timestamptz,
    last_used_at            timestamptz,
    revoked_at              timestamptz
);
CREATE UNIQUE INDEX oauth_clients_client_id_key ON oauth_clients (client_id);

-- +goose Down
DROP TABLE oauth_clients;
