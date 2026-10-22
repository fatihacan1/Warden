-- +goose Up

CREATE TABLE users (
    id                uuid PRIMARY KEY,
    email             text,
    email_verified_at timestamptz,
    password_hash     text,
    name              text        NOT NULL DEFAULT '',
    avatar_key        text,
    roles             text[]      NOT NULL DEFAULT '{}',
    totp_secret       bytea,
    totp_enabled_at   timestamptz,
    totp_last_step    bigint      NOT NULL DEFAULT 0,
    disabled_at       timestamptz,
    last_sign_in_at   timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_email_lowercase CHECK (email = lower(email)),
    CONSTRAINT users_email_length CHECK (char_length(email) <= 254),
    CONSTRAINT users_name_length CHECK (char_length(name) <= 100)
);
CREATE UNIQUE INDEX users_email_key ON users (email);
CREATE INDEX users_created_at_idx ON users (created_at DESC);

CREATE TABLE identities (
    id           uuid PRIMARY KEY,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider     text        NOT NULL,
    subject      text        NOT NULL,
    email        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    CONSTRAINT identities_provider_subject_key UNIQUE (provider, subject),
    CONSTRAINT identities_user_provider_key UNIQUE (user_id, provider)
);

-- A session is a refresh token family. Only hashes of refresh tokens are
-- stored. prev_refresh_hash enables reuse detection after rotation.
CREATE TABLE sessions (
    id                  uuid PRIMARY KEY,
    user_id             uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    refresh_hash        bytea       NOT NULL,
    prev_refresh_hash   bytea,
    rotated_at          timestamptz,
    amr                 text[]      NOT NULL DEFAULT '{}',
    user_agent          text        NOT NULL DEFAULT '',
    ip                  text        NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_used_at        timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at          timestamptz,
    revoke_reason       text        NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX sessions_refresh_hash_key ON sessions (refresh_hash);
CREATE INDEX sessions_prev_refresh_hash_idx ON sessions (prev_refresh_hash) WHERE prev_refresh_hash IS NOT NULL;
CREATE INDEX sessions_user_active_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE recovery_codes (
    user_id   uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash bytea       NOT NULL,
    used_at   timestamptz,
    PRIMARY KEY (user_id, code_hash)
);

-- JWT signing keys. Private keys are encrypted with ENCRYPTION_KEY.
CREATE TABLE signing_keys (
    kid         text PRIMARY KEY,
    algorithm   text        NOT NULL,
    private_key bytea       NOT NULL,
    public_jwk  jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz
);
-- At most one active key at any time.
CREATE UNIQUE INDEX signing_keys_single_active ON signing_keys ((true)) WHERE retired_at IS NULL;

-- Identity provider settings managed from the admin UI. Credentials are
-- encrypted with ENCRYPTION_KEY.
CREATE TABLE provider_settings (
    provider   text PRIMARY KEY,
    enabled    boolean     NOT NULL DEFAULT false,
    config     bytea       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Transactional outbox: domain events and emails are written in the same
-- transaction as the state change, then delivered at-least-once by a relay.
CREATE TABLE outbox (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    topic           text        NOT NULL,
    payload         bytea       NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_until    timestamptz,
    last_error      text,
    processed_at    timestamptz,
    failed_at       timestamptz
);
CREATE INDEX outbox_pending_idx ON outbox (next_attempt_at, id) WHERE processed_at IS NULL AND failed_at IS NULL;
CREATE INDEX outbox_processed_idx ON outbox (processed_at) WHERE processed_at IS NOT NULL;

-- Security audit trail. No foreign key: entries outlive deleted users.
CREATE TABLE audit_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    uuid,
    type       text        NOT NULL,
    ip         text        NOT NULL DEFAULT '',
    user_agent text        NOT NULL DEFAULT '',
    metadata   jsonb       NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_user_idx ON audit_events (user_id, created_at DESC);
CREATE INDEX audit_events_created_at_idx ON audit_events (created_at);

-- +goose Down
DROP TABLE audit_events;
DROP TABLE outbox;
DROP TABLE provider_settings;
DROP TABLE signing_keys;
DROP TABLE recovery_codes;
DROP TABLE sessions;
DROP TABLE identities;
DROP TABLE users;
