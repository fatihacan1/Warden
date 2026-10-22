-- +goose Up

-- API keys for apps. Publishable keys (pk_) identify a client app and may be
-- bound to browser origins; they are public. Secret keys (sk_) authenticate
-- your backends against the server API and are shown once. Only SHA-256
-- hashes are stored; hint is what the admin UI displays.
CREATE TABLE api_keys (
    id              uuid PRIMARY KEY,
    kind            text        NOT NULL CHECK (kind IN ('publishable', 'secret')),
    name            text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    key_hash        bytea       NOT NULL,
    hint            text        NOT NULL,
    allowed_origins text[]      NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    revoked_at      timestamptz
);
CREATE UNIQUE INDEX api_keys_key_hash_key ON api_keys (key_hash);

-- HTTP endpoints notified of domain events. The signing secret is encrypted
-- with ENCRYPTION_KEY. Empty events means every event.
CREATE TABLE webhooks (
    id          uuid PRIMARY KEY,
    url         text        NOT NULL CHECK (char_length(url) <= 2048),
    description text        NOT NULL DEFAULT '',
    events      text[]      NOT NULL DEFAULT '{}',
    secret      bytea       NOT NULL,
    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Email templates edited in the admin UI. Absent rows use the built-in
-- templates shipped with the binary.
CREATE TABLE email_templates (
    name       text PRIMARY KEY,
    subject    text        NOT NULL DEFAULT '',
    html       text        NOT NULL,
    text       text        NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Webhook deliveries are outbox rows with topic webhook:<id>; the admin UI
-- lists the latest ones per webhook.
CREATE INDEX outbox_topic_idx ON outbox (topic, id DESC);

-- +goose Down
DROP INDEX outbox_topic_idx;
DROP TABLE email_templates;
DROP TABLE webhooks;
DROP TABLE api_keys;
