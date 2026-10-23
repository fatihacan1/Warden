-- +goose Up

-- Access tokens for the admin API (/api/v1 on the admin port), meant for
-- automation and AI agents. Scoped per resource, always expiring, optionally
-- bound to IP ranges. Only SHA-256 hashes are stored.
CREATE TABLE access_tokens (
    id              uuid PRIMARY KEY,
    name            text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    token_hash      bytea       NOT NULL,
    hint            text        NOT NULL,
    scopes          jsonb       NOT NULL DEFAULT '{}',
    allowed_ips     text[]      NOT NULL DEFAULT '{}',
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    created_from_ip text        NOT NULL DEFAULT '',
    last_used_at    timestamptz,
    last_used_ip    text        NOT NULL DEFAULT '',
    revoked_at      timestamptz
);
CREATE UNIQUE INDEX access_tokens_hash_key ON access_tokens (token_hash);

-- +goose Down
DROP TABLE access_tokens;
