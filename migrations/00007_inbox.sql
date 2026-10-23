-- +goose Up

-- Admin Inbox (MAIL_DELIVERY=inbox): emails kept on the server instead of
-- being sent, for test setups without an SMTP provider. They contain one-time
-- links, so both columns are encrypted (AES-GCM/XChaCha20 via the instance
-- key). meta holds recipient and subject, body the text and HTML parts.
CREATE TABLE inbox_messages (
    id         uuid PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    meta       bytea       NOT NULL,
    body       bytea       NOT NULL
);
CREATE INDEX inbox_messages_created_idx ON inbox_messages (created_at DESC);

-- +goose Down
DROP TABLE inbox_messages;
