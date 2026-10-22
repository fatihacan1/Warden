-- +goose Up

-- Preferred language for emails. Empty = the instance default.
ALTER TABLE users ADD COLUMN locale text NOT NULL DEFAULT ''
    CONSTRAINT users_locale_length CHECK (char_length(locale) <= 16);

-- Devices a user has signed in from, to send a notice on the first sign-in
-- from a new one. fingerprint is a hash of user id, browser, OS and device
-- type; no raw user agents or IPs are kept here.
CREATE TABLE user_devices (
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    fingerprint bytea       NOT NULL,
    label       text        NOT NULL DEFAULT '',
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, fingerprint)
);
CREATE INDEX user_devices_last_seen_idx ON user_devices (last_seen);

-- Email template overrides become per language.
ALTER TABLE email_templates ADD COLUMN locale text NOT NULL DEFAULT 'en';
ALTER TABLE email_templates DROP CONSTRAINT email_templates_pkey;
ALTER TABLE email_templates ADD PRIMARY KEY (name, locale);

-- +goose Down
ALTER TABLE email_templates DROP CONSTRAINT email_templates_pkey;
DELETE FROM email_templates WHERE locale <> 'en';
ALTER TABLE email_templates DROP COLUMN locale;
ALTER TABLE email_templates ADD PRIMARY KEY (name);
DROP TABLE user_devices;
ALTER TABLE users DROP COLUMN locale;
