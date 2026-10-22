-- +goose Up

-- Feature toggles and policies edited from the admin UI. A single row; when
-- absent, environment variables apply. Contains no secrets.
CREATE TABLE runtime_settings (
    id         smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    data       jsonb       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE runtime_settings;
