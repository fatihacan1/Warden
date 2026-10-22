package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// API keys

type APIKeyRow struct {
	ID             uuid.UUID
	Kind           string
	Name           string
	KeyHash        []byte
	Hint           string
	AllowedOrigins []string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
	RevokedAt      *time.Time
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]APIKeyRow, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, kind, name, key_hash, hint, allowed_origins, created_at, last_used_at, revoked_at
		FROM api_keys ORDER BY revoked_at IS NOT NULL, created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKeyRow
	for rows.Next() {
		var r APIKeyRow
		if err := rows.Scan(&r.ID, &r.Kind, &r.Name, &r.KeyHash, &r.Hint, &r.AllowedOrigins, &r.CreatedAt, &r.LastUsedAt, &r.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateAPIKey(ctx context.Context, r *APIKeyRow) error {
	if r.AllowedOrigins == nil {
		r.AllowedOrigins = []string{}
	}
	return mapErr(s.db.QueryRow(ctx, `
		INSERT INTO api_keys (id, kind, name, key_hash, hint, allowed_origins) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at`, r.ID, r.Kind, r.Name, r.KeyHash, r.Hint, r.AllowedOrigins).Scan(&r.CreatedAt))
}

func (s *Store) UpdateAPIKey(ctx context.Context, id uuid.UUID, name string, origins []string) error {
	return execOne(ctx, s.db, `UPDATE api_keys SET name = $2, allowed_origins = $3 WHERE id = $1 AND revoked_at IS NULL`, id, name, origins)
}

func (s *Store) RevokeAPIKey(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.db, `UPDATE api_keys SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1`, id)
}

func (s *Store) TouchAPIKey(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)
	return err
}

// ---------------------------------------------------------------------------
// Webhooks

type WebhookRow struct {
	ID          uuid.UUID
	URL         string
	Description string
	Events      []string
	Secret      []byte // encrypted
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (s *Store) ListWebhooks(ctx context.Context) ([]WebhookRow, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, url, description, events, secret, enabled, created_at, updated_at FROM webhooks ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebhookRow
	for rows.Next() {
		var r WebhookRow
		if err := rows.Scan(&r.ID, &r.URL, &r.Description, &r.Events, &r.Secret, &r.Enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateWebhook(ctx context.Context, r *WebhookRow) error {
	if r.Events == nil {
		r.Events = []string{}
	}
	return mapErr(s.db.QueryRow(ctx, `
		INSERT INTO webhooks (id, url, description, events, secret, enabled) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at, updated_at`, r.ID, r.URL, r.Description, r.Events, r.Secret, r.Enabled).Scan(&r.CreatedAt, &r.UpdatedAt))
}

func (s *Store) UpdateWebhook(ctx context.Context, r *WebhookRow) error {
	if r.Events == nil {
		r.Events = []string{}
	}
	return execOne(ctx, s.db, `
		UPDATE webhooks SET url = $2, description = $3, events = $4, enabled = $5, updated_at = now() WHERE id = $1`,
		r.ID, r.URL, r.Description, r.Events, r.Enabled)
}

func (s *Store) SetWebhookSecret(ctx context.Context, id uuid.UUID, secret []byte) error {
	return execOne(ctx, s.db, `UPDATE webhooks SET secret = $2, updated_at = now() WHERE id = $1`, id, secret)
}

// DeleteWebhook removes the endpoint and its queued deliveries.
func (s *Store) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	return s.InTx(ctx, func(tx *Store) error {
		if _, err := tx.db.Exec(ctx, `DELETE FROM outbox WHERE topic = $1`, "webhook:"+id.String()); err != nil {
			return err
		}
		return execOne(ctx, tx.db, `DELETE FROM webhooks WHERE id = $1`, id)
	})
}

// Delivery is one outbox row for a webhook.
type Delivery struct {
	ID          int64
	Payload     []byte
	Attempts    int
	CreatedAt   time.Time
	NextAttempt time.Time
	LastError   string
	ProcessedAt *time.Time
	FailedAt    *time.Time
}

func (s *Store) ListDeliveries(ctx context.Context, topic string, limit int) ([]Delivery, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, payload, attempts, created_at, next_attempt_at, COALESCE(last_error, ''), processed_at, failed_at
		FROM outbox WHERE topic = $1 ORDER BY id DESC LIMIT $2`, topic, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.Payload, &d.Attempts, &d.CreatedAt, &d.NextAttempt, &d.LastError, &d.ProcessedAt, &d.FailedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RetryDelivery schedules a failed or pending delivery for immediate retry.
func (s *Store) RetryDelivery(ctx context.Context, topic string, id int64) error {
	return execOne(ctx, s.db, `
		UPDATE outbox SET failed_at = NULL, next_attempt_at = now(), locked_until = NULL, attempts = 0
		WHERE id = $1 AND topic = $2 AND processed_at IS NULL`, id, topic)
}

// ---------------------------------------------------------------------------
// Email templates

type EmailTemplateRow struct {
	Name      string
	Locale    string
	Subject   string
	HTML      string
	Text      string
	UpdatedAt time.Time
}

func (s *Store) ListEmailTemplates(ctx context.Context) ([]EmailTemplateRow, error) {
	rows, err := s.db.Query(ctx, `SELECT name, locale, subject, html, text, updated_at FROM email_templates`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EmailTemplateRow
	for rows.Next() {
		var r EmailTemplateRow
		if err := rows.Scan(&r.Name, &r.Locale, &r.Subject, &r.HTML, &r.Text, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SaveEmailTemplate(ctx context.Context, r EmailTemplateRow) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO email_templates (name, locale, subject, html, text, updated_at) VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (name, locale) DO UPDATE SET subject = EXCLUDED.subject, html = EXCLUDED.html, text = EXCLUDED.text, updated_at = now()`,
		r.Name, r.Locale, r.Subject, r.HTML, r.Text)
	return err
}

func (s *Store) DeleteEmailTemplate(ctx context.Context, name, locale string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM email_templates WHERE name = $1 AND locale = $2`, name, locale)
	return err
}

// ---------------------------------------------------------------------------
// Re-encryption (key rotation)

// EncryptedColumn is a column holding secretbox ciphertexts. Label returns
// the associated data the column's values were sealed with.
type EncryptedColumn struct {
	Name   string
	query  string
	update string
	Label  func(key string) string
}

// EncryptedColumns lists every column that holds data encrypted with
// ENCRYPTION_KEY.
func EncryptedColumns() []EncryptedColumn {
	return []EncryptedColumn{
		{"signing_keys.private_key", `SELECT kid, private_key FROM signing_keys FOR UPDATE`,
			`UPDATE signing_keys SET private_key = $2 WHERE kid = $1`, func(k string) string { return "signing-key:" + k }},
		{"users.totp_secret", `SELECT id::text, totp_secret FROM users WHERE totp_secret IS NOT NULL FOR UPDATE`,
			`UPDATE users SET totp_secret = $2 WHERE id = $1::uuid`, func(k string) string { return "totp:" + k }},
		{"provider_settings.config", `SELECT provider, config FROM provider_settings FOR UPDATE`,
			`UPDATE provider_settings SET config = $2 WHERE provider = $1`, func(k string) string { return "provider:" + k }},
		{"webhooks.secret", `SELECT id::text, secret FROM webhooks FOR UPDATE`,
			`UPDATE webhooks SET secret = $2 WHERE id = $1::uuid`, func(k string) string { return "webhook:" + k }},
		{"outbox.payload (emails)", `SELECT id::text, payload FROM outbox WHERE topic = 'email.send' AND processed_at IS NULL FOR UPDATE`,
			`UPDATE outbox SET payload = $2 WHERE id = $1::bigint`, func(string) string { return "email.send" }},
	}
}

// ResealColumn rewrites every value of col through fn in one transaction and
// returns how many values changed. fn returns the new value and whether it
// differs from the old one.
func (s *Store) ResealColumn(ctx context.Context, col EncryptedColumn, fn func(value []byte, label string) ([]byte, bool, error)) (int, error) {
	changed := 0
	err := s.InTx(ctx, func(tx *Store) error {
		rows, err := tx.db.Query(ctx, col.query)
		if err != nil {
			return err
		}
		type item struct {
			key   string
			value []byte
		}
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.key, &it.value); err != nil {
				rows.Close()
				return err
			}
			items = append(items, it)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, it := range items {
			next, diff, err := fn(it.value, col.Label(it.key))
			if err != nil {
				return err
			}
			if !diff {
				continue
			}
			if _, err := tx.db.Exec(ctx, col.update, it.key, next); err != nil {
				return err
			}
			changed++
		}
		return nil
	})
	return changed, err
}
