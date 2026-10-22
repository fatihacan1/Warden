package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Provider settings (admin UI managed)

type ProviderSettingRow struct {
	Provider  string
	Enabled   bool
	Config    []byte // encrypted JSON
	UpdatedAt time.Time
}

func (s *Store) ListProviderSettings(ctx context.Context) ([]ProviderSettingRow, error) {
	rows, err := s.db.Query(ctx, `SELECT provider, enabled, config, updated_at FROM provider_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProviderSettingRow
	for rows.Next() {
		var r ProviderSettingRow
		if err := rows.Scan(&r.Provider, &r.Enabled, &r.Config, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) UpsertProviderSetting(ctx context.Context, r ProviderSettingRow) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO provider_settings (provider, enabled, config, updated_at) VALUES ($1, $2, $3, now())
		ON CONFLICT (provider) DO UPDATE SET enabled = EXCLUDED.enabled, config = EXCLUDED.config, updated_at = now()`,
		r.Provider, r.Enabled, r.Config)
	return err
}

func (s *Store) DeleteProviderSetting(ctx context.Context, provider string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM provider_settings WHERE provider = $1`, provider)
	return err
}

// ---------------------------------------------------------------------------
// Outbox

type OutboxMessage struct {
	ID       int64
	Topic    string
	Payload  []byte
	Attempts int
}

func (s *Store) EnqueueOutbox(ctx context.Context, topic string, payload []byte) error {
	_, err := s.db.Exec(ctx, `INSERT INTO outbox (topic, payload) VALUES ($1, $2)`, topic, payload)
	return err
}

// ClaimOutbox leases up to limit due messages for lease. SKIP LOCKED lets
// several replicas run relays concurrently without double delivery races.
func (s *Store) ClaimOutbox(ctx context.Context, limit int, lease time.Duration) ([]OutboxMessage, error) {
	rows, err := s.db.Query(ctx, `
		UPDATE outbox SET locked_until = now() + make_interval(secs => $2), attempts = attempts + 1
		WHERE id IN (
			SELECT id FROM outbox
			WHERE processed_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now()
			  AND (locked_until IS NULL OR locked_until < now())
			ORDER BY next_attempt_at, id
			LIMIT $1
			FOR UPDATE SKIP LOCKED)
		RETURNING id, topic, payload, attempts`, limit, lease.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxMessage
	for rows.Next() {
		var m OutboxMessage
		if err := rows.Scan(&m.ID, &m.Topic, &m.Payload, &m.Attempts); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CompleteOutbox marks a message as delivered. Sensitive payloads (emails
// with one-time links) are deleted instead of being kept around.
func (s *Store) CompleteOutbox(ctx context.Context, id int64, deletePayload bool) error {
	if deletePayload {
		_, err := s.db.Exec(ctx, `DELETE FROM outbox WHERE id = $1`, id)
		return err
	}
	_, err := s.db.Exec(ctx, `UPDATE outbox SET processed_at = now(), locked_until = NULL, last_error = NULL WHERE id = $1`, id)
	return err
}

func (s *Store) RetryOutbox(ctx context.Context, id int64, next time.Time, lastErr string, dead bool) error {
	lastErr = cleanText(lastErr, 1000)
	_, err := s.db.Exec(ctx, `
		UPDATE outbox SET next_attempt_at = $2, last_error = $3, locked_until = NULL,
		       failed_at = CASE WHEN $4 THEN now() ELSE NULL END
		WHERE id = $1`, id, next, lastErr, dead)
	return err
}

func (s *Store) OutboxBacklog(ctx context.Context) (pending, failed int, err error) {
	err = s.db.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE processed_at IS NULL AND failed_at IS NULL),
		       count(*) FILTER (WHERE failed_at IS NOT NULL)
		FROM outbox`).Scan(&pending, &failed)
	return
}

func (s *Store) DeleteProcessedOutbox(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM outbox WHERE processed_at < $1 OR failed_at < $1`, before)
	return tag.RowsAffected(), err
}

// ---------------------------------------------------------------------------
// Audit log

type AuditEvent struct {
	ID        int64
	UserID    *uuid.UUID
	Type      string
	IP        string
	UserAgent string
	Metadata  map[string]any
	CreatedAt time.Time
}

func (s *Store) InsertAudit(ctx context.Context, e AuditEvent) error {
	meta, err := json.Marshal(e.Metadata)
	if err != nil || e.Metadata == nil {
		meta = []byte("{}")
	}
	_, err = s.db.Exec(ctx, `INSERT INTO audit_events (user_id, type, ip, user_agent, metadata) VALUES ($1, $2, $3, $4, $5)`,
		e.UserID, e.Type, cleanText(e.IP, 64), cleanText(e.UserAgent, 512), meta)
	return err
}

func (s *Store) ListAudit(ctx context.Context, userID *uuid.UUID, limit int) ([]AuditEvent, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, user_id, type, ip, user_agent, metadata, created_at FROM audit_events
		WHERE ($1::uuid IS NULL OR user_id = $1)
		ORDER BY created_at DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.UserID, &e.Type, &e.IP, &e.UserAgent, &e.Metadata, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAuditBefore(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM audit_events WHERE created_at < $1`, before)
	return tag.RowsAffected(), err
}

// cleanText makes client supplied strings safe for Postgres text columns:
// valid UTF-8, no NUL bytes, bounded length.
func cleanText(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if r == 0 {
			return -1
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// ---------------------------------------------------------------------------
// Runtime settings (admin UI managed feature toggles)

// GetRuntimeSettings returns the stored JSON, or domain.ErrNotFound when the
// admin has never saved settings.
func (s *Store) GetRuntimeSettings(ctx context.Context) ([]byte, time.Time, error) {
	var data []byte
	var at time.Time
	err := s.db.QueryRow(ctx, `SELECT data, updated_at FROM runtime_settings WHERE id = 1`).Scan(&data, &at)
	return data, at, mapErr(err)
}

func (s *Store) SaveRuntimeSettings(ctx context.Context, data []byte) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO runtime_settings (id, data, updated_at) VALUES (1, $1, now())
		ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`, data)
	return err
}

func (s *Store) DeleteRuntimeSettings(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM runtime_settings`)
	return err
}
