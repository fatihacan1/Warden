package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type OAuthClientRow struct {
	ID                  uuid.UUID
	Name                string
	ClientID            string
	SecretHash          []byte
	SecretHint          string
	PrevSecretHash      []byte
	PrevSecretExpiresAt *time.Time
	AllowedScopes       []string
	AllowedAudiences    []string
	TokenTTLSeconds     int
	CreatedAt           time.Time
	SecretRotatedAt     *time.Time
	LastUsedAt          *time.Time
	RevokedAt           *time.Time
}

// #nosec G101 -- column list, not a credential
const oauthClientColumns = `id, name, client_id, secret_hash, secret_hint, prev_secret_hash, prev_secret_expires_at, allowed_scopes, allowed_audiences, token_ttl_seconds, created_at, secret_rotated_at, last_used_at, revoked_at`

func scanOAuthClient(row interface{ Scan(...any) error }) (*OAuthClientRow, error) {
	var r OAuthClientRow
	if err := row.Scan(&r.ID, &r.Name, &r.ClientID, &r.SecretHash, &r.SecretHint, &r.PrevSecretHash, &r.PrevSecretExpiresAt,
		&r.AllowedScopes, &r.AllowedAudiences, &r.TokenTTLSeconds, &r.CreatedAt, &r.SecretRotatedAt, &r.LastUsedAt, &r.RevokedAt); err != nil {
		return nil, mapErr(err)
	}
	return &r, nil
}

func (s *Store) ListOAuthClients(ctx context.Context) ([]*OAuthClientRow, error) {
	rows, err := s.db.Query(ctx, `SELECT `+oauthClientColumns+` FROM oauth_clients ORDER BY revoked_at IS NOT NULL, created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OAuthClientRow
	for rows.Next() {
		r, err := scanOAuthClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetOAuthClient(ctx context.Context, id uuid.UUID) (*OAuthClientRow, error) {
	return scanOAuthClient(s.db.QueryRow(ctx, `SELECT `+oauthClientColumns+` FROM oauth_clients WHERE id = $1`, id))
}

func (s *Store) GetOAuthClientByClientID(ctx context.Context, clientID string) (*OAuthClientRow, error) {
	return scanOAuthClient(s.db.QueryRow(ctx, `SELECT `+oauthClientColumns+` FROM oauth_clients WHERE client_id = $1`, clientID))
}

func (s *Store) CreateOAuthClient(ctx context.Context, r *OAuthClientRow) error {
	return mapErr(s.db.QueryRow(ctx, `
		INSERT INTO oauth_clients (id, name, client_id, secret_hash, secret_hint, allowed_scopes, allowed_audiences, token_ttl_seconds)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING created_at`,
		r.ID, r.Name, r.ClientID, r.SecretHash, r.SecretHint, r.AllowedScopes, r.AllowedAudiences, r.TokenTTLSeconds).Scan(&r.CreatedAt))
}

// RotateOAuthClientSecret installs a new secret. A positive grace keeps the
// current one valid until now()+grace as the "previous" secret.
func (s *Store) RotateOAuthClientSecret(ctx context.Context, id uuid.UUID, hash []byte, hint string, grace time.Duration) error {
	return execOne(ctx, s.db, `
		UPDATE oauth_clients SET
			prev_secret_hash = CASE WHEN $4::bigint > 0 THEN secret_hash END,
			prev_secret_expires_at = CASE WHEN $4::bigint > 0 THEN now() + make_interval(secs => $4::bigint) END,
			secret_hash = $2, secret_hint = $3, secret_rotated_at = now()
		WHERE id = $1 AND revoked_at IS NULL`, id, hash, hint, int64(grace.Seconds()))
}

func (s *Store) RevokeOAuthClient(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.db, `UPDATE oauth_clients SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1`, id)
}

func (s *Store) TouchOAuthClient(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `UPDATE oauth_clients SET last_used_at = now() WHERE id = $1`, id)
	return err
}
