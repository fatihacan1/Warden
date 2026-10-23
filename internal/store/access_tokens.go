package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type AccessTokenRow struct {
	ID            uuid.UUID
	Name          string
	TokenHash     []byte
	Hint          string
	Scopes        map[string]string
	AllowedIPs    []string
	ExpiresAt     time.Time
	CreatedAt     time.Time
	CreatedFromIP string
	LastUsedAt    *time.Time
	LastUsedIP    string
	RevokedAt     *time.Time
}

// #nosec G101 -- column list, not a credential
const accessTokenColumns = `id, name, token_hash, hint, scopes, allowed_ips, expires_at, created_at, created_from_ip, last_used_at, last_used_ip, revoked_at`

func scanAccessToken(row interface{ Scan(...any) error }) (*AccessTokenRow, error) {
	var r AccessTokenRow
	var scopes []byte
	if err := row.Scan(&r.ID, &r.Name, &r.TokenHash, &r.Hint, &scopes, &r.AllowedIPs, &r.ExpiresAt, &r.CreatedAt,
		&r.CreatedFromIP, &r.LastUsedAt, &r.LastUsedIP, &r.RevokedAt); err != nil {
		return nil, mapErr(err)
	}
	if err := json.Unmarshal(scopes, &r.Scopes); err != nil {
		r.Scopes = map[string]string{}
	}
	return &r, nil
}

func (s *Store) ListAccessTokens(ctx context.Context) ([]*AccessTokenRow, error) {
	rows, err := s.db.Query(ctx, `SELECT `+accessTokenColumns+` FROM access_tokens ORDER BY revoked_at IS NOT NULL, expires_at < now(), created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AccessTokenRow
	for rows.Next() {
		r, err := scanAccessToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetAccessTokenByHash(ctx context.Context, hash []byte) (*AccessTokenRow, error) {
	return scanAccessToken(s.db.QueryRow(ctx, `SELECT `+accessTokenColumns+` FROM access_tokens WHERE token_hash = $1`, hash))
}

func (s *Store) CreateAccessToken(ctx context.Context, r *AccessTokenRow) error {
	scopes, err := json.Marshal(r.Scopes)
	if err != nil {
		return err
	}
	if r.AllowedIPs == nil {
		r.AllowedIPs = []string{}
	}
	return mapErr(s.db.QueryRow(ctx, `
		INSERT INTO access_tokens (id, name, token_hash, hint, scopes, allowed_ips, expires_at, created_from_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING created_at`,
		r.ID, r.Name, r.TokenHash, r.Hint, scopes, r.AllowedIPs, r.ExpiresAt, cleanText(r.CreatedFromIP, 64)).Scan(&r.CreatedAt))
}

func (s *Store) RevokeAccessToken(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.db, `UPDATE access_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1`, id)
}

func (s *Store) TouchAccessToken(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := s.db.Exec(ctx, `UPDATE access_tokens SET last_used_at = now(), last_used_ip = $2 WHERE id = $1`, id, cleanText(ip, 64))
	return err
}

// DeleteDeadAccessTokens removes tokens that expired or were revoked before.
func (s *Store) DeleteDeadAccessTokens(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM access_tokens WHERE expires_at < $1 OR revoked_at < $1`, before)
	return tag.RowsAffected(), err
}
