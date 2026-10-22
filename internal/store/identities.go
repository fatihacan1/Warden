package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fatihacan1/warden/internal/domain"
)

func scanIdentity(row pgx.Row) (*domain.Identity, error) {
	var i domain.Identity
	var email *string
	if err := row.Scan(&i.ID, &i.UserID, &i.Provider, &i.Subject, &email, &i.CreatedAt, &i.LastUsedAt); err != nil {
		return nil, mapErr(err)
	}
	i.Email = deref(email)
	return &i, nil
}

const identityColumns = `id, user_id, provider, subject, email, created_at, last_used_at`

func (s *Store) GetIdentity(ctx context.Context, provider, subject string) (*domain.Identity, error) {
	return scanIdentity(s.db.QueryRow(ctx,
		`SELECT `+identityColumns+` FROM identities WHERE provider = $1 AND subject = $2`, provider, subject))
}

func (s *Store) CreateIdentity(ctx context.Context, i *domain.Identity) error {
	err := s.db.QueryRow(ctx, `
		INSERT INTO identities (id, user_id, provider, subject, email, last_used_at)
		VALUES ($1, $2, $3, $4, $5, now()) RETURNING created_at`,
		i.ID, i.UserID, i.Provider, i.Subject, nullable(i.Email)).Scan(&i.CreatedAt)
	return mapErr(err)
}

func (s *Store) TouchIdentity(ctx context.Context, id uuid.UUID, email string) error {
	_, err := s.db.Exec(ctx, `UPDATE identities SET last_used_at = now(), email = COALESCE($2, email) WHERE id = $1`, id, nullable(email))
	return err
}

func (s *Store) ListIdentities(ctx context.Context, userID uuid.UUID) ([]*domain.Identity, error) {
	rows, err := s.db.Query(ctx, `SELECT `+identityColumns+` FROM identities WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Identity
	for rows.Next() {
		i, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *Store) DeleteIdentity(ctx context.Context, userID uuid.UUID, provider string) error {
	return execOne(ctx, s.db, `DELETE FROM identities WHERE user_id = $1 AND provider = $2`, userID, provider)
}
