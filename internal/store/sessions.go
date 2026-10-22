package store

import (
	"context"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fatihacan1/warden/internal/domain"
)

const sessionColumns = `id, user_id, refresh_hash, prev_refresh_hash, rotated_at, amr, user_agent, ip,
	created_at, last_used_at, expires_at, absolute_expires_at, revoked_at, revoke_reason`

func scanSession(row pgx.Row) (*domain.Session, error) {
	var s domain.Session
	err := row.Scan(&s.ID, &s.UserID, &s.RefreshHash, &s.PrevRefreshHash, &s.RotatedAt, &s.AMR, &s.UserAgent, &s.IP,
		&s.CreatedAt, &s.LastUsedAt, &s.ExpiresAt, &s.AbsoluteExpiresAt, &s.RevokedAt, &s.RevokeReason)
	if err != nil {
		return nil, mapErr(err)
	}
	return &s, nil
}

func (s *Store) CreateSession(ctx context.Context, sess *domain.Session) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO sessions (id, user_id, refresh_hash, amr, user_agent, ip, created_at, last_used_at, expires_at, absolute_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9)`,
		sess.ID, sess.UserID, sess.RefreshHash, sess.AMR, cleanText(sess.UserAgent, 512), cleanText(sess.IP, 64),
		sess.CreatedAt, sess.ExpiresAt, sess.AbsoluteExpiresAt)
	return mapErr(err)
}

// FindSessionByRefreshHash looks a session up by its current or previous
// refresh token hash. matchedPrevious tells the caller which one matched.
func (s *Store) FindSessionByRefreshHash(ctx context.Context, hash []byte) (sess *domain.Session, matchedPrevious bool, err error) {
	sess, err = scanSession(s.db.QueryRow(ctx, `
		SELECT `+sessionColumns+` FROM sessions
		WHERE refresh_hash = $1 OR prev_refresh_hash = $1
		LIMIT 1`, hash))
	if err != nil {
		return nil, false, err
	}
	return sess, string(sess.RefreshHash) != string(hash), nil
}

func (s *Store) GetSession(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	return scanSession(s.db.QueryRow(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = $1`, id))
}

// RotateRefreshToken swaps the refresh token using optimistic concurrency: it
// only succeeds if the session still has the hash the caller observed.
//
// resetRotatedAt is false when rotating from the previous token inside the
// reuse grace window: the window must not be extended, otherwise a stolen old
// token could be replayed forever by refreshing every few seconds.
func (s *Store) RotateRefreshToken(ctx context.Context, id uuid.UUID, observed, prev, next []byte, expiresAt time.Time, ip, ua string, resetRotatedAt bool) (bool, error) {
	tag, err := s.db.Exec(ctx, `
		UPDATE sessions
		SET refresh_hash = $3, prev_refresh_hash = $4,
		    rotated_at = CASE WHEN $8 THEN now() ELSE rotated_at END, last_used_at = now(),
		    expires_at = LEAST($5, absolute_expires_at), ip = $6, user_agent = $7
		WHERE id = $1 AND refresh_hash = $2 AND revoked_at IS NULL`,
		id, observed, next, prev, expiresAt, cleanText(ip, 64), cleanText(ua, 512), resetRotatedAt)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	rows, err := s.db.Query(ctx, `
		SELECT `+sessionColumns+` FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		ORDER BY last_used_at DESC LIMIT 100`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// RevokeSession revokes one session and returns its id if it was active.
func (s *Store) RevokeSession(ctx context.Context, userID, id uuid.UUID, reason string) (bool, error) {
	tag, err := s.db.Exec(ctx, `
		UPDATE sessions SET revoked_at = now(), revoke_reason = $3
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, id, userID, reason)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// RevokeUserSessions revokes every active session of a user except keep (may
// be uuid.Nil) and returns the ids that were revoked.
func (s *Store) RevokeUserSessions(ctx context.Context, userID, keep uuid.UUID, reason string) ([]uuid.UUID, error) {
	rows, err := s.db.Query(ctx, `
		UPDATE sessions SET revoked_at = now(), revoke_reason = $3
		WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL
		RETURNING id`, userID, keep, reason)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// DeleteExpiredSessions removes sessions that can no longer be used.
func (s *Store) DeleteExpiredSessions(ctx context.Context, olderThan time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, `
		DELETE FROM sessions WHERE (expires_at < $1) OR (revoked_at IS NOT NULL AND revoked_at < $1)`, olderThan)
	return tag.RowsAffected(), err
}

func itoa(i int) string { return strconv.Itoa(i) }
