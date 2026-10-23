package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// InboxRow is one stored email. Meta and Body are sealed with the instance
// key (labels are built by the mailer package); the store never sees plaintext.
type InboxRow struct {
	ID        uuid.UUID
	CreatedAt time.Time
	Meta      []byte
	Body      []byte
}

func (s *Store) AddInboxMessage(ctx context.Context, r *InboxRow) error {
	return mapErr(s.db.QueryRow(ctx, `INSERT INTO inbox_messages (id, meta, body) VALUES ($1, $2, $3) RETURNING created_at`,
		r.ID, r.Meta, r.Body).Scan(&r.CreatedAt))
}

// ListInbox returns the newest messages without their bodies.
func (s *Store) ListInbox(ctx context.Context, limit, offset int) ([]InboxRow, error) {
	rows, err := s.db.Query(ctx, `SELECT id, created_at, meta FROM inbox_messages ORDER BY created_at DESC, id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InboxRow
	for rows.Next() {
		var r InboxRow
		if err := rows.Scan(&r.ID, &r.CreatedAt, &r.Meta); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CountInbox(ctx context.Context) (n int, err error) {
	err = s.db.QueryRow(ctx, `SELECT count(*) FROM inbox_messages`).Scan(&n)
	return n, err
}

func (s *Store) GetInboxMessage(ctx context.Context, id uuid.UUID) (*InboxRow, error) {
	var r InboxRow
	err := s.db.QueryRow(ctx, `SELECT id, created_at, meta, body FROM inbox_messages WHERE id = $1`, id).
		Scan(&r.ID, &r.CreatedAt, &r.Meta, &r.Body)
	if err != nil {
		return nil, mapErr(err)
	}
	return &r, nil
}

func (s *Store) DeleteInboxMessage(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.db, `DELETE FROM inbox_messages WHERE id = $1`, id)
}

func (s *Store) DeleteAllInbox(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM inbox_messages`)
	return tag.RowsAffected(), err
}

// PruneInbox removes messages older than cutoff and everything beyond the
// newest keep messages. It returns how many rows were deleted.
func (s *Store) PruneInbox(ctx context.Context, keep int, cutoff time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, `
		DELETE FROM inbox_messages
		WHERE created_at < $2
		   OR id IN (SELECT id FROM inbox_messages ORDER BY created_at DESC, id OFFSET $1)`, keep, cutoff)
	return tag.RowsAffected(), err
}
