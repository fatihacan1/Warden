// Package store is the PostgreSQL persistence layer. All SQL lives here.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fatihacan1/warden/internal/domain"
)

// DBTX is satisfied by both *pgxpool.Pool and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store exposes typed queries. A Store returned by InTx runs every query in
// the same transaction.
type Store struct {
	pool *pgxpool.Pool
	db   DBTX
}

// New wraps a pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, db: pool}
}

// Pool returns the underlying pool (health checks, migrations).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// InTx runs fn inside a transaction. It commits when fn returns nil and rolls
// back otherwise (including on panic).
func (s *Store) InTx(ctx context.Context, fn func(tx *Store) error) (err error) {
	if _, nested := s.db.(pgx.Tx); nested {
		return fn(s)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	if err = fn(&Store{pool: s.pool, db: tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// TryAdvisoryLock runs fn only if this process wins the named lock. It is used
// so background jobs run on a single replica at a time.
func (s *Store) TryAdvisoryLock(ctx context.Context, key int64, fn func(context.Context) error) (bool, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
		return false, err
	}
	if !got {
		return false, nil
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key)
	}()
	return true, fn(ctx)
}

// Advisory lock keys.
const (
	LockKeyRotation int64 = 0x7761_7264_0001
	LockCleanup     int64 = 0x7761_7264_0002
)

// mapErr translates driver errors into domain errors.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if pgErr.ConstraintName == "users_email_key" {
			return domain.ErrEmailTaken
		}
		return domain.ErrConflict
	}
	return err
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
