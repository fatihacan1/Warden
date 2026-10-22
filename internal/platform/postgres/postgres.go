// Package postgres creates the connection pool and runs schema migrations.
package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/migrations"
)

// Connect opens a bounded connection pool. Every connection carries a server
// side statement timeout, so a slow query can never pin a connection forever.
func Connect(ctx context.Context, cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse url: %w", err)
	}
	pc.MaxConns = cfg.MaxConns
	pc.MinConns = cfg.MinConns
	pc.MaxConnLifetime = cfg.MaxConnLifetime
	pc.MaxConnLifetimeJitter = cfg.MaxConnLifetime / 10
	pc.MaxConnIdleTime = cfg.MaxConnIdleTime
	rp := pc.ConnConfig.RuntimeParams
	rp["application_name"] = "warden"
	rp["statement_timeout"] = strconv.FormatInt(cfg.StatementTimeout.Milliseconds(), 10)
	rp["idle_in_transaction_session_timeout"] = strconv.FormatInt(3*cfg.StatementTimeout.Milliseconds(), 10)
	rp["lock_timeout"] = strconv.FormatInt(cfg.StatementTimeout.Milliseconds(), 10)

	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending migrations. goose takes a Postgres advisory lock,
// so several replicas starting at once are safe.
func Migrate(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	for _, r := range results {
		log.Info("migration applied", "version", r.Source.Version, "file", r.Source.Path, "duration", r.Duration)
	}
	return nil
}

// Status prints migration status (used by `warden migrate status`).
func Status(ctx context.Context, pool *pgxpool.Pool) ([]*goose.MigrationStatus, error) {
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		return nil, err
	}
	return provider.Status(ctx)
}
