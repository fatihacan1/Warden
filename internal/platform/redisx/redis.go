// Package redisx creates the Redis client.
package redisx

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/fatihacan1/warden/internal/config"
)

// Connect returns a pooled client with strict timeouts, so a slow or
// unreachable Redis degrades requests quickly instead of hanging them.
func Connect(ctx context.Context, cfg config.RedisConfig) (*redis.Client, error) {
	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("redis: parse url: %w", err)
	}
	if cfg.PoolSize > 0 {
		opts.PoolSize = cfg.PoolSize
	}
	opts.DialTimeout = cfg.DialTimeout
	opts.ReadTimeout = cfg.ReadTimeout
	opts.WriteTimeout = cfg.WriteTimeout
	opts.PoolTimeout = cfg.ReadTimeout + cfg.WriteTimeout
	opts.ClientName = "warden"
	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return client, nil
}
