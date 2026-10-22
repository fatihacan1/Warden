package ratelimit

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func newRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, rdb
}

func TestAllowEnforcesLimit(t *testing.T) {
	_, rdb := newRedis(t)
	l := New(rdb, true, true, discard, nil)
	p := Per("test", 3, time.Minute)
	ctx := context.Background()
	for i := range 3 {
		if d := l.Allow(ctx, p, "1.2.3.4"); !d.Allowed {
			t.Fatalf("request %d rejected", i)
		}
	}
	d := l.Allow(ctx, p, "1.2.3.4")
	if d.Allowed || d.RetryAfter <= 0 {
		t.Fatalf("4th request should be limited with retry-after, got %+v", d)
	}
	if d := l.Allow(ctx, p, "5.6.7.8"); !d.Allowed {
		t.Fatal("limits must be per key")
	}
}

func TestFailOpenAndClosed(t *testing.T) {
	mr, rdb := newRedis(t)
	mr.Close() // Redis down
	p := Per("test", 1, time.Minute)
	if d := New(rdb, true, true, discard, nil).Allow(context.Background(), p, "k"); !d.Allowed {
		t.Fatal("fail-open limiter must allow when Redis is down")
	}
	if d := New(rdb, true, false, discard, nil).Allow(context.Background(), p, "k"); d.Allowed {
		t.Fatal("fail-closed limiter must reject when Redis is down")
	}
}

func TestDisabled(t *testing.T) {
	_, rdb := newRedis(t)
	l := New(rdb, false, true, discard, nil)
	for range 10 {
		if !l.Allow(context.Background(), Per("x", 1, time.Hour), "k").Allowed {
			t.Fatal("disabled limiter rejected a request")
		}
	}
}

func TestLockout(t *testing.T) {
	mr, rdb := newRedis(t)
	lo := NewLockout(rdb, func() int { return 3 }, 15*time.Minute, true, discard)
	ctx := context.Background()
	for range 2 {
		lo.Fail(ctx, "user@example.com")
	}
	if lo.Check(ctx, "user@example.com") != 0 {
		t.Fatal("locked too early")
	}
	lo.Fail(ctx, "user@example.com")
	if ra := lo.Check(ctx, "user@example.com"); ra <= 0 || ra > 15*time.Minute {
		t.Fatalf("expected lockout, retry-after=%v", ra)
	}
	mr.FastForward(16 * time.Minute)
	if lo.Check(ctx, "user@example.com") != 0 {
		t.Fatal("lockout should expire after the window")
	}
	lo.Fail(ctx, "user@example.com")
	lo.Reset(ctx, "user@example.com")
	if lo.Check(ctx, "user@example.com") != 0 {
		t.Fatal("reset did not clear the counter")
	}
}
