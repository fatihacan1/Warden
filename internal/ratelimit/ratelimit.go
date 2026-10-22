// Package ratelimit implements distributed rate limiting (GCRA on Redis) and
// per-account brute force protection.
//
// Limits are shared by every replica. When Redis is unavailable the limiter
// either fails open (availability first, the default) or closed, depending
// on configuration; it never blocks a request waiting for Redis.
package ratelimit

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
)

// Policy is a named limit.
type Policy struct {
	Name  string
	Limit redis_rate.Limit
}

// Per builds a policy allowing n events per period with a burst of n.
func Per(name string, n int, period time.Duration) Policy {
	return Policy{Name: name, Limit: redis_rate.Limit{Rate: n, Burst: n, Period: period}}
}

// Decision is the outcome of a rate limit check.
type Decision struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Recorder receives rejections for metrics. Optional.
type Recorder interface {
	RateLimited(policy string)
}

type Limiter struct {
	rdb      *redis.Client
	rl       *redis_rate.Limiter
	enabled  bool
	failOpen bool
	log      *slog.Logger
	rec      Recorder
}

func New(rdb *redis.Client, enabled, failOpen bool, log *slog.Logger, rec Recorder) *Limiter {
	return &Limiter{rdb: rdb, rl: redis_rate.NewLimiter(rdb), enabled: enabled, failOpen: failOpen, log: log, rec: rec}
}

// Allow consumes one token for key under policy p.
func (l *Limiter) Allow(ctx context.Context, p Policy, key string) Decision {
	if !l.enabled {
		return Decision{Allowed: true}
	}
	res, err := l.rl.Allow(ctx, p.Name+":"+key, p.Limit)
	if err != nil {
		l.log.Warn("rate limiter unavailable", "policy", p.Name, "err", err, "fail_open", l.failOpen)
		if l.failOpen {
			return Decision{Allowed: true}
		}
		return Decision{Allowed: false, RetryAfter: time.Second}
	}
	if res.Allowed == 0 {
		if l.rec != nil {
			l.rec.RateLimited(p.Name)
		}
		return Decision{Allowed: false, RetryAfter: max(res.RetryAfter, time.Second)}
	}
	return Decision{Allowed: true, Remaining: res.Remaining}
}

// Lockout counts failed attempts per account. After threshold failures in
// window further attempts are rejected until the window expires. The counter
// starts at the first failure (fixed window), which bounds online guessing to
// threshold attempts per window per account regardless of source IPs.
type Lockout struct {
	rdb       *redis.Client
	threshold func() int
	window    time.Duration
	failOpen  bool
	log       *slog.Logger
}

func NewLockout(rdb *redis.Client, threshold func() int, window time.Duration, failOpen bool, log *slog.Logger) *Lockout {
	return &Lockout{rdb: rdb, threshold: threshold, window: window, failOpen: failOpen, log: log}
}

var incrScript = redis.NewScript(`
local n = redis.call("INCR", KEYS[1])
if n == 1 then redis.call("PEXPIRE", KEYS[1], ARGV[1]) end
return n`)

// Check returns a positive retry-after when the account is locked.
func (l *Lockout) Check(ctx context.Context, key string) time.Duration {
	k := "lockout:" + key
	n, err := l.rdb.Get(ctx, k).Int()
	if err == redis.Nil {
		return 0
	}
	if err != nil {
		l.log.Warn("lockout check unavailable", "err", err)
		if l.failOpen {
			return 0
		}
		return time.Second
	}
	if n < l.threshold() {
		return 0
	}
	ttl, err := l.rdb.PTTL(ctx, k).Result()
	if err != nil || ttl <= 0 {
		return l.window
	}
	return ttl
}

// Fail records a failed attempt and returns the number of failures so far.
func (l *Lockout) Fail(ctx context.Context, key string) int {
	n, err := incrScript.Run(ctx, l.rdb, []string{"lockout:" + key}, strconv.FormatInt(l.window.Milliseconds(), 10)).Int()
	if err != nil {
		l.log.Warn("lockout record unavailable", "err", err)
	}
	return n
}

// Reset clears the counter after a successful sign-in.
func (l *Lockout) Reset(ctx context.Context, key string) {
	if err := l.rdb.Del(ctx, "lockout:"+key).Err(); err != nil {
		l.log.Warn("lockout reset failed", "err", err)
	}
}
