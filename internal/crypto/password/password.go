// Package password hashes and verifies passwords with Argon2id.
//
// Argon2id is memory hard by design: every hash allocates Params.Memory KiB.
// Without a bound, a burst of sign-in requests would allocate unbounded memory
// and crash the process (a classic auth-service DoS). Hasher therefore limits
// the number of concurrent hash operations; callers that cannot get a slot
// within QueueTimeout receive ErrBusy, which the API maps to 503 + Retry-After.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrBusy means no hashing slot became available in time.
	ErrBusy = errors.New("password: hasher busy")
	// ErrInvalidHash means the stored hash is malformed.
	ErrInvalidHash = errors.New("password: invalid hash format")
)

// Params are Argon2id cost parameters.
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams follow the OWASP Password Storage Cheat Sheet minimums
// (m=19 MiB, t=2, p=1).
var DefaultParams = Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// Observer receives timing information for metrics. Optional.
type Observer interface {
	ObserveHash(wait, compute time.Duration)
	ObserveRejected()
}

// Hasher hashes passwords with bounded concurrency.
type Hasher struct {
	params       Params
	slots        chan struct{}
	queueTimeout time.Duration
	observer     Observer
	dummyHash    string
}

// NewHasher creates a hasher. maxConcurrent <= 0 means 2 x GOMAXPROCS.
func NewHasher(p Params, maxConcurrent int, queueTimeout time.Duration, obs Observer) *Hasher {
	if p.SaltLength == 0 {
		p.SaltLength = DefaultParams.SaltLength
	}
	if p.KeyLength == 0 {
		p.KeyLength = DefaultParams.KeyLength
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 2 * runtime.GOMAXPROCS(0)
	}
	if queueTimeout <= 0 {
		queueTimeout = 3 * time.Second
	}
	h := &Hasher{
		params:       p,
		slots:        make(chan struct{}, maxConcurrent),
		queueTimeout: queueTimeout,
		observer:     obs,
	}
	// A real hash with the current params, used to equalize timing when a user
	// does not exist (prevents account enumeration through response times).
	h.dummyHash = h.encode(h.compute([]byte("warden-dummy-password"), randomBytes(p.SaltLength), p), randomBytes(p.SaltLength), p)
	return h
}

// Hash returns a PHC formatted Argon2id hash.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	salt := randomBytes(h.params.SaltLength)
	var key []byte
	if err := h.withSlot(ctx, func() { key = h.compute([]byte(password), salt, h.params) }); err != nil {
		return "", err
	}
	return h.encode(key, salt, h.params), nil
}

// Verify checks password against an encoded hash. needsRehash is true when the
// hash was produced with weaker parameters than the current ones.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (match, needsRehash bool, err error) {
	p, salt, want, err := decode(encoded)
	if err != nil {
		return false, false, err
	}
	var got []byte
	if err := h.withSlot(ctx, func() { got = h.compute([]byte(password), salt, p) }); err != nil {
		return false, false, err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	needsRehash = p.Memory < h.params.Memory || p.Iterations < h.params.Iterations ||
		p.Parallelism < h.params.Parallelism || uint32(len(want)) < h.params.KeyLength // #nosec G115 -- len(want) <= 128, checked in decode
	return true, needsRehash, nil
}

// DummyVerify burns the same CPU/memory as a real verification. Call it when
// the account does not exist or has no password.
func (h *Hasher) DummyVerify(ctx context.Context, password string) error {
	_, _, err := h.Verify(ctx, password, h.dummyHash)
	return err
}

func (h *Hasher) withSlot(ctx context.Context, fn func()) error {
	start := time.Now()
	timer := time.NewTimer(h.queueTimeout)
	defer timer.Stop()
	select {
	case h.slots <- struct{}{}:
	case <-timer.C:
		if h.observer != nil {
			h.observer.ObserveRejected()
		}
		return ErrBusy
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-h.slots }()
	waited := time.Since(start)
	computeStart := time.Now()
	fn()
	if h.observer != nil {
		h.observer.ObserveHash(waited, time.Since(computeStart))
	}
	return nil
}

func (h *Hasher) compute(pw, salt []byte, p Params) []byte {
	return argon2.IDKey(pw, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
}

func (h *Hasher) encode(key, salt []byte, p Params) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64.EncodeToString(salt), b64.EncodeToString(key))
}

// Upper bounds protect against a tampered hash forcing huge allocations.
const (
	maxMemory     = 1 << 20 // 1 GiB in KiB
	maxIterations = 64
)

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if p.Memory == 0 || p.Memory > maxMemory || p.Iterations == 0 || p.Iterations > maxIterations || p.Parallelism == 0 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 128 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	p.SaltLength = uint32(len(salt)) // #nosec G115 -- bounded by the base64 field of a stored hash
	p.KeyLength = uint32(len(key))   // #nosec G115 -- len(key) <= 128, checked above
	return p, salt, key, nil
}

func randomBytes(n uint32) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("password: " + err.Error())
	}
	return b
}
