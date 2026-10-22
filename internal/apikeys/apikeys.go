// Package apikeys manages the keys apps use to talk to Warden.
//
// Publishable keys (pk_live_/pk_test_) are public. They name the app making a
// request, can be bound to the browser origins the app runs on, and add those
// origins to CORS. They are an app identifier, not a credential: anything
// shipped to a browser or a phone can be extracted.
//
// Secret keys (sk_live_/sk_test_) authenticate your own backends against the
// server API (/v1/server). They are shown once, stored as SHA-256 hashes, and
// rejected on any request that carries a browser Origin header.
package apikeys

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/store"
)

// Kind is publishable or secret.
type Kind string

const (
	Publishable Kind = "publishable"
	Secret      Kind = "secret"
)

// Key is an API key without its secret part.
type Key struct {
	ID             uuid.UUID
	Kind           Kind
	Name           string
	Hint           string
	AllowedOrigins []string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
	RevokedAt      *time.Time
}

// Active reports whether the key may be used.
func (k *Key) Active() bool { return k.RevokedAt == nil }

// AllowsOrigin reports whether a browser on origin may use this key. Keys
// without origins work everywhere (mobile apps, scripts).
func (k *Key) AllowsOrigin(origin string) bool {
	return len(k.AllowedOrigins) == 0 || origin == "" || slices.Contains(k.AllowedOrigins, origin)
}

// Store persists keys.
type Store interface {
	ListAPIKeys(ctx context.Context) ([]store.APIKeyRow, error)
	CreateAPIKey(ctx context.Context, r *store.APIKeyRow) error
	UpdateAPIKey(ctx context.Context, id uuid.UUID, name string, origins []string) error
	RevokeAPIKey(ctx context.Context, id uuid.UUID) error
	TouchAPIKey(ctx context.Context, id uuid.UUID) error
}

type snapshot struct {
	all     []*Key
	byHash  map[[32]byte]*Key
	origins []string
}

// Manager serves key lookups from memory and reloads periodically so keys
// created or revoked on one replica reach the others.
type Manager struct {
	store      Store
	production bool
	log        *slog.Logger
	st         atomic.Pointer[snapshot]
	touched    sync.Map // id -> time.Time of the last last_used_at write
}

func NewManager(st Store, production bool, log *slog.Logger) *Manager {
	m := &Manager{store: st, production: production, log: log}
	m.st.Store(&snapshot{byHash: map[[32]byte]*Key{}})
	return m
}

// Reload reads every key from the database.
func (m *Manager) Reload(ctx context.Context) error {
	rows, err := m.store.ListAPIKeys(ctx)
	if err != nil {
		return err
	}
	snap := &snapshot{byHash: map[[32]byte]*Key{}}
	for _, r := range rows {
		k := &Key{ID: r.ID, Kind: Kind(r.Kind), Name: r.Name, Hint: r.Hint, AllowedOrigins: r.AllowedOrigins,
			CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt}
		snap.all = append(snap.all, k)
		if !k.Active() || len(r.KeyHash) != sha256.Size {
			continue
		}
		snap.byHash[[32]byte(r.KeyHash)] = k
		if k.Kind == Publishable {
			for _, o := range k.AllowedOrigins {
				if !slices.Contains(snap.origins, o) {
					snap.origins = append(snap.origins, o)
				}
			}
		}
	}
	m.st.Store(snap)
	return nil
}

// Run reloads until ctx is cancelled.
func (m *Manager) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Reload(ctx); err != nil && ctx.Err() == nil {
				m.log.Error("api keys reload failed", "err", err)
			}
		}
	}
}

// List returns every key, active first.
func (m *Manager) List() []*Key { return m.st.Load().all }

// Origins returns the origins of every active publishable key (added to CORS).
func (m *Manager) Origins() []string { return m.st.Load().origins }

// HasPublishable reports whether at least one active publishable key exists.
func (m *Manager) HasPublishable() bool {
	for _, k := range m.st.Load().byHash {
		if k.Kind == Publishable {
			return true
		}
	}
	return false
}

// Lookup returns the active key matching raw, or nil. The map lookup is by
// SHA-256 of the presented value, so timing reveals nothing about stored keys.
func (m *Manager) Lookup(raw string, kind Kind) *Key {
	if len(raw) < 16 || len(raw) > 128 {
		return nil
	}
	k := m.st.Load().byHash[sha256.Sum256([]byte(raw))]
	if k == nil || k.Kind != kind {
		return nil
	}
	m.touch(k)
	return k
}

// touch records last use at most once a minute per key, off the request path.
func (m *Manager) touch(k *Key) {
	now := time.Now()
	if last, ok := m.touched.Load(k.ID); ok && now.Sub(last.(time.Time)) < time.Minute {
		return
	}
	m.touched.Store(k.ID, now)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.store.TouchAPIKey(ctx, k.ID); err != nil {
			m.log.Warn("api key touch failed", "err", err)
		}
	}()
}

// Prefix returns the key prefix for kind in this environment.
func (m *Manager) Prefix(kind Kind) string {
	env := "test"
	if m.production {
		env = "live"
	}
	if kind == Secret {
		return "sk_" + env + "_"
	}
	return "pk_" + env + "_"
}

// Create stores a new key and returns its full value. For secret keys this is
// the only time the value is available.
func (m *Manager) Create(ctx context.Context, kind Kind, name string, origins []string) (string, *Key, error) {
	if kind != Publishable && kind != Secret {
		return "", nil, domain.ErrValidation.WithMessage("Choose publishable or secret.")
	}
	name, origins, err := m.clean(kind, name, origins)
	if err != nil {
		return "", nil, err
	}
	raw := m.Prefix(kind) + randtoken.New(24)
	hint := raw
	if kind == Secret {
		hint = raw[:len(m.Prefix(kind))+4] + "…" + raw[len(raw)-4:]
	}
	sum := sha256.Sum256([]byte(raw))
	row := &store.APIKeyRow{ID: uuid.Must(uuid.NewV7()), Kind: string(kind), Name: name, KeyHash: sum[:], Hint: hint, AllowedOrigins: origins}
	if err := m.store.CreateAPIKey(ctx, row); err != nil {
		return "", nil, err
	}
	if err := m.Reload(ctx); err != nil {
		return "", nil, err
	}
	return raw, &Key{ID: row.ID, Kind: kind, Name: name, Hint: hint, AllowedOrigins: origins, CreatedAt: row.CreatedAt}, nil
}

// Update renames a key and replaces its origins.
func (m *Manager) Update(ctx context.Context, id uuid.UUID, name string, origins []string) error {
	k := m.find(id)
	if k == nil {
		return domain.ErrNotFound
	}
	name, origins, err := m.clean(k.Kind, name, origins)
	if err != nil {
		return err
	}
	if err := m.store.UpdateAPIKey(ctx, id, name, origins); err != nil {
		return err
	}
	return m.Reload(ctx)
}

// Revoke disables a key permanently.
func (m *Manager) Revoke(ctx context.Context, id uuid.UUID) error {
	if err := m.store.RevokeAPIKey(ctx, id); err != nil {
		return err
	}
	return m.Reload(ctx)
}

func (m *Manager) find(id uuid.UUID) *Key {
	for _, k := range m.List() {
		if k.ID == id {
			return k
		}
	}
	return nil
}

func (m *Manager) clean(kind Kind, name string, origins []string) (string, []string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 80 {
		return "", nil, domain.ErrValidation.WithMessage("Name the key (1 to 80 characters), for example \"Web app\" or \"Billing service\".")
	}
	out := []string{}
	if kind == Secret {
		return name, out, nil
	}
	var errs []error
	for _, o := range origins {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o == "" || slices.Contains(out, o) {
			continue
		}
		if err := ValidateOrigin(o, m.production); err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, o)
	}
	if len(out) > 20 {
		errs = append(errs, errors.New("at most 20 origins per key"))
	}
	if err := errors.Join(errs...); err != nil {
		return "", nil, domain.ErrValidation.WithMessage(err.Error())
	}
	return name, out, nil
}

// ValidateOrigin accepts exact browser origins like https://app.example.com.
func ValidateOrigin(o string, production bool) error {
	u, err := url.Parse(o)
	switch {
	case o == "*" || strings.EqualFold(o, "null"):
		return fmt.Errorf("%q: list exact origins, wildcards are not allowed", o)
	case err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil:
		return fmt.Errorf("%q is not an origin like https://app.example.com", o)
	case production && u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1":
		return fmt.Errorf("%q must use https in production", o)
	}
	return nil
}
