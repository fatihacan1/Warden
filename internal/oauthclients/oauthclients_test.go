package oauthclients

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/store"
)

type memStore struct {
	mu   sync.Mutex
	rows map[string]*store.OAuthClientRow
	now  func() time.Time
}

func (m *memStore) ListOAuthClients(context.Context) ([]*store.OAuthClientRow, error) {
	return nil, nil
}
func (m *memStore) GetOAuthClient(_ context.Context, id uuid.UUID) (*store.OAuthClientRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.ID == id {
			c := *r
			return &c, nil
		}
	}
	return nil, domain.ErrNotFound
}
func (m *memStore) GetOAuthClientByClientID(_ context.Context, id string) (*store.OAuthClientRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rows[id]; ok {
		c := *r
		return &c, nil
	}
	return nil, domain.ErrNotFound
}
func (m *memStore) CreateOAuthClient(_ context.Context, r *store.OAuthClientRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[r.ClientID] = r
	return nil
}
func (m *memStore) RotateOAuthClientSecret(_ context.Context, id uuid.UUID, hash []byte, hint string, grace time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.ID == id {
			r.PrevSecretHash, r.PrevSecretExpiresAt = nil, nil
			if grace > 0 {
				exp := m.now().Add(grace)
				r.PrevSecretHash, r.PrevSecretExpiresAt = r.SecretHash, &exp
			}
			r.SecretHash, r.SecretHint = hash, hint
		}
	}
	return nil
}
func (m *memStore) RevokeOAuthClient(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.ID == id {
			now := m.now()
			r.RevokedAt = &now
		}
	}
	return nil
}
func (m *memStore) TouchOAuthClient(context.Context, uuid.UUID) error { return nil }

func newManager(t *testing.T) (*Manager, *time.Time) {
	t.Helper()
	clock := time.Now()
	st := &memStore{rows: map[string]*store.OAuthClientRow{}, now: func() time.Time { return clock }}
	m := NewManager(st, []string{"api"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.now = func() time.Time { return clock }
	return m, &clock
}

func TestAuthenticateAndRotate(t *testing.T) {
	ctx := context.Background()
	m, clock := newManager(t)
	secret, cl, err := m.Create(ctx, Input{Name: "billing", Scopes: []string{"orders:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if cl.TTL != DefaultTTL || len(cl.AllowedAudiences) != 1 || cl.AllowedAudiences[0] != "api" {
		t.Fatalf("defaults %+v", cl)
	}
	if _, err := m.Authenticate(ctx, cl.ClientID, secret); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{cl.ClientID, "wrong"}, {"svc_nope", secret}, {"", ""}, {cl.ClientID, ""}} {
		if _, err := m.Authenticate(ctx, c[0], c[1]); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("%v: %v", c, err)
		}
	}

	next, err := m.Rotate(ctx, cl.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{secret, next} {
		if _, err := m.Authenticate(ctx, cl.ClientID, s); err != nil {
			t.Fatalf("both secrets work during the grace period: %v", err)
		}
	}
	*clock = clock.Add(61 * time.Minute)
	if _, err := m.Authenticate(ctx, cl.ClientID, secret); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("old secret after grace: %v", err)
	}
	if _, err := m.Authenticate(ctx, cl.ClientID, next); err != nil {
		t.Fatal(err)
	}

	third, _ := m.Rotate(ctx, cl.ID, 0)
	if _, err := m.Authenticate(ctx, cl.ClientID, next); !errors.Is(err, ErrInvalidClient) {
		t.Fatal("grace 0 must end the old secret at once")
	}
	if err := m.Revoke(ctx, cl.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(ctx, cl.ClientID, third); !errors.Is(err, ErrInvalidClient) {
		t.Fatal("revoked client authenticated")
	}
	if _, err := m.Active(ctx, cl.ClientID); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("Active on revoked: %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	for _, in := range []Input{
		{Name: ""},
		{Name: "x", Scopes: []string{`bad"scope`}},
		{Name: "x", Scopes: []string{"with\\slash"}},
		{Name: "x", TTL: 2 * time.Hour},
		{Name: "x", TTL: time.Second},
		{Name: "x", Audiences: []string{"has space"}},
	} {
		if _, _, err := m.Create(ctx, in); err == nil {
			t.Fatalf("%+v accepted", in)
		}
	}
}

func TestResolve(t *testing.T) {
	c := &Client{AllowedScopes: []string{"a", "b"}, AllowedAudiences: []string{"x", "y"}}
	scopes, aud, err := c.Resolve("", nil)
	if err != nil || len(scopes) != 2 || len(aud) != 1 || aud[0] != "x" {
		t.Fatalf("defaults: %v %v %v", scopes, aud, err)
	}
	scopes, aud, err = c.Resolve("b  a b", []string{"y", "x"})
	if err != nil || len(scopes) != 2 || scopes[0] != "b" || len(aud) != 2 {
		t.Fatalf("subset: %v %v %v", scopes, aud, err)
	}
	if _, _, err := c.Resolve("a c", nil); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("scope: %v", err)
	}
	if _, _, err := c.Resolve("a", []string{"z"}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("audience: %v", err)
	}
	none := &Client{}
	if _, _, err := none.Resolve("", nil); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("no audiences: %v", err)
	}
}
