package settings

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/domain"
)

type memStore struct{ data []byte }

func (m *memStore) GetRuntimeSettings(context.Context) ([]byte, time.Time, error) {
	if m.data == nil {
		return nil, time.Time{}, domain.ErrNotFound
	}
	return m.data, time.Now(), nil
}
func (m *memStore) SaveRuntimeSettings(_ context.Context, d []byte) error { m.data = d; return nil }
func (m *memStore) DeleteRuntimeSettings(context.Context) error           { m.data = nil; return nil }

func testConfig() *config.Config {
	c := &config.Config{Env: "development"}
	c.Auth.AllowSignup = true
	c.Auth.AppName = "Acme"
	c.Auth.LockoutThreshold = 10
	c.Auth.VerifyEmailURL = "https://app.example.com/verify?token={token}"
	c.Auth.ResetPasswordURL = "https://app.example.com/reset?token={token}"
	c.Auth.AllowedRedirectURIs = []string{"myapp://auth"}
	c.Password.MinLength = 8
	return c
}

func TestOverrideAndReset(t *testing.T) {
	st := &memStore{}
	m := NewManager(testConfig(), st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if !m.Get().AllowSignup || m.Get().AppName != "Acme" {
		t.Fatal("env defaults not applied")
	}
	r := *m.Get()
	r.AllowSignup = false
	r.CORSOrigins = []string{" https://app.example.com/ ", "https://app.example.com"}
	if err := m.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
	if m.Get().AllowSignup {
		t.Fatal("override not applied")
	}
	if got := m.Get().CORSOrigins; len(got) != 1 || got[0] != "https://app.example.com" {
		t.Fatalf("origins not normalized: %v", got)
	}
	if over, _ := m.Overridden(); !over {
		t.Fatal("should report override")
	}
	if err := m.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if !m.Get().AllowSignup {
		t.Fatal("reset did not restore env value")
	}
}

func TestRejectsUnsafeSettings(t *testing.T) {
	m := NewManager(testConfig(), &memStore{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	base := *m.Get()
	cases := map[string]func(r *Runtime){
		"short passwords":   func(r *Runtime) { r.PasswordMinLength = 4 },
		"no lockout":        func(r *Runtime) { r.LockoutThreshold = 0 },
		"wildcard cors":     func(r *Runtime) { r.CORSOrigins = []string{"*"} },
		"null cors":         func(r *Runtime) { r.CORSOrigins = []string{"null"} },
		"cors with path":    func(r *Runtime) { r.CORSOrigins = []string{"https://a.com/x"} },
		"js redirect":       func(r *Runtime) { r.AllowedRedirectURIs = []string{"javascript:alert(1)"} },
		"fragment redirect": func(r *Runtime) { r.AllowedRedirectURIs = []string{"https://a.com/cb#x"} },
		"template no token": func(r *Runtime) { r.VerifyEmailURL = "https://a.com/verify" },
		"empty app name":    func(r *Runtime) { r.AppName = "  " },
	}
	for name, mutate := range cases {
		r := base
		r.AllowedRedirectURIs = append([]string{}, base.AllowedRedirectURIs...)
		mutate(&r)
		if err := m.Save(context.Background(), r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !m.Get().AllowSignup || len(m.Get().CORSOrigins) != 0 {
		t.Fatal("a rejected save changed the live settings")
	}
}

func TestProductionRequiresHTTPS(t *testing.T) {
	r := FromConfig(testConfig())
	r.AllowedRedirectURIs = []string{"http://app.example.com/cb"}
	if err := r.Validate(true); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected https error, got %v", err)
	}
	r.AllowedRedirectURIs = []string{"http://localhost:3000/cb", "myapp://auth"}
	if err := r.Validate(true); err != nil {
		t.Fatalf("localhost and custom schemes should be allowed: %v", err)
	}
}
