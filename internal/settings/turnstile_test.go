package settings

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/fatihacan1/warden/internal/crypto/secretbox"
)

const tsSecret = "0x4AAAAAAA-super-secret-turnstile-key"

func tsManager(t *testing.T, envSecret string) (*Manager, *memStore, *secretbox.Box) {
	t.Helper()
	box, err := secretbox.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := testConfig()
	c.Auth.TurnstileSecretKey = envSecret
	c.Auth.TurnstileSiteKey = "0x4AAAAAAAsite"
	c.Auth.TurnstileSignIn = "after_failures"
	c.Auth.TurnstileSignInAfter = 3
	st := &memStore{}
	m := NewManager(c, st, box, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return m, st, box
}

func enabled(m *Manager) Runtime {
	r := *m.Get()
	r.TurnstileEnabled = true
	r.TurnstileSiteKey = "0x4AAAAAAAsite"
	r.TurnstileSignIn = "always"
	r.TurnstileSignInAfter = 3
	return r
}

func TestTurnstileSecretIsEncryptedAndNeverSerialized(t *testing.T) {
	m, st, _ := tsManager(t, "")
	ctx := context.Background()
	r := enabled(m)
	r.TurnstileSecretKey = tsSecret
	if err := m.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(st.data, []byte(tsSecret)) || bytes.Contains(st.data, []byte("super-secret")) {
		t.Fatalf("secret stored in plaintext: %s", st.data)
	}
	if !bytes.Contains(st.data, []byte(`"turnstile_secret_enc"`)) {
		t.Fatalf("sealed secret missing: %s", st.data)
	}
	if got := m.Get().TurnstileSecretKey; got != tsSecret {
		t.Fatalf("secret not loaded back: %q", got)
	}
	// What the admin API returns.
	out, _ := json.Marshal(m.Get())
	if strings.Contains(string(out), tsSecret) || strings.Contains(string(out), "turnstile_secret") {
		t.Fatalf("secret leaked in JSON: %s", out)
	}
	if h := m.Get().TurnstileSecretHint(); h != "…"+tsSecret[len(tsSecret)-4:] {
		t.Fatalf("hint reveals too much: %q", h)
	}
}

func TestTurnstileEmptySecretKeepsCurrentAndClearWorks(t *testing.T) {
	m, st, _ := tsManager(t, "")
	ctx := context.Background()
	r := enabled(m)
	r.TurnstileSecretKey = tsSecret
	if err := m.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
	// Admin API / form without a secret must not wipe it.
	r = *m.Get()
	r.TurnstileSecretKey = ""
	r.AppName = "Other"
	if err := m.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
	if m.Get().TurnstileSecretKey != tsSecret {
		t.Fatal("saving without a secret dropped it")
	}
	// Clearing while enabled without an env secret is refused.
	if err := m.SaveClearingTurnstileSecret(ctx, *m.Get()); err == nil {
		t.Fatal("cleared the secret while Turnstile stays on")
	}
	r = *m.Get()
	r.TurnstileEnabled = false
	if err := m.SaveClearingTurnstileSecret(ctx, r); err != nil {
		t.Fatal(err)
	}
	if m.Get().TurnstileSecretKey != "" || bytes.Contains(st.data, []byte("turnstile_secret_enc")) {
		t.Fatal("secret not cleared")
	}
}

func TestTurnstileEnvSecretNotCopiedToDatabase(t *testing.T) {
	m, st, _ := tsManager(t, tsSecret)
	ctx := context.Background()
	if !m.Get().TurnstileEnabled {
		t.Fatal("env secret should enable Turnstile")
	}
	r := *m.Get()
	r.TurnstileSecretKey = ""
	r.AppName = "Changed"
	if err := m.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(st.data, []byte("turnstile_secret_enc")) {
		t.Fatal("env secret was copied into the database")
	}
	if m.Get().TurnstileSecretKey != tsSecret {
		t.Fatal("env secret lost after save")
	}
	// An admin override wins, and clearing it falls back to the env secret.
	r = *m.Get()
	r.TurnstileSecretKey = "0x4AAAAAAA-admin-override-secret"
	if err := m.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
	if m.Get().TurnstileSecretKey != "0x4AAAAAAA-admin-override-secret" {
		t.Fatal("override not applied")
	}
	if err := m.SaveClearingTurnstileSecret(ctx, *m.Get()); err != nil {
		t.Fatal(err)
	}
	if m.Get().TurnstileSecretKey != tsSecret {
		t.Fatal("clearing did not fall back to the env secret")
	}
}

func TestTurnstileTamperedCiphertextIsRejected(t *testing.T) {
	m, st, _ := tsManager(t, "")
	ctx := context.Background()
	r := enabled(m)
	r.TurnstileSecretKey = tsSecret
	if err := m.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	_ = json.Unmarshal(st.data, &raw)
	raw["turnstile_secret_enc"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	st.data, _ = json.Marshal(raw)
	if err := m.Reload(ctx); err == nil {
		t.Fatal("tampered secret accepted")
	}
	if m.Get().TurnstileSecretKey != tsSecret {
		t.Fatal("failed reload replaced the live settings")
	}
}

func TestTurnstileWithoutBoxCannotStoreSecret(t *testing.T) {
	c := testConfig()
	m := NewManager(c, &memStore{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := enabled(m)
	r.TurnstileSecretKey = tsSecret
	if err := m.Save(context.Background(), r); err == nil {
		t.Fatal("stored a secret without encryption")
	}
}

func TestTurnstileProductionRules(t *testing.T) {
	r := FromConfig(testConfig())
	r.TurnstileEnabled = true
	r.TurnstileSiteKey = "0x4AAAAAAAsite"
	r.TurnstileSecretKey = "1x0000000000000000000000000000000AA"
	r.TurnstileSignIn = "after_failures"
	r.TurnstileSignInAfter = 3
	if err := r.Validate(false); err != nil {
		t.Fatalf("test key should work in development: %v", err)
	}
	if err := r.Validate(true); err == nil {
		t.Fatal("test key accepted in production")
	}
}
