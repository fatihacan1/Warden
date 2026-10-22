package token

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/store"
)

// memKeyStore is an in-memory KeyStore.
type memKeyStore struct {
	mu   sync.Mutex
	rows []store.SigningKeyRow
}

func (m *memKeyStore) ListSigningKeys(_ context.Context, since time.Time) ([]store.SigningKeyRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.SigningKeyRow
	for _, r := range m.rows {
		if r.RetiredAt == nil || r.RetiredAt.After(since) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memKeyStore) RotateSigningKey(_ context.Context, k store.SigningKeyRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for i := range m.rows {
		if m.rows[i].RetiredAt == nil {
			m.rows[i].RetiredAt = &now
		}
	}
	k.CreatedAt = now
	m.rows = append(m.rows, k)
	return nil
}

func (m *memKeyStore) DeleteRetiredKeys(context.Context, time.Time) error { return nil }

func (m *memKeyStore) TryAdvisoryLock(ctx context.Context, _ int64, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

func newTestIssuer(t *testing.T) (*Issuer, *KeyManager) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, _ := secretbox.New(key)
	km := NewKeyManager(&memKeyStore{}, box, 0, 15*time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := km.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return NewIssuer(km, "https://auth.example.com", []string{"api"}, 15*time.Minute), km
}

func subject() Subject {
	return Subject{UserID: uuid.New(), SessionID: uuid.New(), Email: "a@b.co", EmailVerified: true, Roles: []string{"admin"}, AMR: []string{"pwd"}}
}

func TestIssueAndVerify(t *testing.T) {
	iss, _ := newTestIssuer(t)
	s := subject()
	raw, exp, err := iss.Issue(s)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(exp) > 15*time.Minute || time.Until(exp) < 14*time.Minute {
		t.Fatalf("unexpected expiry %v", exp)
	}
	c, err := iss.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != s.UserID.String() || c.SessionID != s.SessionID.String() || c.Email != "a@b.co" || !c.EmailVerified {
		t.Fatalf("claims mismatch: %+v", c)
	}
}

func TestRotationKeepsOldTokensValid(t *testing.T) {
	iss, km := newTestIssuer(t)
	old, _, _ := iss.Issue(subject())
	oldKID := km.ActiveKID()
	if err := km.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if km.ActiveKID() == oldKID {
		t.Fatal("kid did not change")
	}
	if _, err := iss.Verify(old); err != nil {
		t.Fatalf("token signed before rotation must still verify: %v", err)
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(km.JWKS(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 2 {
		t.Fatalf("expected 2 published keys, got %d", len(doc.Keys))
	}
	for _, k := range doc.Keys {
		if _, hasD := k["d"]; hasD {
			t.Fatal("private key material leaked into JWKS")
		}
		if k["alg"] != "ES256" || k["kty"] != "EC" {
			t.Fatalf("bad jwk %v", k)
		}
	}
}

func TestRejectsForgedAndConfusedTokens(t *testing.T) {
	iss, _ := newTestIssuer(t)
	other, _ := newTestIssuer(t)
	s := subject()

	foreign, _, _ := other.Issue(s)
	if _, err := iss.Verify(foreign); err == nil {
		t.Fatal("token signed by an unknown key accepted")
	}

	// alg=none
	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": s.UserID.String(), "sid": "x", "iss": "https://auth.example.com", "aud": "api", "exp": time.Now().Add(time.Hour).Unix()})
	none.Header["typ"] = AccessTokenType
	rawNone, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := iss.Verify(rawNone); err == nil {
		t.Fatal("alg=none accepted")
	}

	// HS256 signed with the public JWKS as secret (classic key confusion).
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": s.UserID.String(), "sid": "x"})
	hs.Header["typ"] = AccessTokenType
	rawHS, _ := hs.SignedString([]byte("public-key-bytes"))
	if _, err := iss.Verify(rawHS); err == nil {
		t.Fatal("HS256 accepted")
	}

	// Tampered payload.
	good, _, _ := iss.Issue(s)
	parts := strings.Split(good, ".")
	parts[1] = parts[1][:len(parts[1])-2] + "AA"
	if _, err := iss.Verify(strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestRejectsWrongAudienceIssuerAndExpiry(t *testing.T) {
	iss, km := newTestIssuer(t)
	s := subject()

	wrongAud := NewIssuer(km, "https://auth.example.com", []string{"other"}, time.Minute)
	raw, _, _ := wrongAud.Issue(s)
	if _, err := iss.Verify(raw); err == nil {
		t.Fatal("wrong audience accepted")
	}

	wrongIss := NewIssuer(km, "https://evil.example.com", []string{"api"}, time.Minute)
	raw, _, _ = wrongIss.Issue(s)
	if _, err := iss.Verify(raw); err == nil {
		t.Fatal("wrong issuer accepted")
	}

	past := NewIssuer(km, "https://auth.example.com", []string{"api"}, time.Minute)
	past.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	raw, _, _ = past.Issue(s)
	if _, err := iss.Verify(raw); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestRejectsWrongTyp(t *testing.T) {
	iss, km := newTestIssuer(t)
	a := km.active()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://auth.example.com", Subject: uuid.NewString(), Audience: jwt.ClaimStrings{"api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)), IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		SessionID: uuid.NewString(),
	})
	tok.Header["kid"] = a.kid
	tok.Header["typ"] = "JWT" // e.g. an ID token
	raw, _ := tok.SignedString(a.private)
	if _, err := iss.Verify(raw); err == nil {
		t.Fatal("token without at+jwt typ accepted")
	}
}
